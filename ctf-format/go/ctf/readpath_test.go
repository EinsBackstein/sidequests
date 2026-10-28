package ctf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"testing"

	"lukechampine.com/blake3"
)

// resealSuiteID patches a bundle's suite_id and recomputes the commitment root
// over the header and section table, so the only remaining defect is the id.
func resealSuiteID(t *testing.T, data []byte, suiteID uint16) []byte {
	t.Helper()
	out := append([]byte(nil), data...)
	binary.LittleEndian.PutUint16(out[16:18], suiteID)
	h, err := ParseHeader(out)
	if err != nil {
		t.Fatalf("reparse header: %v", err)
	}
	tableLen, ok := checkedMul(uint64(h.SectionTableCount), SectionRecordLen)
	if !ok {
		t.Fatal("table length overflows")
	}
	hash := blake3.New(RootLen, nil)
	hash.Write([]byte(rootLabel))
	hash.Write(out[:HeaderLen])
	hash.Write(out[h.SectionTableOff : h.SectionTableOff+tableLen])
	copy(out[h.FooterOff:h.FooterOff+RootLen], hash.Sum(nil))
	return out
}

// §19.2 S2/S3: suite_id is resolved at the first primitive, the commitment root.
// An id absent from the registry is rejected there, naming the suite. §19.2 S1 is
// preserved: ParseHeader alone never resolves the id, so a header-only read of an
// unknown suite still succeeds.
func TestSuiteIDResolvesBeforeTheCommitmentRoot(t *testing.T) {
	data, err := os.ReadFile("../../spec/vectors/conformance/golden/minimal.ctf")
	if err != nil {
		t.Fatal(err)
	}

	unknown := resealSuiteID(t, data, 99)
	if _, err := ParseHeader(unknown); err != nil {
		t.Fatalf("§19.2 S1: a header-only read must not resolve the suite: %v", err)
	}
	_, err = Parse(unknown)
	if err == nil {
		t.Fatal("a bundle naming an unregistered suite_id parsed")
	}
	var ce *Error
	if !errors.As(err, &ce) || ce.Category != CatUsage || ce.Rule != "S3" {
		t.Fatalf("the refusal is an S3 usage error, got %v", err)
	}
	if !strings.Contains(err.Error(), "99") {
		t.Fatalf("the refusal must name the suite: %v", err)
	}

	// A registered suite still parses: resolution rejects only absent ids.
	suite3 := resealSuiteID(t, data, 3)
	b, err := Parse(suite3)
	if err != nil {
		t.Fatalf("suite 3 must parse: %v", err)
	}
	if b.Header.SuiteID != 3 {
		t.Fatalf("suite_id = %d, want 3", b.Header.SuiteID)
	}
	if findings := b.VerifyAll(); len(findings) != 0 {
		t.Fatalf("suite 3 verification findings: %v", findings)
	}
}

func parseDemo(t *testing.T) *Bundle {
	t.Helper()
	data, err := os.ReadFile("../../spec/vectors/conformance/golden/demo.ctf")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse(data)
	if err != nil {
		t.Fatalf("parse demo: %v", err)
	}
	return b
}

// demoSection returns the index of the one section carrying a chunk index.
func demoSection(t *testing.T, b *Bundle) int {
	t.Helper()
	for i := range b.Sections {
		if b.Sections[i].ChunkIndexOff != 0 {
			return i
		}
	}
	t.Fatal("demo.ctf has no chunked section")
	return 0
}

// Every chunk of golden/demo.ctf must verify against its index entry, and the
// bytes returned must be that chunk of the section plaintext. Before the fix,
// chunk 1 failed C5 and chunk 2 panicked.
func TestVerifyChunkMatchesEveryDemoChunk(t *testing.T) {
	b := parseDemo(t)
	idx := demoSection(t, b)
	rec := b.Sections[idx]
	entries, err := b.VerifyChunkIndex(rec.NameID)
	if err != nil {
		t.Fatalf("chunk index: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("demo.ctf chunk entries = %d, want 3", len(entries))
	}
	plaintext, err := b.SectionBytes(rec.NameID)
	if err != nil {
		t.Fatalf("section bytes: %v", err)
	}
	for i := range entries {
		chunk, err := b.VerifyChunk(rec.NameID, uint64(i))
		if err != nil {
			t.Fatalf("VerifyChunk(%d): %v", i, err)
		}
		start := uint64(i) * uint64(rec.ChunkSize)
		end := start + uint64(rec.ChunkSize)
		if end > uint64(len(plaintext)) {
			end = uint64(len(plaintext))
		}
		if !bytes.Equal(chunk, plaintext[start:end]) {
			t.Fatalf("chunk %d is not plaintext[%d:%d]", i, start, end)
		}
	}
}

// A flipped index entry that still matches the table root it is checked against is
// a lying index: C4 passes and C5 must reject the chunk whose entry changed.
func TestVerifyChunkRejectsFlippedIndexEntry(t *testing.T) {
	b := parseDemo(t)
	idx := demoSection(t, b)
	rec := b.Sections[idx]

	// Entry 1's first byte, in place, then re-derive the section root from the
	// tampered entries so VerifyChunkIndex' C4 cannot be what rejects.
	b.raw[rec.ChunkIndexOff+RootLen] ^= 0x01
	count, ok := chunkCount(rec.LenPlain, uint64(rec.ChunkSize))
	if !ok {
		t.Fatal("chunk count overflows")
	}
	entries, err := parseChunkIndexAt(b.raw, rec.ChunkIndexOff, count)
	if err != nil {
		t.Fatal(err)
	}
	root, err := indexRoot(entries)
	if err != nil {
		t.Fatal(err)
	}
	b.Sections[idx].Root = [RootLen]byte(root)

	// Chunk 0 still matches its untouched entry.
	if _, err := b.VerifyChunk(rec.NameID, 0); err != nil {
		t.Fatalf("untouched chunk 0: %v", err)
	}
	_, err = b.VerifyChunk(rec.NameID, 1)
	if err == nil {
		t.Fatal("a chunk whose index entry was flipped verified")
	}
	var ce *Error
	if !errors.As(err, &ce) || ce.Category != CatChunkIndex || ce.Rule != "C5" {
		t.Fatalf("the refusal is C5, got %v", err)
	}
}

// An index outside the entry count is a rejection, never a slice panic.
func TestVerifyChunkRejectsOutOfRangeIndex(t *testing.T) {
	b := parseDemo(t)
	rec := b.Sections[demoSection(t, b)]
	for _, i := range []uint64{3, 1 << 40, ^uint64(0)} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("VerifyChunk(%d) panicked: %v", i, r)
				}
			}()
			_, err := b.VerifyChunk(rec.NameID, i)
			if err == nil {
				t.Fatalf("VerifyChunk(%d) accepted an out-of-range index", i)
			}
			var ce *Error
			if !errors.As(err, &ce) || ce.Category != CatChunkIndex || ce.Rule != "C5" {
				t.Fatalf("VerifyChunk(%d) is C5, got %v", i, err)
			}
		}()
	}
}
