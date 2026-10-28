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

// resealTable recomputes the commitment root after a test has edited the
// header or section table, so a deliberately non-conforming record reaches
// VerifyAll instead of failing Parse at F8.
func resealTable(t *testing.T, data []byte) []byte {
	t.Helper()
	out := append([]byte(nil), data...)
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

// setRecordComp patches one record's comp byte and reseals the table. The
// writer emits comp=0 only, so this is how a test reaches the compressed path.
func setRecordComp(t *testing.T, data []byte, index int, comp uint8) []byte {
	t.Helper()
	out := append([]byte(nil), data...)
	h, err := ParseHeader(out)
	if err != nil {
		t.Fatalf("reparse header: %v", err)
	}
	rec := h.SectionTableOff + uint64(index)*SectionRecordLen
	out[rec+7] = comp
	return resealTable(t, out)
}

// setRecordRoot patches one record's root and reseals the table, so a test can
// reach the hashing path with a stored section that would otherwise match.
func setRecordRoot(t *testing.T, data []byte, index int, fill byte) []byte {
	t.Helper()
	out := append([]byte(nil), data...)
	h, err := ParseHeader(out)
	if err != nil {
		t.Fatalf("reparse header: %v", err)
	}
	rec := h.SectionTableOff + uint64(index)*SectionRecordLen
	for i := uint64(0); i < RootLen; i++ {
		out[rec+48+i] = fill
	}
	return resealTable(t, out)
}

// setRecordEncAndBigPlain patches one record's enc byte and len_plain and reseals
// the table, so a cap check can be exercised without a decoder.
func setRecordEncAndBigPlain(t *testing.T, data []byte, index int, enc uint8, lenPlain uint64) []byte {
	t.Helper()
	out := append([]byte(nil), data...)
	h, err := ParseHeader(out)
	if err != nil {
		t.Fatalf("reparse header: %v", err)
	}
	rec := h.SectionTableOff + uint64(index)*SectionRecordLen
	out[rec+6] = enc
	binary.LittleEndian.PutUint32(out[rec+32:rec+36], 4096)
	binary.LittleEndian.PutUint64(out[rec+24:rec+32], lenPlain)
	return resealTable(t, out)
}

func minimalWithSection(t *testing.T, kind uint16, flags uint16) []byte {
	t.Helper()
	m := NewManifest()
	m.Set("id", Text("verify-comp"))
	m.Set("name", Text("Verify Comp"))
	m.Set("names", Array(Text("manifest"), Text("section")))
	m.Set("spec", Uint(1))
	data, err := WriteBundle(m, []Section{{
		Kind:   kind,
		NameID: 1,
		Flags:  flags,
	}}, WriteOptions{})
	if err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	return data
}

// Spec §5.4: D1 and D2 are enforced on the authenticated declaration before any
// decoder runs. VerifyAll used to skip every compressed section, so a cap
// violation produced no error at all and a verification pass claimed success.
func TestVerifyAllRejectsCompressionBombs(t *testing.T) {
	cases := []struct {
		fixture string
		rule    string
		detail  string
	}{
		{"compressed-output-cap.ctf", "D1", "MAX_DECOMPRESSED_SECTION"},
		{"compressed-ratio-cap.ctf", "D2", "ratio"},
	}
	for _, tc := range cases {
		data, err := os.ReadFile("../../spec/vectors/conformance/hostile/" + tc.fixture)
		if err != nil {
			t.Fatal(err)
		}
		b, err := Parse(data)
		if err != nil {
			t.Fatalf("%s: parse: %v", tc.fixture, err)
		}
		errs := b.VerifyAll()
		if len(errs) != 1 {
			t.Fatalf("%s: VerifyAll returned %d errors, want 1: %v", tc.fixture, len(errs), errs)
		}
		var ce *Error
		if !errors.As(errs[0], &ce) || ce.Rule != tc.rule {
			t.Fatalf("%s: want a %s error, got %v", tc.fixture, tc.rule, errs[0])
		}
		if !strings.Contains(errs[0].Error(), tc.detail) {
			t.Fatalf("%s: error does not name the cap %q: %v", tc.fixture, tc.detail, errs[0])
		}
		if err := b.Verify(); err == nil {
			t.Fatalf("%s: Verify claimed a bomb verified", tc.fixture)
		}
	}
}

// Spec §13: a plain bundle still verifies cleanly, and an EXTERNAL section is
// skipped because its bytes are not in the file.
func TestVerifyAllAcceptsPlainAndExternalSections(t *testing.T) {
	minimal, err := os.ReadFile("../../spec/vectors/conformance/golden/minimal.ctf")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse(minimal)
	if err != nil {
		t.Fatalf("parse minimal: %v", err)
	}
	if errs := b.VerifyAll(); len(errs) != 0 {
		t.Fatalf("plain bundle findings: %v", errs)
	}

	b = parseDemo(t)
	if errs := b.VerifyAll(); len(errs) != 0 {
		t.Fatalf("demo bundle findings: %v", errs)
	}
}

// A compressed section inside the caps is now decodable, so a verification pass
// must decode it and check the plaintext against its root. The writer emits the
// frame, and the reader returns exactly the original plaintext.
func TestVerifyAllDecodesInCapCompressedSection(t *testing.T) {
	plaintext := []byte("compressed plaintext that round-trips through the reader")
	m := NewManifest()
	m.Set("id", Text("verify-comp"))
	m.Set("name", Text("Verify Comp"))
	m.Set("names", Array(Text("manifest"), Text("section")))
	m.Set("spec", Uint(1))
	data, err := WriteBundle(m, []Section{{
		Kind:      KindArtifact,
		NameID:    1,
		Flags:     FlagPlayerVisible,
		Comp:      CompZstd,
		Plaintext: plaintext,
	}}, WriteOptions{})
	if err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	b, err := Parse(data)
	if err != nil {
		t.Fatalf("parse compressed bundle: %v", err)
	}
	if errs := b.VerifyAll(); len(errs) != 0 {
		t.Fatalf("in-cap compressed section was reported as a finding: %v", errs)
	}
	got, err := b.SectionPlaintext(1, nil)
	if err != nil {
		t.Fatalf("serve compressed section: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("decompressed plaintext does not match: got %d bytes, want %d", len(got), len(plaintext))
	}
	if got, err := b.SectionBytes(1); err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("SectionBytes on compressed section: %v", err)
	}
}

// A corrupt compressed frame is a finding, not something VerifyAll may skip.
func TestVerifyAllReportsCorruptCompressedFrame(t *testing.T) {
	plaintext := bytes.Repeat([]byte("abcdefgh"), 4096)
	m := NewManifest()
	m.Set("id", Text("verify-corrupt-comp"))
	m.Set("name", Text("Verify Corrupt Comp"))
	m.Set("names", Array(Text("manifest"), Text("section")))
	m.Set("spec", Uint(1))
	data, err := WriteBundle(m, []Section{{
		Kind:      KindArtifact,
		NameID:    1,
		Flags:     FlagPlayerVisible,
		Comp:      CompZstd,
		Plaintext: plaintext,
	}}, WriteOptions{})
	if err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	b, err := Parse(data)
	if err != nil {
		t.Fatalf("parse compressed bundle: %v", err)
	}
	rec, _ := b.Section(1)
	corrupt := append([]byte(nil), data...)
	corrupt[rec.Offset] ^= 0xff
	b2, err := Parse(corrupt)
	if err != nil {
		t.Fatalf("parse corrupt compressed bundle: %v", err)
	}
	if errs := b2.VerifyAll(); len(errs) == 0 {
		t.Fatal("VerifyAll skipped a corrupt compressed frame")
	}
	if _, err := b2.SectionPlaintext(1, nil); err == nil {
		t.Fatal("SectionPlaintext served a corrupt compressed frame")
	}
}

// Spec §5.4: the caps apply to a compressed encrypted section's declared totals
// before any key is used, so VerifyAll must not skip it on the way to the
// encryption check.
func TestVerifyAllChecksCapsBeforeSkippingAnEncryptedSection(t *testing.T) {
	data := minimalWithSection(t, KindArtifact, FlagPlayerVisible)
	data = setRecordComp(t, data, 1, CompZstd)
	data = setRecordEncAndBigPlain(t, data, 1, 1, 1<<40)
	b, err := Parse(data)
	if err != nil {
		t.Fatalf("parse encrypted compressed bundle: %v", err)
	}
	errs := b.VerifyAll()
	if len(errs) != 1 {
		t.Fatalf("VerifyAll returned %d errors, want 1: %v", len(errs), errs)
	}
	var ce *Error
	if !errors.As(errs[0], &ce) || ce.Rule != "D1" {
		t.Fatalf("want a D1 error, got %v", errs[0])
	}
}

// Spec §10: a kind this build does not implement must never be decompressed, so
// an unknown-kind comp=1 section is unverifiable, not a finding. The root is made
// wrong on purpose: if the skip were deleted, the plain path would hash the stored
// bytes and this test would then see a root-mismatch finding.
func TestVerifyAllSkipsUnknownKindCompressedSection(t *testing.T) {
	m := NewManifest()
	m.Set("id", Text("verify-unknown"))
	m.Set("name", Text("Verify Unknown"))
	m.Set("names", Array(Text("manifest"), Text("section")))
	m.Set("spec", Uint(1))
	data, err := WriteBundle(m, []Section{{
		Kind:      99,
		NameID:    1,
		Flags:     FlagOptional,
		Plaintext: []byte("stored bytes that are not the root"),
	}}, WriteOptions{})
	if err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	data = setRecordComp(t, data, 1, CompZstd)
	data = setRecordRoot(t, data, 1, 0xaa)
	b, err := Parse(data)
	if err != nil {
		t.Fatalf("parse unknown-kind bundle: %v", err)
	}
	if errs := b.VerifyAll(); len(errs) != 0 {
		t.Fatalf("unknown-kind compressed section was reported: %v", errs)
	}
}
