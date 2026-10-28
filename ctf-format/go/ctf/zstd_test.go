package ctf

import (
	"bytes"
	"errors"
	"testing"
)

var zstdFrameMagic = []byte{0x28, 0xb5, 0x2f, 0xfd}

func compressedBundle(t *testing.T, plaintext []byte, chunkSize uint32) (*Bundle, []byte) {
	t.Helper()
	m := NewManifest()
	m.Set("id", Text("zstd-roundtrip"))
	m.Set("name", Text("Zstd Roundtrip"))
	m.Set("names", Array(Text("manifest"), Text("section")))
	m.Set("spec", Uint(1))
	data, err := WriteBundle(m, []Section{{
		Kind:      KindArtifact,
		NameID:    1,
		Flags:     FlagPlayerVisible,
		Comp:      CompZstd,
		Plaintext: plaintext,
		ChunkSize: chunkSize,
	}}, WriteOptions{})
	if err != nil {
		t.Fatalf("write compressed bundle: %v", err)
	}
	b, err := Parse(data)
	if err != nil {
		t.Fatalf("parse compressed bundle: %v", err)
	}
	return b, data
}

// §5.4: one zstd frame per chunk, a single frame for chunk_size = 0, and an
// empty plaintext is one empty frame. Every case round-trips through the reader.
func TestZstdSectionRoundTrip(t *testing.T) {
	cases := []struct {
		name      string
		plaintext []byte
		chunkSize uint32
		frames    int
	}{
		{"single-frame", []byte("one zstd frame covering the whole plaintext"), 0, 1},
		{"chunked-three-frames", bytes.Repeat([]byte("abcdefgh"), 2048), 4096, 4},
		{"empty-no-chunk", nil, 0, 1},
		{"empty-chunked", nil, 4096, 1},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			b, data := compressedBundle(t, tc.plaintext, tc.chunkSize)
			rec, ok := b.Section(1)
			if !ok {
				t.Fatal("section 1 absent")
			}
			if rec.Comp != CompZstd {
				t.Fatalf("comp = %d, want %d", rec.Comp, CompZstd)
			}
			if rec.LenPlain != uint64(len(tc.plaintext)) {
				t.Fatalf("len_plain = %d, want %d", rec.LenPlain, len(tc.plaintext))
			}
			stored := data[rec.Offset : rec.Offset+rec.LenStored]
			if got := bytes.Count(stored, zstdFrameMagic); got != tc.frames {
				t.Fatalf("stored bytes carry %d zstd frames, want %d", got, tc.frames)
			}
			got, err := b.SectionPlaintext(1, nil)
			if err != nil {
				t.Fatalf("decompress: %v", err)
			}
			if !bytes.Equal(got, tc.plaintext) {
				t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), len(tc.plaintext))
			}
			if errs := b.VerifyAll(); len(errs) != 0 {
				t.Fatalf("VerifyAll findings: %v", errs)
			}
			if tc.chunkSize != 0 && len(tc.plaintext) > int(tc.chunkSize) {
				if _, err := b.VerifyChunkIndex(1); err != nil {
					t.Fatalf("chunk index for compressed section: %v", err)
				}
			}
		})
	}
}

// §5.4: D1 and D2 are checked on the declaration before any decoder runs. The
// stored bytes are not a zstd frame, so a decoder-first implementation would
// report a decode failure instead of the named cap.
func TestZstdCapsBeforeDecode(t *testing.T) {
	cases := []struct {
		name     string
		lenPlain uint64
		rule     string
	}{
		{"D1-output-cap", MaxDecompressedSection + 1, "D1"},
		{"D2-ratio-cap", 8 << 20, "D2"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, data := compressedBundle(t, []byte("not a frame"), 0)
			patched := setRecordComp(t, data, 1, CompZstd)
			patched = setRecordLenPlain(t, patched, 1, tc.lenPlain)
			b2, err := Parse(patched)
			if err != nil {
				t.Fatalf("parse patched bundle: %v", err)
			}
			if b2 == nil {
				t.Fatal("nil bundle")
			}
			_, err = b2.SectionPlaintext(1, nil)
			var ce *Error
			if !errors.As(err, &ce) || ce.Rule != tc.rule {
				t.Fatalf("want a %s error before decode, got %v", tc.rule, err)
			}
			if bytes.Contains([]byte(err.Error()), []byte("zstd")) {
				t.Fatalf("decoder ran before the caps: %v", err)
			}
			errs := b2.VerifyAll()
			if len(errs) != 1 {
				t.Fatalf("VerifyAll returned %d errors, want 1: %v", len(errs), errs)
			}
			if !errors.As(errs[0], &ce) || ce.Rule != tc.rule {
				t.Fatalf("VerifyAll did not apply %s first: %v", tc.rule, errs[0])
			}
		})
	}
}

// A truncated frame and an output that disagrees with len_plain are both
// rejected; neither may be returned as plaintext.
func TestZstdTruncatedAndCorruptFramesRejected(t *testing.T) {
	plain := bytes.Repeat([]byte("zstd corruption probe"), 512)
	frame, err := compressSection(plain, 0)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := decompressExact(frame, uint64(len(plain))); err != nil || !bytes.Equal(out, plain) {
		t.Fatalf("valid frame: out %d bytes, err %v", len(out), err)
	}
	for cut := 1; cut < len(frame); cut += len(frame) / 5 {
		if _, err := decompressExact(frame[:len(frame)-cut], uint64(len(plain))); err == nil {
			t.Fatalf("accepted a frame truncated by %d bytes", cut)
		}
	}
	if _, err := decompressExact(frame, uint64(len(plain))+1); err == nil {
		t.Fatal("accepted a decode whose output does not equal len_plain")
	}
	flipped := append([]byte(nil), frame...)
	flipped[len(flipped)/2] ^= 0xff
	if _, err := decompressExact(flipped, uint64(len(plain))); err == nil {
		t.Fatal("accepted a corrupt frame")
	}
}

func setRecordLenPlain(t *testing.T, data []byte, index int, lenPlain uint64) []byte {
	t.Helper()
	out := append([]byte(nil), data...)
	h, err := ParseHeader(out)
	if err != nil {
		t.Fatalf("reparse header: %v", err)
	}
	rec := h.SectionTableOff + uint64(index)*SectionRecordLen
	putU64(out[rec+24:rec+32], lenPlain)
	return resealTable(t, out)
}

func putU64(b []byte, v uint64) {
	for i := 0; i < 8; i++ {
		b[i] = byte(v >> (8 * i))
	}
}
