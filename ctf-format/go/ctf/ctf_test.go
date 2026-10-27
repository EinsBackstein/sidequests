package ctf

import (
	"bytes"
	"encoding/hex"
	"os"
	"testing"
)

func TestMinimalGoldenParse(t *testing.T) {
	data, err := os.ReadFile("../../spec/vectors/conformance/golden/minimal.ctf")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if b.Header.SectionTableCount != 1 || b.Header.SectionTableOff != 4160 || b.Header.FooterOff != 4288 {
		t.Fatalf("header layout: %+v", b.Header)
	}
	if b.Footer.TotalLen != 4344 {
		t.Fatalf("total_len = %d", b.Footer.TotalLen)
	}
	wantRoot, _ := hex.DecodeString("20e7bc2bfd396451e65968161d6acee9493944d8b8f10c680c2f43d207a057bb")
	root := b.CommitmentRoot()
	if !bytes.Equal(root[:], wantRoot) {
		t.Fatalf("commitment root mismatch: %x", root)
	}
	id, ok := b.Manifest.Get("id")
	if !ok || !id.IsText() || id.T != "whos-that-bird" {
		t.Fatalf("manifest id = %+v", id)
	}
	if err := b.Verify(); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestMinimalGoldenWrite(t *testing.T) {
	want, err := os.ReadFile("../../spec/vectors/conformance/golden/minimal.ctf")
	if err != nil {
		t.Fatal(err)
	}
	m := NewManifest()
	m.Set("id", Text("whos-that-bird"))
	m.Set("name", Text("Who's That Bird"))
	m.Set("names", Array(Text("manifest")))
	m.Set("spec", Uint(1))
	got, err := WriteBundle(m, nil, WriteOptions{})
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("minimal bundle is not byte-identical: got %d bytes, want %d", len(got), len(want))
	}
	logGoldenHash(t, got)
}

func TestChunkIndexWorkedExample(t *testing.T) {
	plain := make([]byte, 3*4096)
	entries, err := BuildChunkIndex(plain, 4096)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"3694b08b169d1c322ef5e9d4dee1a3d2536233851fffd7977a8c1b5a0d51628f",
		"64b687935a6f38f68a040817d157412bf934ec48790e6b34d85825252979e5be",
		"e7a0e6d9923560f45e51bacc92be096e061c088fec2667c6fb68b86b02059847",
	}
	for i, w := range want {
		b, _ := hex.DecodeString(w)
		if !bytes.Equal(entries[i][:], b) {
			t.Errorf("cv(%d) = %x, want %s", i, entries[i], w)
		}
	}
	got, err := indexRoot(entries)
	if err != nil {
		t.Fatal(err)
	}
	wantRoot, _ := hex.DecodeString("819ad8f20ee2578f84eeb28b4aa852458c066911cce810767021030961e43e60")
	if !bytes.Equal(got[:], wantRoot) {
		t.Errorf("root = %x, want %s", got, wantRoot)
	}
}

func TestCanonicalCBORRejects(t *testing.T) {
	cases := map[string][]byte{
		"nonshortest-int": {0xa1, 0x61, 'a', 0x18, 0x01},
		"duplicate-key":   {0xa2, 0x61, 'a', 0x01, 0x61, 'a', 0x02},
		"unsorted-keys":   {0xa2, 0x61, 'b', 0x01, 0x61, 'a', 0x02},
		"indefinite":      {0x5f, 0x41, 0x00, 0xff},
		"tag":             {0xc0, 0x01},
		"float":           {0xfb, 0, 0, 0, 0, 0, 0, 0, 0},
		"trailing":        {0xa0, 0x00},
		"truncated":       {0x62, 'a'},
	}
	for name, b := range cases {
		if _, err := decodeCBOR(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCBORDepthCap(t *testing.T) {
	b := make([]byte, 0, 40)
	for i := 0; i < 17; i++ {
		b = append(b, 0x81) // array(1)
	}
	b = append(b, 0x00)
	if _, err := decodeCBOR(b); err == nil {
		t.Fatal("17 levels accepted")
	}
}

// TestParseNeverPanics feeds the parser truncations, single-byte flips, and
// deterministic garbage. Any panic is a parser bug on hostile input, whatever
// the accept/reject decision would have been (spec §13).
func TestParseNeverPanics(t *testing.T) {
	base, err := os.ReadFile("../../spec/vectors/conformance/golden/minimal.ctf")
	if err != nil {
		t.Fatal(err)
	}
	check := func(b []byte) {
		t.Helper()
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic parsing %d-byte input: %v", len(b), r)
			}
		}()
		_, _ = Parse(b)
	}
	for n := 0; n <= len(base); n++ {
		check(base[:n])
	}
	for i := range base {
		for _, mask := range []byte{0x01, 0x80, 0xff} {
			m := append([]byte(nil), base...)
			m[i] ^= mask
			check(m)
		}
	}
	seed := uint64(0x9e3779b97f4a7c15)
	for i := 0; i < 2000; i++ {
		seed = seed*6364136223846793005 + 1442695040888963407
		n := int(seed % 5000)
		buf := make([]byte, n)
		for j := range buf {
			seed = seed*6364136223846793005 + 1442695040888963407
			buf[j] = byte(seed >> 33)
		}
		check(buf)
	}
}
