package ctf

import (
	"bytes"
	"crypto/sha256"
	"os"
	"testing"

	"lukechampine.com/blake3"
)

// logGoldenHash records the two digests a reviewer can compare against the
// committed fixture, so byte identity has evidence beyond a test passing.
func logGoldenHash(t *testing.T, got []byte) {
	t.Helper()
	sha := sha256.Sum256(got)
	b3 := blake3.Sum256(got)
	t.Logf("byte-identical: len=%d sha256=%x blake3=%x", len(got), sha, b3)
}

func demoManifest() *Manifest {
	root := make([]byte, 32)
	for i := range root {
		root[i] = 0x33
	}
	m := NewManifest()
	m.Set("id", Text("workstation-triage"))
	m.Set("name", Text("Workstation Triage"))
	m.Set("spec", Uint(1))
	m.Set("names", Array(Text("manifest"), Text("notes.md"), Text("workstation.E01")))
	m.Set("version", Uint(3))
	m.Set("category", Text("forensics"))
	m.Set("external", MapValue(Pair{
		Key: Uint(2),
		Val: MapValue(
			Pair{Key: Text("size"), Val: Uint(41231986688)},
			Pair{Key: Text("root"), Val: Bytes(root)},
			Pair{Key: Text("mirrors"), Val: Array(Text("https://mirror.example/workstation.E01"))},
		),
	}))
	m.Set("description", Text("Find what the intruder exfiltrated."))
	return m
}

func TestDemoGoldenWrite(t *testing.T) {
	want, err := os.ReadFile("../../spec/vectors/conformance/golden/demo.ctf")
	if err != nil {
		t.Fatal(err)
	}
	unit := []byte("# Triage notes\n\nStart with the browser history.\n")
	artifact := bytes.Repeat(unit, 200)
	var extRoot [32]byte
	for i := range extRoot {
		extRoot[i] = 0x33
	}
	got, err := WriteBundle(demoManifest(), []Section{
		{
			Kind:      KindArtifact,
			NameID:    1,
			Flags:     FlagPlayerVisible,
			Plaintext: artifact,
			ChunkSize: 4096,
		},
		{
			Kind:         KindArtifact,
			NameID:       2,
			Flags:        FlagPlayerVisible | FlagExternal,
			ExternalSize: 41231986688,
			ExternalRoot: extRoot,
		},
	}, WriteOptions{})
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("demo bundle is not byte-identical: got %d bytes, want %d", len(got), len(want))
	}
	logGoldenHash(t, got)
}
