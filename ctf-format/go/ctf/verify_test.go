package ctf

import (
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

// A compressed section inside the caps is not silently verified: this build has
// no zstd decoder, so VerifyAll must report that the section was not checked.
func TestVerifyAllReportsCompressedSectionWithinCaps(t *testing.T) {
	data := minimalWithSection(t, KindArtifact, FlagPlayerVisible)
	data = setRecordComp(t, data, 1, CompZstd)
	b, err := Parse(data)
	if err != nil {
		t.Fatalf("parse compressed bundle: %v", err)
	}
	errs := b.VerifyAll()
	if len(errs) != 1 {
		t.Fatalf("VerifyAll returned %d errors, want 1: %v", len(errs), errs)
	}
	var ce *Error
	if !errors.As(errs[0], &ce) || ce.Rule != "" || ce.Category != CatUsage {
		t.Fatalf("want a usage refusal, got %v", errs[0])
	}
	if !strings.Contains(errs[0].Error(), "section 1 uses enc/comp") {
		t.Fatalf("error does not name the refusal: %v", errs[0])
	}
}

// Spec §10: a kind this build does not implement must never be decompressed, so
// an unknown-kind comp=1 section is unverifiable, not a finding.
func TestVerifyAllSkipsUnknownKindCompressedSection(t *testing.T) {
	data := minimalWithSection(t, 99, FlagOptional)
	data = setRecordComp(t, data, 1, CompZstd)
	b, err := Parse(data)
	if err != nil {
		t.Fatalf("parse unknown-kind bundle: %v", err)
	}
	if errs := b.VerifyAll(); len(errs) != 0 {
		t.Fatalf("unknown-kind compressed section was reported: %v", errs)
	}
}
