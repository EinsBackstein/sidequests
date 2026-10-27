// Package conformance executes every committed vector under
// spec/vectors/conformance against the independent Go implementation.
package conformance

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	cf "github.com/EinsBackstein/sidequests/ctf-format/go/ctf"
)

const vectorRoot = "../../spec/vectors/conformance"

type expectation struct {
	Kind   string  `json:"kind"`
	Error  string  `json:"error"`
	NameID *uint16 `json:"name_id"`
}

type rawCase struct {
	Name        string       `json:"name"`
	Path        string       `json:"path"`
	File        string       `json:"file"`
	Expect      string       `json:"expect"`
	Outcome     string       `json:"outcome"`
	Result      string       `json:"result"`
	Rule        string       `json:"rule"`
	Error       string       `json:"error"`
	Verify      *bool        `json:"verify"`
	Note        string       `json:"note"`
	Kind        string       `json:"kind"`
	Expectation *expectation `json:"expectation"`
	Rules       []string     `json:"rules"`
	NameID      *uint16      `json:"name_id"`
}

type conformanceCase struct {
	Name   string
	Path   string
	Expect string // accept, reject, onserve
	Rule   string
	Verify bool
	Source string
	Kind   string // expectation kind, for onserve dispatch
	NameID *uint16
}

func (c rawCase) expectationKind() string {
	if c.Expectation != nil && c.Expectation.Kind != "" {
		return c.Expectation.Kind
	}
	return c.Kind
}

func (c rawCase) normalize(dir string) (conformanceCase, error) {
	out := conformanceCase{Name: c.Name, Rule: c.Rule, Verify: true}
	if out.Rule == "" {
		out.Rule = c.Error
	}
	p := c.Path
	if p == "" {
		p = c.File
	}
	if p == "" {
		return out, fmt.Errorf("case has no path")
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(dir, p)
	}
	out.Path = filepath.Clean(p)
	if out.Name == "" {
		rel, err := filepath.Rel(vectorRoot, out.Path)
		if err != nil {
			rel = out.Path
		}
		out.Name = rel
	}
	if c.Expectation != nil {
		out.NameID = c.Expectation.NameID
	}
	if out.NameID == nil {
		out.NameID = c.NameID
	}
	kind := strings.ToLower(c.expectationKind())
	out.Kind = kind
	// A rule tag is assertable only when the corpus cites exactly one. A `rejects`
	// vector cites several on purpose, and an `error` vector that cites a section
	// instead of a tag (the manifest root check) has no tag to compare; asserting
	// any single one of those would make this test pass or fail for the wrong
	// reason. The fixtures themselves are built so a single-tag `error` vector's
	// first failure is that rule.
	if out.Rule == "" && kind == "error" && len(c.Rules) == 1 {
		out.Rule = c.Rules[0]
	}
	switch kind {
	case "parses", "accept", "accepted", "ok", "valid", "pass",
		"parses_read_only", "parses_unknown_optional":
		out.Expect = "accept"
	case "rejects", "reject", "rejected", "invalid", "fail", "error":
		out.Expect = "reject"
	case "rejects_on_serve", "serve_error", "chunk_index_error":
		out.Expect = "onserve"
	default:
		e := strings.ToLower(firstNonEmpty(c.Expect, c.Outcome, c.Result))
		switch e {
		case "accept", "accepted", "ok", "valid", "pass":
			out.Expect = "accept"
		case "reject", "rejected", "invalid", "fail", "error":
			out.Expect = "reject"
		default:
			return out, fmt.Errorf("case %q has no recognizable expectation", out.Name)
		}
	}
	if c.Verify != nil {
		out.Verify = *c.Verify
	}
	return out, nil
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func findIndex(root string) string {
	for _, name := range []string{"corpus.json", "index.json", "vectors.json", "cases.json", "index.jsonl"} {
		p := filepath.Join(root, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

// loadIndex accepts a JSON document in any of the shapes a conformance index is
// likely to take: the committed corpus.json ({vectors:[...]} with
// expectation.kind), {cases:[...]}, a bare array, or a map from path to a case.
func loadIndex(path string) ([]conformanceCase, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(path)

	if strings.HasSuffix(path, ".jsonl") {
		var out []conformanceCase
		for i, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			var rc rawCase
			if err := json.Unmarshal([]byte(line), &rc); err != nil {
				return nil, fmt.Errorf("index line %d: %w", i+1, err)
			}
			c, err := rc.normalize(dir)
			if err != nil {
				return nil, fmt.Errorf("index line %d: %w", i+1, err)
			}
			out = append(out, c)
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("index has no cases")
		}
		return out, nil
	}

	var probe any
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, err
	}
	var raws []rawCase
	switch v := probe.(type) {
	case []any:
		for _, item := range v {
			b, _ := json.Marshal(item)
			var rc rawCase
			if err := json.Unmarshal(b, &rc); err != nil {
				return nil, err
			}
			raws = append(raws, rc)
		}
	case map[string]any:
		if arr, ok := v["vectors"]; ok {
			b, _ := json.Marshal(arr)
			if err := json.Unmarshal(b, &raws); err != nil {
				return nil, err
			}
		} else if arr, ok := v["cases"]; ok {
			b, _ := json.Marshal(arr)
			if err := json.Unmarshal(b, &raws); err != nil {
				return nil, err
			}
		} else {
			keys := make([]string, 0, len(v))
			for k := range v {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				b, _ := json.Marshal(v[k])
				var rc rawCase
				if err := json.Unmarshal(b, &rc); err != nil {
					return nil, err
				}
				rc.Path = k
				raws = append(raws, rc)
			}
		}
	default:
		return nil, fmt.Errorf("unrecognized index shape")
	}
	if len(raws) == 0 {
		return nil, fmt.Errorf("index has no cases")
	}
	out := make([]conformanceCase, 0, len(raws))
	for i, rc := range raws {
		c, err := rc.normalize(dir)
		if err != nil {
			return nil, fmt.Errorf("index case %d: %w", i, err)
		}
		c.Source = path
		out = append(out, c)
	}
	return out, nil
}

func readSidecar(ctfPath string) (conformanceCase, bool, error) {
	base := strings.TrimSuffix(ctfPath, ".ctf")
	candidates := []string{ctfPath + ".json", base + ".json", ctfPath + ".expect", base + ".expect"}
	for _, p := range candidates {
		data, err := os.ReadFile(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return conformanceCase{}, false, err
		}
		c := conformanceCase{Path: ctfPath, Verify: true, Source: p}
		name, err := filepath.Rel(vectorRoot, ctfPath)
		if err != nil {
			name = ctfPath
		}
		c.Name = name
		text := strings.TrimSpace(string(data))
		if strings.HasSuffix(p, ".json") {
			var rc rawCase
			if err := json.Unmarshal(data, &rc); err == nil {
				rc.Path = filepath.Base(ctfPath)
				n, nerr := rc.normalize(filepath.Dir(ctfPath))
				if nerr != nil {
					return conformanceCase{}, false, nerr
				}
				n.Source = p
				n.Name = name
				return n, true, nil
			}
			var word string
			if err := json.Unmarshal(data, &word); err == nil {
				text = word
			} else {
				return conformanceCase{}, false, fmt.Errorf("sidecar %s is not a case object or string", p)
			}
		}
		fields := strings.Fields(text)
		if len(fields) == 0 {
			return conformanceCase{}, false, fmt.Errorf("sidecar %s is empty", p)
		}
		switch strings.ToLower(fields[0]) {
		case "accept", "accepted", "ok", "valid", "pass":
			c.Expect = "accept"
		case "reject", "rejected", "invalid", "fail", "error":
			c.Expect = "reject"
			if len(fields) > 1 {
				c.Rule = fields[1]
			}
		default:
			return conformanceCase{}, false, fmt.Errorf("sidecar %s: unknown expectation %q", p, fields[0])
		}
		return c, true, nil
	}
	return conformanceCase{}, false, nil
}

func classifyByPath(path string) (string, bool) {
	slash := filepath.ToSlash(path)
	for _, part := range strings.Split(slash, "/") {
		switch part {
		case "golden":
			return "accept", true
		case "hostile", "invalid", "reject", "malformed", "corrupt":
			return "reject", true
		}
	}
	return "", false
}

func discover() ([]conformanceCase, error) {
	var allCTF []string
	err := filepath.WalkDir(vectorRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".ctf") {
			allCTF = append(allCTF, filepath.Clean(path))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(allCTF)
	if len(allCTF) == 0 {
		return nil, fmt.Errorf("no .ctf fixtures under %s", vectorRoot)
	}

	idx := findIndex(vectorRoot)
	if idx != "" {
		cases, err := loadIndex(idx)
		if err != nil {
			return nil, fmt.Errorf("index %s: %w", idx, err)
		}
		covered := make(map[string]bool, len(cases))
		for _, c := range cases {
			covered[filepath.Clean(c.Path)] = true
		}
		var missing []string
		for _, p := range allCTF {
			if !covered[p] {
				missing = append(missing, p)
			}
		}
		if len(missing) > 0 {
			return nil, fmt.Errorf("index %s does not list %d fixture(s): %s",
				idx, len(missing), strings.Join(missing, ", "))
		}
		return cases, nil
	}

	// No index. Sidecars may classify fixtures; anything else uses the
	// directory convention, and a fixture we cannot classify is a hard failure
	// rather than a silent skip.
	var cases []conformanceCase
	var unclassified []string
	for _, p := range allCTF {
		if c, ok, err := readSidecar(p); err != nil {
			return nil, err
		} else if ok {
			cases = append(cases, c)
			continue
		}
		if exp, ok := classifyByPath(p); ok {
			name, _ := filepath.Rel(vectorRoot, p)
			cases = append(cases, conformanceCase{Name: name, Path: p, Expect: exp, Verify: true, Source: "path-convention"})
			continue
		}
		unclassified = append(unclassified, p)
	}
	if len(unclassified) > 0 {
		return nil, fmt.Errorf("conformance directory has no index and %d fixture(s) have no sidecar or "+
			"recognizable directory name: %s\nadd spec/vectors/conformance/index.json "+
			"({\"vectors\":[{\"name\":...,\"path\":...,\"expect\":\"accept|reject\",\"rule\":\"R13\"}]}) "+
			"or a .expect sidecar", len(unclassified), strings.Join(unclassified, ", "))
	}
	return cases, nil
}

func checkAccept(t *testing.T, c conformanceCase, data []byte) {
	t.Helper()
	b, err := cf.Parse(data)
	if err != nil {
		t.Fatalf("expected accept, got rejection: %v", err)
	}
	switch c.Kind {
	case "parses_read_only":
		if b.MayRewrite() {
			t.Fatalf("file carries an unknown ro_compat bit but MayRewrite is true")
		}
	case "parses_unknown_optional":
		if c.NameID == nil {
			t.Fatalf("parses_unknown_optional case has no name_id")
		}
		rec, ok := b.Section(*c.NameID)
		if !ok {
			t.Fatalf("section name_id %d is absent", *c.NameID)
		}
		if rec.Understood() {
			t.Fatalf("section name_id %d kind %d is not an unknown kind", *c.NameID, rec.Kind)
		}
		if _, err := b.SectionBytes(*c.NameID); err == nil {
			t.Fatalf("unknown-kind section was served")
		}
		if _, err := b.VerifyChunkIndex(*c.NameID); err == nil {
			t.Fatalf("chunk index of unknown-kind section %d was exposed", *c.NameID)
		}
		// VerifyAll must actually cover a kind it skips for serving, not merely
		// return no errors. Corrupt one stored byte: the commitment root still
		// holds, but the section root no longer does, so a VerifyAll that skipped
		// this section would report nothing.
		corrupt := append([]byte(nil), data...)
		if rec.LenStored == 0 || rec.Offset >= uint64(len(corrupt)) {
			t.Fatalf("unknown-kind section %d has no stored bytes to corrupt", *c.NameID)
		}
		corrupt[rec.Offset] ^= 0xff
		b2, err := cf.Parse(corrupt)
		if err != nil {
			t.Fatalf("corrupting a section byte broke the parse: %v", err)
		}
		errs := b2.VerifyAll()
		want := fmt.Sprintf("section %d", *c.NameID)
		found := false
		for _, e := range errs {
			if strings.Contains(e.Error(), want) {
				found = true
			}
		}
		if !found {
			t.Fatalf("VerifyAll did not report the corrupted unknown-kind %s: %v", want, errs)
		}
	}
	if c.Verify {
		if err := b.Verify(); err != nil {
			t.Fatalf("intact parse but a plain section root failed: %v", err)
		}
	}
	t.Logf("PASS accept %s (%d bytes, commitment %x)", c.Name, len(data), b.CommitmentRoot())
}

func checkOnServe(t *testing.T, c conformanceCase, data []byte) {
	t.Helper()
	b, err := cf.Parse(data)
	if err != nil {
		t.Fatalf("expected the file to parse and fail on use, but parse rejected it: %v", err)
	}
	if c.NameID == nil {
		t.Fatalf("%s case has no name_id", c.Kind)
	}
	switch c.Kind {
	case "chunk_index_error":
		if _, err := b.VerifyChunkIndex(*c.NameID); err == nil {
			t.Fatalf("chunk index for name_id %d was accepted", *c.NameID)
		} else {
			t.Logf("PASS on-use reject %s: %v", c.Name, err)
		}
	case "serve_error", "rejects_on_serve":
		if _, err := b.SectionPlaintext(*c.NameID, nil); err == nil {
			t.Fatalf("section name_id %d was served", *c.NameID)
		} else {
			t.Logf("PASS on-use reject %s: %v", c.Name, err)
		}
	default:
		t.Fatalf("unknown on-use kind %q", c.Kind)
	}
}

func TestConformanceVectors(t *testing.T) {
	cases, err := discover()
	if err != nil {
		t.Fatalf("load conformance vectors: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("no conformance vectors loaded")
	}
	index := findIndex(vectorRoot)
	if index == "" {
		t.Logf("no index file; loaded %d fixtures by sidecar/path convention", len(cases))
	} else {
		t.Logf("loaded %d fixtures from %s", len(cases), index)
	}
	for _, c := range cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			data, err := os.ReadFile(c.Path)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			switch c.Expect {
			case "accept":
				checkAccept(t, c, data)
			case "reject":
				b, perr := cf.Parse(data)
				if perr == nil {
					t.Fatalf("expected rejection, got acceptance")
				}
				var ce *cf.Error
				if c.Rule != "" {
					// A vector that names a rule must be rejected by a tagged error;
					// otherwise the comparison below would be skipped and the rule
					// assertion would silently disappear.
					if !errors.As(perr, &ce) {
						t.Fatalf("rejected with an untagged error while the vector cites rule %q: %v", c.Rule, perr)
					}
					if ce.Rule != c.Rule {
						t.Fatalf("rejected with rule %q, vector cites %q (%v)", ce.Rule, c.Rule, perr)
					}
				}
				_ = b
				t.Logf("PASS reject %s: %v", c.Name, perr)
			case "onserve":
				checkOnServe(t, c, data)
			default:
				t.Fatalf("bad expectation %q", c.Expect)
			}
		})
	}
}

// TestNamedRuleIsAssertedOnlyForSingleRuleVectors keeps the rule check from going
// vacuous again. A `rejects` vector cites several rules on purpose (§2.1), so no
// single rule may be demanded of it; a single-rule `error` vector must carry its
// rule through to the comparison.
func TestNamedRuleIsAssertedOnlyForSingleRuleVectors(t *testing.T) {
	cases, err := loadIndex(filepath.Join(vectorRoot, "corpus.json"))
	if err != nil {
		t.Fatalf("load corpus index: %v", err)
	}
	byName := make(map[string]conformanceCase, len(cases))
	for _, c := range cases {
		byName[c.Name] = c
	}
	if got := byName["payload-beyond-footer"].Rule; got != "T3" {
		t.Errorf("payload-beyond-footer asserts rule %q, want T3", got)
	}
	if got := byName["unknown-enc-discriminant"].Rule; got != "R10" {
		t.Errorf("unknown-enc-discriminant asserts rule %q, want R10", got)
	}
	if got := byName["unknown-comp-discriminant"].Rule; got != "R10" {
		t.Errorf("unknown-comp-discriminant asserts rule %q, want R10", got)
	}
	if got := byName["truncated-footer"].Rule; got != "" {
		t.Errorf("truncated-footer asserts rule %q, want none: F1 always implies F5", got)
	}
	if got := byName["wrong-total-len"].Rule; got != "F7" {
		t.Errorf("wrong-total-len asserts rule %q, want F7", got)
	}
}

// TestGoldenDirectoryIsPresent keeps a clear failure if the fixtures move or
// are deleted while another agent edits the spec tree.
func TestGoldenDirectoryIsPresent(t *testing.T) {
	for _, name := range []string{"minimal.ctf", "demo.ctf"} {
		p := filepath.Join(vectorRoot, "golden", name)
		if _, err := os.Stat(p); err != nil {
			t.Errorf("golden fixture %s: %v", p, err)
		}
	}
}
