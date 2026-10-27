package ctf

import (
	"bytes"
	"unicode/utf8"
)

// Manifest is one decoded canonical-CBOR map (spec §7). Unknown keys are
// carried in the value tree and re-encoded byte-for-byte.
type Manifest struct {
	v Value
}

// NewManifest returns an empty manifest map.
func NewManifest() *Manifest { return &Manifest{v: Value{Kind: ValueMap}} }

// Set inserts or replaces a top-level text key.
func (m *Manifest) Set(key string, val Value) {
	for i := range m.v.M {
		if m.v.M[i].Key.Kind == ValueText && m.v.M[i].Key.T == key {
			m.v.M[i].Val = val
			return
		}
	}
	m.v.M = append(m.v.M, Pair{Key: Text(key), Val: val})
}

// Get returns a top-level text key's value.
func (m *Manifest) Get(key string) (Value, bool) {
	for i := range m.v.M {
		if m.v.M[i].Key.Kind == ValueText && m.v.M[i].Key.T == key {
			return m.v.M[i].Val, true
		}
	}
	return Value{}, false
}

// Value returns the underlying map value.
func (m *Manifest) Value() Value { return m.v }

// Encode canonicalizes the map (sorting every level by encoded key) and returns
// its canonical CBOR encoding.
func (m *Manifest) Encode() ([]byte, error) {
	v, err := canonicalize(m.v)
	if err != nil {
		return nil, err
	}
	if v.Kind != ValueMap {
		return nil, errf(CatManifest, "M2", "outermost value is not a map")
	}
	return encodeValue(v)
}

// DecodeManifest decodes one canonical CBOR map and applies the manifest-local
// rules M1–M18 and M22–M24. M19–M21 and M25 need the section table and are
// applied by ValidateAgainst (spec §10 step 8).
func DecodeManifest(b []byte) (*Manifest, error) {
	v, err := decodeCBOR(b)
	if err != nil {
		return nil, err
	}
	// §7.1 requires re-encoding an accepted manifest to reproduce the input.
	again, err := encodeValue(v)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(again, b) {
		return nil, errf(CatCBOR, "M1", "manifest does not re-encode to its input bytes")
	}
	if v.Kind != ValueMap {
		return nil, errf(CatManifest, "M2", "outermost value is not a map")
	}
	for i, p := range v.M {
		if p.Key.Kind != ValueText {
			return nil, errf(CatManifest, "M3", "top-level key %d is not text", i)
		}
	}
	m := &Manifest{v: v}
	if err := m.validateLocal(); err != nil {
		return nil, err
	}
	return m, nil
}

// knownManifestKey lists the top-level keys this implementation understands.
// An unknown key is carried; an unknown key named in crit is rejected (M7).
func knownManifestKey(k string) bool {
	switch k {
	case "spec", "id", "name", "names", "paths", "version", "category",
		"description", "crit", "external", "flag", "generate", "runtime",
		"sealed", "verify", "platform":
		return true
	}
	return false
}

func (m *Manifest) index() map[string]Value {
	idx := make(map[string]Value, len(m.v.M))
	for _, p := range m.v.M {
		idx[p.Key.T] = p.Val
	}
	return idx
}

func (m *Manifest) validateLocal() error {
	idx := m.index()

	// M6, M7, M8: criticality is evaluated before the rest of the schema.
	if crit, ok := idx["crit"]; ok {
		if crit.Kind != ValueArray {
			return errf(CatManifest, "M6", "crit is not an array")
		}
		for i, e := range crit.A {
			if e.Kind != ValueText {
				return errf(CatManifest, "M6", "crit entry %d is not text", i)
			}
			if !knownManifestKey(e.T) {
				return errf(CatManifest, "M7", "crit entry %d names an unimplemented key", i)
			}
			if _, present := idx[e.T]; !present {
				return errf(CatManifest, "M8", "crit entry %d names an absent key", i)
			}
		}
	}

	spec, ok := idx["spec"]
	if !ok {
		return errf(CatManifest, "M4", "spec is absent")
	}
	if spec.Kind != ValueUint {
		return errf(CatManifest, "M4", "spec is not an unsigned integer")
	}
	if spec.U == 0 {
		return errf(CatManifest, "M5", "spec is zero")
	}

	id, ok := idx["id"]
	if !ok {
		return errf(CatManifest, "M9", "id is absent")
	}
	if id.Kind != ValueText || !validChallengeID(id.T) {
		return errf(CatManifest, "M9", "id is not text or has an invalid shape")
	}

	name, ok := idx["name"]
	if !ok {
		return errf(CatManifest, "M10", "name is absent")
	}
	if name.Kind != ValueText {
		return errf(CatManifest, "M10", "name is not text")
	}

	for _, k := range []string{"category", "description"} {
		if v, ok := idx[k]; ok && v.Kind != ValueText {
			return errf(CatManifest, "M11", "%s is not text", k)
		}
	}
	if v, ok := idx["version"]; ok && v.Kind != ValueUint {
		return errf(CatManifest, "M12", "version is not an unsigned integer")
	}

	names, ok := idx["names"]
	if !ok {
		return errf(CatManifest, "M13", "names is absent")
	}
	if names.Kind != ValueArray {
		return errf(CatManifest, "M13", "names is not an array")
	}
	if len(names.A) > MaxNames {
		return errf(CatManifest, "M14", "names has %d entries, limit %d", len(names.A), MaxNames)
	}
	seen := make(map[string]struct{}, len(names.A))
	for i, e := range names.A {
		if e.Kind != ValueText || !validName(e.T) {
			return errf(CatManifest, "M15", "names entry %d is not text or has an invalid shape", i)
		}
		if _, dup := seen[e.T]; dup {
			return errf(CatManifest, "M16", "names entry %d is a duplicate", i)
		}
		seen[e.T] = struct{}{}
	}

	if err := validateExternal(idx); err != nil {
		return err
	}
	if err := validatePaths(idx); err != nil {
		return err
	}
	return nil
}

func validateExternal(idx map[string]Value) error {
	ext, ok := idx["external"]
	if !ok {
		return nil
	}
	if ext.Kind != ValueMap {
		return errf(CatManifest, "M17", "external is not a map")
	}
	for i, p := range ext.M {
		if p.Key.Kind != ValueUint || p.Key.U > 0xffff {
			return errf(CatManifest, "M17", "external key %d is not a u16 integer", i)
		}
		e := p.Val
		if e.Kind != ValueMap {
			return errf(CatManifest, "M18", "external entry %d is not a map", i)
		}
		var size, root, mirrors *Value
		for j := range e.M {
			switch {
			case e.M[j].Key.Kind == ValueText && e.M[j].Key.T == "size":
				size = &e.M[j].Val
			case e.M[j].Key.Kind == ValueText && e.M[j].Key.T == "root":
				root = &e.M[j].Val
			case e.M[j].Key.Kind == ValueText && e.M[j].Key.T == "mirrors":
				mirrors = &e.M[j].Val
			}
		}
		if size == nil || root == nil || mirrors == nil {
			return errf(CatManifest, "M18", "external entry %d is missing a required key", i)
		}
		if size.Kind != ValueUint {
			return errf(CatManifest, "M18", "external entry %d size is not an unsigned integer", i)
		}
		if root.Kind != ValueBytes || len(root.B) != RootLen {
			return errf(CatManifest, "M18", "external entry %d root is not a 32-byte string", i)
		}
		if mirrors.Kind != ValueArray || len(mirrors.A) == 0 {
			return errf(CatManifest, "M18", "external entry %d mirrors is not a non-empty array", i)
		}
		for j, mir := range mirrors.A {
			if mir.Kind != ValueText || len(mir.T) < 1 || len(mir.T) > MaxMirrorLen {
				return errf(CatManifest, "M18", "external entry %d mirror %d is empty or too long", i, j)
			}
		}
	}
	return nil
}

func validatePaths(idx map[string]Value) error {
	paths, ok := idx["paths"]
	if !ok {
		return nil
	}
	if paths.Kind != ValueMap {
		return errf(CatManifest, "M22", "paths is not a map")
	}
	seen := make(map[string]struct{}, len(paths.M))
	for i, p := range paths.M {
		if p.Key.Kind != ValueUint || p.Key.U > 0xffff {
			return errf(CatManifest, "M22", "paths key %d is not a u16 integer", i)
		}
		if p.Val.Kind != ValueText || !validRelativePath(p.Val.T) {
			return errf(CatManifest, "M23", "paths entry %d is not text or is not a valid relative path", i)
		}
		if _, dup := seen[p.Val.T]; dup {
			return errf(CatManifest, "M24", "paths entry %d duplicates a path", i)
		}
		seen[p.Val.T] = struct{}{}
	}
	return nil
}

// ValidateAgainst applies the rules that need the section table: M19–M21 and
// M25 (spec §10 step 8).
func (m *Manifest) ValidateAgainst(records []SectionRecord) error {
	idx := m.index()
	names := idx["names"].A

	for i, r := range records {
		if int(r.NameID) >= len(names) {
			return errf(CatManifest, "M19", "section record %d name_id %d outside names table of %d", i, r.NameID, len(names))
		}
	}

	extVal, hasExternal := idx["external"]
	externalSections := make(map[uint16]SectionRecord)
	for _, r := range records {
		if r.External() {
			externalSections[r.NameID] = r
		}
	}
	if hasExternal {
		for i, p := range extVal.M {
			nid := uint16(p.Key.U)
			if _, ok := externalSections[nid]; !ok {
				return errf(CatManifest, "M20", "external entry %d names name_id %d with no EXTERNAL section", i, nid)
			}
			var size uint64
			var root []byte
			for j := range p.Val.M {
				switch p.Val.M[j].Key.T {
				case "size":
					size = p.Val.M[j].Val.U
				case "root":
					root = p.Val.M[j].Val.B
				}
			}
			rec := externalSections[nid]
			if size != rec.LenPlain || !bytes.Equal(root, rec.Root[:]) {
				return errf(CatManifest, "M21", "external entry %d disagrees with the record", i)
			}
		}
	}
	for nid := range externalSections {
		if !hasExternal {
			return errf(CatManifest, "M20", "EXTERNAL section name_id %d has no external entry", nid)
		}
		found := false
		for _, p := range extVal.M {
			if uint16(p.Key.U) == nid {
				found = true
				break
			}
		}
		if !found {
			return errf(CatManifest, "M20", "EXTERNAL section name_id %d has no external entry", nid)
		}
	}

	if paths, ok := idx["paths"]; ok {
		for i, p := range paths.M {
			nid := uint16(p.Key.U)
			found := false
			for _, r := range records {
				if r.NameID == nid {
					found = true
					break
				}
			}
			if !found {
				return errf(CatManifest, "M25", "paths entry %d names name_id %d with no section", i, nid)
			}
		}
	}
	return nil
}

// ---- shape rules (§7.2) ----

func validChallengeID(s string) bool {
	if len(s) < 1 || len(s) > MaxIDLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-':
		default:
			return false
		}
	}
	return s[0] != '-' && s[len(s)-1] != '-'
}

func isBidiControl(r rune) bool {
	return (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069)
}

func validName(s string) bool {
	if len(s) < 1 || len(s) > MaxNameLen {
		return false
	}
	if s == "." || s == ".." {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f || c == '/' || c == '\\' {
			return false
		}
	}
	for _, r := range s {
		if isBidiControl(r) {
			return false
		}
	}
	return true
}

func validRelativePath(s string) bool {
	if len(s) < 1 || len(s) > MaxPathLen || !utf8.ValidString(s) {
		return false
	}
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '/' {
			comp := s[start:i]
			if !validName(comp) {
				return false
			}
			start = i + 1
		}
	}
	return true
}
