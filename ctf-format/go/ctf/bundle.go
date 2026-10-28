package ctf

import (
	"encoding/binary"

	"lukechampine.com/blake3"
)

// Footer is the variable-width footer of spec §8.
type Footer struct {
	Root            [RootLen]byte
	SigClassicalLen uint32
	SigPQLen        uint32
	SigClassical    []byte
	SigPQ           []byte
	TotalLen        uint64
}

// Bundle is a parsed .ctf file. Parsing establishes that the file is intact; it
// does not establish authenticity (spec §10, §13).
type Bundle struct {
	raw        []byte
	Header     Header
	Sections   []SectionRecord
	Footer     Footer
	Manifest   *Manifest
	commitment [RootLen]byte
}

// Parse runs the §10 reader-conformance procedure, steps 1–8. The returned
// bundle is intact, never authentic.
func Parse(data []byte) (*Bundle, error) {
	h, err := ParseHeader(data)
	if err != nil {
		return nil, err
	}
	// Step 2: this implementation needs the manifest, footer, and chunk index.
	// The bit is the authority on whether the read can proceed, never
	// version_minor (spec §2.3). The minor only picks which refusal reads
	// correctly: a pre-0.3 file is an older format with nothing to read, while a
	// 0.3+ file missing the bit is a feature-negotiation inconsistency.
	if !h.hasContainerV1() {
		if h.VersionMinor < containerV1Minor {
			return nil, errf(CatLegacy, "§10.2",
				"pre-0.3 file (version_minor %d): no footer, manifest, or chunk index", h.VersionMinor)
		}
		return nil, errf(CatHeader, "§2.3",
			"file does not declare the ro_compat feature CONTAINER_V1 (0x%08x), which a whole-container read needs",
			FeatROCompatContainerV1)
	}
	b := &Bundle{raw: data, Header: h}

	tableLen, _ := checkedMul(uint64(h.SectionTableCount), SectionRecordLen)
	tableStart := h.SectionTableOff
	tableEnd := tableStart + tableLen
	table := data[tableStart:tableEnd]

	// Step 4: records and table-level rules.
	b.Sections = make([]SectionRecord, 0, h.SectionTableCount)
	for i := uint32(0); i < h.SectionTableCount; i++ {
		rec, err := parseRecord(table[i*SectionRecordLen:(i+1)*SectionRecordLen], int(i), h.hasContainerV1())
		if err != nil {
			return nil, err
		}
		b.Sections = append(b.Sections, rec)
	}
	if err := b.validateTable(tableStart, tableEnd); err != nil {
		return nil, err
	}

	// Step 5: footer F1–F7 and F9.
	if err := b.parseFooter(); err != nil {
		return nil, err
	}

	// Step 6: the first point a primitive is needed is the commitment root, so
	// this is where suite_id is resolved through the registry. §19.2 S3: an id
	// absent from it is rejected here, naming the suite. §19.2 S1 still holds
	// because ParseHeader never consults the registry, so a header-only read of
	// an unknown suite succeeds.
	if _, err := LookupSuite(h.SuiteID); err != nil {
		return nil, err
	}

	// Step 6: commitment root. Every registered suite selects BLAKE3, and §8.3
	// fixes the commitment construction, so the root is computed directly.
	if err := b.checkCommitment(tableStart, tableEnd); err != nil {
		return nil, err
	}

	// Step 7: locate the manifest, verify its root, then decode it.
	var manifestRec *SectionRecord
	for i := range b.Sections {
		if b.Sections[i].Kind == KindManifest {
			manifestRec = &b.Sections[i]
			break
		}
	}
	if manifestRec == nil {
		return nil, errf(CatTable, "T1", "no manifest section")
	}
	stored, err := b.storedBytes(*manifestRec)
	if err != nil {
		return nil, err
	}
	sum := blake3.Sum256(stored)
	if [RootLen]byte(sum) != manifestRec.Root {
		return nil, errf(CatSection, "", "manifest root mismatch")
	}
	m, err := DecodeManifest(stored)
	if err != nil {
		return nil, err
	}
	b.Manifest = m

	// Step 8: rules that need the section table.
	if err := m.ValidateAgainst(b.Sections); err != nil {
		return nil, err
	}
	return b, nil
}

// Raw returns the exact input bytes.
func (b *Bundle) Raw() []byte { return b.raw }

// CommitmentRoot returns the verified commitment root (§8.3).
func (b *Bundle) CommitmentRoot() [RootLen]byte { return b.commitment }

// MayRewrite reports whether §4.4 permits rewriting this file.
func (b *Bundle) MayRewrite() bool {
	return b.Header.MayRewrite() && b.Header.hasContainerV1()
}

// Section returns the record for a name_id. name_id is the identity; record
// order is not (spec §3, §5.1).
func (b *Bundle) Section(nameID uint16) (SectionRecord, bool) {
	for _, r := range b.Sections {
		if r.NameID == nameID {
			return r, true
		}
	}
	return SectionRecord{}, false
}

func (b *Bundle) validateTable(tableStart, tableEnd uint64) error {
	// T1: exactly one manifest.
	manifestCount := 0
	for _, r := range b.Sections {
		if r.Kind == KindManifest {
			manifestCount++
		}
	}
	if manifestCount != 1 {
		return errf(CatTable, "T1", "manifest sections: %d", manifestCount)
	}
	// T2: unique name_id.
	seen := make(map[uint16]struct{}, len(b.Sections))
	for i, r := range b.Sections {
		if _, dup := seen[r.NameID]; dup {
			return errf(CatTable, "T2", "record %d reuses name_id %d", i, r.NameID)
		}
		seen[r.NameID] = struct{}{}
	}

	footerOff := b.Header.FooterOff
	type span struct{ start, end uint64 }
	var payloads []span
	var indices []span
	for i, r := range b.Sections {
		if !r.External() {
			start, end, nonEmpty, ok := r.InlineRange()
			if !ok {
				return errf(CatTable, "T3", "record %d payload range overflows", i)
			}
			// T3
			if end > footerOff {
				return errf(CatTable, "T3", "record %d payload end %d beyond footer_off %d", i, end, footerOff)
			}
			if nonEmpty {
				payloads = append(payloads, span{start, end})
			}
		}
		if r.ChunkIndexOff != 0 {
			start, end, ok := r.ChunkIndexRange()
			if !ok || end > footerOff {
				return errf(CatTable, "T6", "record %d chunk index out of bounds", i)
			}
			indices = append(indices, span{start, end})
		}
	}

	overlaps := func(a, b span) bool { return a.start < b.end && b.start < a.end }

	// T4: payload/payload overlap.
	for i := 0; i < len(payloads); i++ {
		for j := i + 1; j < len(payloads); j++ {
			if overlaps(payloads[i], payloads[j]) {
				return errf(CatTable, "T4", "inline payloads %d and %d overlap", i, j)
			}
		}
	}
	table := span{tableStart, tableEnd}
	// T5 and T7: payloads and indices against the table.
	for i, p := range payloads {
		if overlaps(p, table) {
			return errf(CatTable, "T5", "payload %d overlaps the section table", i)
		}
	}
	for i := range indices {
		if overlaps(indices[i], table) {
			return errf(CatTable, "T7", "chunk index %d overlaps the section table", i)
		}
		for j, p := range payloads {
			if overlaps(indices[i], p) {
				return errf(CatTable, "T7", "chunk index %d overlaps payload %d", i, j)
			}
		}
		for j := i + 1; j < len(indices); j++ {
			if overlaps(indices[i], indices[j]) {
				return errf(CatTable, "T7", "chunk indices %d and %d overlap", i, j)
			}
		}
	}

	// T8: unclaimed bytes in [64, footer_off) are zero.
	if b.Header.hasContainerV1() {
		all := make([]span, 0, len(payloads)+len(indices)+1)
		all = append(all, payloads...)
		all = append(all, indices...)
		all = append(all, table)
		// Insertion sort is fine: the table cap is 4096 records.
		for i := 1; i < len(all); i++ {
			for j := i; j > 0 && all[j-1].start > all[j].start; j-- {
				all[j-1], all[j] = all[j], all[j-1]
			}
		}
		pos := uint64(HeaderLen)
		for _, s := range all {
			if s.start > pos {
				if !allZero(b.raw[pos:s.start]) {
					return errf(CatTable, "T8", "non-zero padding in [%d,%d)", pos, s.start)
				}
			}
			if s.end > pos {
				pos = s.end
			}
		}
		if pos < footerOff {
			if !allZero(b.raw[pos:footerOff]) {
				return errf(CatTable, "T8", "non-zero padding in [%d,%d)", pos, footerOff)
			}
		}
	}
	return nil
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func (b *Bundle) parseFooter() error {
	fileLen := uint64(len(b.raw))
	footerOff := b.Header.FooterOff
	// F1
	if fileLen-footerOff < MinFooterLen {
		return errf(CatFooter, "F1", "footer length %d below %d", fileLen-footerOff, MinFooterLen)
	}
	// F2
	if footerOff < HeaderLen || footerOff > fileLen {
		return errf(CatFooter, "F2", "footer_off %d outside file of %d bytes", footerOff, fileLen)
	}
	fo := b.raw[footerOff:]
	// F3
	sc := binary.LittleEndian.Uint32(fo[32:36])
	sp := binary.LittleEndian.Uint32(fo[36:40])
	if sc > MaxSigLen || sp > MaxSigLen {
		return errf(CatFooter, "F3", "signature lengths %d/%d exceed %d", sc, sp, MaxSigLen)
	}
	// F4: exactly one empty slot is the downgrade case. Both empty is the legal
	// unsigned state (§8.2 note); both non-empty is the hybrid signed state.
	if (sc == 0) != (sp == 0) {
		return errf(CatFooter, "F4", "exactly one signature slot is empty: %d/%d", sc, sp)
	}
	// F5
	want := uint64(MinFooterLen) + uint64(sc) + uint64(sp)
	if uint64(len(fo)) != want {
		return errf(CatFooter, "F5", "footer length %d != 56+%d+%d", len(fo), sc, sp)
	}
	// F6
	if [8]byte(fo[len(fo)-8:]) != Magic {
		return errf(CatFooter, "F6", "footer magic mismatch")
	}
	// F7
	total := binary.LittleEndian.Uint64(fo[len(fo)-16 : len(fo)-8])
	if total != fileLen {
		return errf(CatFooter, "F7", "total_len %d != file length %d", total, fileLen)
	}
	// F10: for a suite this reader implements the slot lengths are the suite's
	// (§8.1, §20.3), never the file's. An unsigned footer has no slots to locate,
	// an unrecognized suite_id is not resolved during a container read (§19.1 S1),
	// and suite 3's signature role (SLH-DSA) is not implemented here, so its slots
	// are resolved when the primitive is (Rust skips the same suites).
	if sc != 0 {
		if suite, err := LookupSuite(b.Header.SuiteID); err == nil && suite.ImplementsSignatureRole() {
			wantC, wantPQ, _ := SignatureSlotLengths(b.Header.SuiteID)
			if int(sc) != wantC || int(sp) != wantPQ {
				return errf(CatFooter, "F10", "signature slots %d/%d do not match suite %d's %d/%d",
					sc, sp, b.Header.SuiteID, wantC, wantPQ)
			}
		}
	}
	copy(b.Footer.Root[:], fo[0:32])
	b.Footer.SigClassicalLen = sc
	b.Footer.SigPQLen = sp
	b.Footer.SigClassical = fo[40 : 40+sc]
	b.Footer.SigPQ = fo[40+sc : 40+sc+sp]
	b.Footer.TotalLen = total
	return nil
}

func (b *Bundle) checkCommitment(tableStart, tableEnd uint64) error {
	h := blake3.New(RootLen, nil)
	h.Write([]byte(rootLabel))
	h.Write(b.raw[:HeaderLen])
	h.Write(b.raw[tableStart:tableEnd])
	var got [RootLen]byte
	copy(got[:], h.Sum(nil))
	if got != b.Footer.Root {
		return errf(CatCommitment, "F8", "commitment root mismatch")
	}
	b.commitment = got
	return nil
}

// storedBytes returns the stored bytes of an inline section without exposing
// unverified content. It does not decode enc/comp.
func (b *Bundle) storedBytes(r SectionRecord) ([]byte, error) {
	if r.External() {
		return nil, errf(CatUsage, "", "section %d is EXTERNAL", r.NameID)
	}
	start, end, _, ok := r.InlineRange()
	if !ok || end > uint64(len(b.raw)) {
		return nil, errf(CatSection, "", "section %d payload out of bounds", r.NameID)
	}
	return b.raw[start:end], nil
}

// Verify checks every inline section this implementation can interpret without
// a key or decompressor: plain, unencrypted, uncompressed sections. It returns
// the first mismatch. A whole-file verification pass SHOULD report every one;
// VerifyAll does that.
func (b *Bundle) Verify() error {
	errs := b.VerifyAll()
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// VerifyAll checks all plain inline sections and returns every mismatch, so an
// operator is not left to bisect a large bundle (spec §13).
//
// An EXTERNAL section's bytes are absent by design, so it is skipped. An
// encrypted section cannot be checked without the content key, and a compressed
// section of a kind this build does not implement must not be decompressed
// (spec §10), so both are unverifiable rather than silently verified. A
// compressed section of a kind this build does implement is subject to D1 and
// D2 before any decoder would run; because this build has no zstd decoder, the
// caps are enforced and then the section is reported rather than claimed
// verified.
func (b *Bundle) VerifyAll() []error {
	var errs []error
	for _, r := range b.Sections {
		if r.External() || r.Enc != EncNone {
			continue
		}
		if !r.Understood() && r.Comp != CompNone {
			continue
		}
		if r.Comp != CompNone {
			if err := decompressionCaps(r); err != nil {
				errs = append(errs, err)
				continue
			}
			errs = append(errs, errf(CatUsage, "",
				"section %d uses enc/comp; this build cannot decompress it", r.NameID))
			continue
		}
		stored, err := b.storedBytes(r)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		sum := blake3.Sum256(stored)
		if [RootLen]byte(sum) != r.Root {
			errs = append(errs, errf(CatSection, "", "section %d root mismatch", r.NameID))
		}
	}
	return errs
}

// SectionBytes returns a section's plaintext only after its root verifies. It
// refuses SEALED sections and kinds this implementation does not understand
// (§10, C7). Encryption and compression are handled by SectionPlaintext.
func (b *Bundle) SectionBytes(nameID uint16) ([]byte, error) {
	r, ok := b.Section(nameID)
	if !ok {
		return nil, errf(CatUsage, "", "no section with name_id %d", nameID)
	}
	if r.Has(FlagSealed) {
		return nil, errf(CatUsage, "", "section %d is SEALED", nameID)
	}
	if !r.Understood() {
		return nil, errf(CatUsage, "", "section %d kind %d is not understood", nameID, r.Kind)
	}
	if r.External() {
		return nil, errf(CatUsage, "", "section %d is EXTERNAL; use VerifyExternal with a reader", nameID)
	}
	if r.Enc != EncNone || r.Comp != CompNone {
		return nil, errf(CatUsage, "", "section %d needs a key or decompressor; use SectionPlaintext", nameID)
	}
	stored, err := b.storedBytes(r)
	if err != nil {
		return nil, err
	}
	sum := blake3.Sum256(stored)
	if [RootLen]byte(sum) != r.Root {
		return nil, errf(CatSection, "", "section %d root mismatch", nameID)
	}
	return stored, nil
}

// SectionPlaintext returns a plaintext after verifying it against the record's
// root. contentKey may be nil only when enc = 0.
func (b *Bundle) SectionPlaintext(nameID uint16, contentKey []byte) ([]byte, error) {
	r, ok := b.Section(nameID)
	if !ok {
		return nil, errf(CatUsage, "", "no section with name_id %d", nameID)
	}
	if r.Has(FlagSealed) {
		return nil, errf(CatUsage, "", "section %d is SEALED", nameID)
	}
	if !r.Understood() {
		return nil, errf(CatUsage, "", "section %d kind %d is not understood", nameID, r.Kind)
	}
	if r.External() {
		return nil, errf(CatUsage, "", "section %d is EXTERNAL", nameID)
	}
	if r.Enc == EncNone && r.Comp == CompNone {
		return b.SectionBytes(nameID)
	}
	// D1 and D2 must be applied before any decompressor is invoked (§5.4).
	// They are checked on the authenticated declaration alone, so a bomb is
	// refused without allocating its output.
	if r.Comp == CompZstd {
		if err := decompressionCaps(r); err != nil {
			return nil, err
		}
	}
	return nil, errf(CatUsage, "", "section %d uses enc/comp; use the crypto helpers", nameID)
}

// decompressionCaps enforces D1 and D2 from spec §5.4. Both checks use only
// table fields, so neither can be influenced by the stored bytes.
func decompressionCaps(r SectionRecord) error {
	if r.LenPlain > MaxDecompressedSection {
		return errf(CatSection, "D1", "section %d: len_plain %d exceeds MAX_DECOMPRESSED_SECTION %d",
			r.NameID, r.LenPlain, uint64(MaxDecompressedSection))
	}
	// D2: len_plain > len_stored × MAX_DECOMPRESSION_RATIO. The product is
	// compared with overflow detection; an overflowing product is larger than
	// any uint64 len_plain and therefore cannot violate the cap.
	if limit, ok := checkedMul(r.LenStored, MaxDecompressionRatio); ok && r.LenPlain > limit {
		return errf(CatSection, "D2", "section %d: len_plain %d exceeds len_stored %d × ratio %d",
			r.NameID, r.LenPlain, r.LenStored, uint64(MaxDecompressionRatio))
	}
	return nil
}
