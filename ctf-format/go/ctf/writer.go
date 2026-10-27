package ctf

import (
	"encoding/binary"

	"lukechampine.com/blake3"
)

// Section is one author-supplied section for WriteBundle. Plaintext is the
// section's plaintext; for an EXTERNAL section it is unused and ExternalSize /
// ExternalRoot describe the payload stored elsewhere.
type Section struct {
	Kind      uint16
	NameID    uint16
	Flags     uint16
	Enc       uint8
	Comp      uint8
	Plaintext []byte
	ChunkSize uint32

	ExternalSize uint64
	ExternalRoot [RootLen]byte

	// EmitChunkIndex overrides the default: an index is emitted whenever
	// ChunkSize != 0 and the section has at least two chunks. Set it to choose
	// explicitly; a nil pointer keeps the default.
	EmitChunkIndex *bool
}

// WriteOptions configures the container fields a writer can choose. The zero
// value is the default: suite 1, minor version 3, manifest name_id 0.
type WriteOptions struct {
	SuiteID        uint16
	VersionMinor   uint16
	ManifestNameID uint16
}

func (o WriteOptions) suite() uint16 {
	if o.SuiteID == 0 {
		return SuiteDefault
	}
	return o.SuiteID
}

func (o WriteOptions) minor() uint16 {
	if o.VersionMinor == 0 {
		return VersionMinor
	}
	return o.VersionMinor
}

type writeSection struct {
	rec  SectionRecord
	data []byte // inline payload, or nil for EXTERNAL
}

// WriteBundle emits a complete .ctf file. It reproduces the §11 minimal bundle
// byte-for-byte from the author inputs in that section. The output is parsed
// back before it is returned: a writer that can emit a file its own reader
// rejects is a bug generator (spec §10).
func WriteBundle(m *Manifest, sections []Section, opts WriteOptions) ([]byte, error) {
	if m == nil {
		return nil, errf(CatUsage, "", "nil manifest")
	}
	if err := m.validateLocal(); err != nil {
		return nil, err
	}
	manifestBytes, err := m.Encode()
	if err != nil {
		return nil, err
	}

	all := make([]writeSection, 0, len(sections)+1)
	all = append(all, writeSection{
		rec: SectionRecord{
			Kind:   KindManifest,
			NameID: opts.ManifestNameID,
			Enc:    EncNone,
			Comp:   CompNone,
		},
		data: manifestBytes,
	})
	for i, s := range sections {
		if s.Kind == KindManifest {
			return nil, errf(CatUsage, "", "section %d: manifest section is emitted by WriteBundle", i)
		}
		if s.Enc != EncNone || s.Comp != CompNone {
			return nil, errf(CatUsage, "", "section %d: this writer implements enc=0 comp=0 only", i)
		}
		ws := writeSection{data: s.Plaintext}
		ws.rec = SectionRecord{
			Kind:      s.Kind,
			NameID:    s.NameID,
			Flags:     s.Flags,
			Enc:       s.Enc,
			Comp:      s.Comp,
			ChunkSize: s.ChunkSize,
		}
		if s.Flags&FlagExternal != 0 {
			ws.rec.LenPlain = s.ExternalSize
			ws.rec.Root = s.ExternalRoot
			ws.data = nil
		}
		all = append(all, ws)
	}

	// Layout: payloads at 4096-byte boundaries, chunk indices immediately after
	// their payload at an 8-byte boundary, then the table, then the footer.
	pos := uint64(HeaderLen)
	for i := range all {
		if all[i].rec.External() {
			continue
		}
		off, ok := alignUp(pos, PayloadAlign)
		if !ok {
			return nil, errf(CatUsage, "", "payload offset overflows")
		}
		all[i].rec.Offset = off
		all[i].rec.LenStored = uint64(len(all[i].data))
		all[i].rec.LenPlain = uint64(len(all[i].data))
		sum := blake3.Sum256(all[i].data)
		all[i].rec.Root = [RootLen]byte(sum)
		pos = off + uint64(len(all[i].data))

		emit := false
		if all[i].rec.ChunkSize != 0 {
			count, cok := chunkCount(all[i].rec.LenPlain, uint64(all[i].rec.ChunkSize))
			if !cok {
				return nil, errf(CatUsage, "", "chunk count overflows")
			}
			emit = count >= 2
		}
		if sections := findSection(sections, all[i].rec.NameID); sections != nil && sections.EmitChunkIndex != nil {
			emit = *sections.EmitChunkIndex
		}
		if emit {
			if all[i].rec.ChunkSize == 0 {
				return nil, errf(CatUsage, "", "section %d: chunk index requested with chunk_size 0", all[i].rec.NameID)
			}
			idxOff, ok := alignUp(pos, TableAlign)
			if !ok {
				return nil, errf(CatUsage, "", "chunk index offset overflows")
			}
			entries, err := BuildChunkIndex(all[i].data, all[i].rec.ChunkSize)
			if err != nil {
				return nil, err
			}
			if len(entries) < 2 {
				return nil, errf(CatUsage, "", "section %d: chunk index would have fewer than 2 entries", all[i].rec.NameID)
			}
			all[i].rec.ChunkIndexOff = idxOff
			all[i].data = appendChunkIndex(all[i].data[:0:0], entries, all[i].data)
			pos = idxOff + uint64(len(entries))*RootLen
		}
	}

	tableOff, ok := alignUp(pos, TableAlign)
	if !ok {
		return nil, errf(CatUsage, "", "section table offset overflows")
	}
	tableLen, ok := checkedMul(uint64(len(all)), SectionRecordLen)
	if !ok {
		return nil, errf(CatUsage, "", "section table length overflows")
	}
	footerOff, ok := alignUp(tableOff+tableLen, TableAlign)
	if !ok {
		return nil, errf(CatUsage, "", "footer offset overflows")
	}
	totalLen := footerOff + MinFooterLen

	out := make([]byte, totalLen)
	h := Header{
		VersionMinor:      opts.minor(),
		HeaderLen:         HeaderLen,
		SuiteID:           opts.suite(),
		SectionTableCount: uint32(len(all)),
		SectionTableOff:   tableOff,
		FooterOff:         footerOff,
		FeatIncompat:      0,
		FeatROCompat:      FeatROCompatContainerV1,
	}
	writeHeader(out[:HeaderLen], h)

	for i := range all {
		if all[i].rec.External() {
			continue
		}
		copy(out[all[i].rec.Offset:], all[i].data[:all[i].rec.LenStored])
		if all[i].rec.ChunkIndexOff != 0 {
			encoded := all[i].data[all[i].rec.LenStored:]
			copy(out[all[i].rec.ChunkIndexOff:], encoded)
		}
	}
	for i, ws := range all {
		writeRecord(out[tableOff+uint64(i)*SectionRecordLen:], ws.rec)
	}

	// Commitment root over the bytes as they appear in the file.
	hasher := blake3.New(RootLen, nil)
	hasher.Write([]byte(rootLabel))
	hasher.Write(out[:HeaderLen])
	hasher.Write(out[tableOff : tableOff+tableLen])
	var commitment [RootLen]byte
	copy(commitment[:], hasher.Sum(nil))
	copy(out[footerOff:footerOff+RootLen], commitment[:])
	binary.LittleEndian.PutUint64(out[totalLen-16:totalLen-8], totalLen)
	copy(out[totalLen-8:], Magic[:])

	// Parse our own output before returning it.
	if _, err := Parse(out); err != nil {
		return nil, errf(CatUsage, "", "writer produced a file its reader rejects: %v", err)
	}
	return out, nil
}

// appendChunkIndex appends the index entries to a fresh buffer and returns
// payload ‖ index, so the writer can copy both from one slice.
func appendChunkIndex(dst []byte, entries []ChunkHash, payload []byte) []byte {
	dst = append(dst[:0], payload...)
	for _, e := range entries {
		dst = append(dst, e[:]...)
	}
	return dst
}

func findSection(sections []Section, nameID uint16) *Section {
	for i := range sections {
		if sections[i].NameID == nameID {
			return &sections[i]
		}
	}
	return nil
}

func writeHeader(b []byte, h Header) {
	copy(b[0:8], Magic[:])
	binary.LittleEndian.PutUint16(b[8:10], h.VersionMajor)
	binary.LittleEndian.PutUint16(b[10:12], h.VersionMinor)
	binary.LittleEndian.PutUint32(b[12:16], h.HeaderLen)
	binary.LittleEndian.PutUint16(b[16:18], h.SuiteID)
	binary.LittleEndian.PutUint16(b[18:20], h.Flags)
	binary.LittleEndian.PutUint32(b[20:24], h.SectionTableCount)
	binary.LittleEndian.PutUint64(b[24:32], h.SectionTableOff)
	binary.LittleEndian.PutUint64(b[32:40], h.FooterOff)
	binary.LittleEndian.PutUint32(b[40:44], h.FeatIncompat)
	binary.LittleEndian.PutUint32(b[44:48], h.FeatROCompat)
}

func writeRecord(b []byte, r SectionRecord) {
	for i := range b {
		b[i] = 0
	}
	binary.LittleEndian.PutUint16(b[0:2], r.Kind)
	binary.LittleEndian.PutUint16(b[2:4], r.NameID)
	binary.LittleEndian.PutUint16(b[4:6], r.Flags)
	b[6] = r.Enc
	b[7] = r.Comp
	binary.LittleEndian.PutUint64(b[8:16], r.Offset)
	binary.LittleEndian.PutUint64(b[16:24], r.LenStored)
	binary.LittleEndian.PutUint64(b[24:32], r.LenPlain)
	binary.LittleEndian.PutUint32(b[32:36], r.ChunkSize)
	binary.LittleEndian.PutUint64(b[40:48], r.ChunkIndexOff)
	copy(b[48:80], r.Root[:])
}
