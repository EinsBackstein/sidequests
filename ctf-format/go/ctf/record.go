package ctf

import "encoding/binary"

// SectionRecord is one fixed 128-byte section-table record of spec §5.1.
type SectionRecord struct {
	Kind          uint16
	NameID        uint16
	Flags         uint16
	Enc           uint8
	Comp          uint8
	Offset        uint64
	LenStored     uint64
	LenPlain      uint64
	ChunkSize     uint32
	ChunkIndexOff uint64
	Root          [RootLen]byte
}

// Has reports whether every bit of mask is set in the record's flags.
func (r SectionRecord) Has(mask uint16) bool { return r.Flags&mask == mask }

// External reports whether the section's bytes live outside the file.
func (r SectionRecord) External() bool { return r.Has(FlagExternal) }

// Understood reports whether this implementation implements the kind. Unknown
// kinds are carried, never interpreted (spec §5.2).
func (r SectionRecord) Understood() bool { return r.Kind >= 1 && r.Kind <= 8 }

// InlineRange returns the payload range and whether it is non-empty. EXTERNAL
// records have no inline range.
func (r SectionRecord) InlineRange() (start, end uint64, nonEmpty bool, ok bool) {
	if r.External() {
		return 0, 0, false, true
	}
	end, ok = checkedAdd(r.Offset, r.LenStored)
	if !ok {
		return 0, 0, false, false
	}
	return r.Offset, end, r.LenStored > 0, true
}

// ChunkIndexRange returns the index range for a record with a non-zero
// chunk_index_off. It requires chunk_size != 0 (R16 guarantees that in a parsed
// record), and reports overflow as ok=false.
func (r SectionRecord) ChunkIndexRange() (start, end uint64, ok bool) {
	if r.ChunkIndexOff == 0 {
		return 0, 0, true
	}
	if r.ChunkSize == 0 {
		return 0, 0, false
	}
	count, cok := chunkCount(r.LenPlain, uint64(r.ChunkSize))
	if !cok {
		return 0, 0, false
	}
	length, mok := checkedMul(count, RootLen)
	if !mok {
		return 0, 0, false
	}
	end, aok := checkedAdd(r.ChunkIndexOff, length)
	if !aok {
		return 0, 0, false
	}
	return r.ChunkIndexOff, end, true
}

// parseRecord decodes and validates one record. Rules are evaluated in the
// order §5.6 requires: R4 before R3/R18, R16 before R19 and the chunk-length
// formula. R20, R21 and R22 apply only when CONTAINER_V1 is set.
func parseRecord(b []byte, index int, containerV1 bool) (SectionRecord, error) {
	var r SectionRecord
	if len(b) < SectionRecordLen {
		return r, errf(CatSection, "R1", "record %d: have %d bytes, need %d", index, len(b), SectionRecordLen)
	}
	_ = b[SectionRecordLen-1]
	for i := 36; i < 40; i++ {
		if b[i] != 0 {
			return r, errf(CatSection, "R2", "record %d: reserved byte at %d is non-zero", index, i)
		}
	}
	for i := 80; i < 128; i++ {
		if b[i] != 0 {
			return r, errf(CatSection, "R2", "record %d: reserved byte at %d is non-zero", index, i)
		}
	}
	r.Kind = binary.LittleEndian.Uint16(b[0:2])
	r.NameID = binary.LittleEndian.Uint16(b[2:4])
	r.Flags = binary.LittleEndian.Uint16(b[4:6])
	r.Enc = b[6]
	r.Comp = b[7]
	r.Offset = binary.LittleEndian.Uint64(b[8:16])
	r.LenStored = binary.LittleEndian.Uint64(b[16:24])
	r.LenPlain = binary.LittleEndian.Uint64(b[24:32])
	r.ChunkSize = binary.LittleEndian.Uint32(b[32:36])
	r.ChunkIndexOff = binary.LittleEndian.Uint64(b[40:48])
	copy(r.Root[:], b[48:80])

	// R4 before R3 and R18: whether an undefined kind is a rejection or a
	// skippable section depends on the OPTIONAL flag.
	if r.Flags&^flagAssignedMask != 0 {
		return r, errf(CatSection, "R4", "record %d: unassigned flag bits 0x%04x", index, r.Flags&^flagAssignedMask)
	}
	if r.Kind == 0 {
		return r, errf(CatSection, "R3", "record %d: kind 0", index)
	}
	if r.Kind > 8 && !r.Has(FlagOptional) {
		return r, errf(CatSection, "R18", "record %d: unknown kind %d without OPTIONAL", index, r.Kind)
	}
	if r.Has(FlagSealed) && r.Has(FlagPlayerVisible) {
		return r, errf(CatSection, "R5", "record %d: SEALED and PLAYER_VISIBLE both set", index)
	}
	switch r.Kind {
	case KindSolver, KindWriteup, KindProgress:
		if !r.Has(FlagSealed) {
			return r, errf(CatSection, "R6", "record %d: kind %d is not SEALED", index, r.Kind)
		}
	case KindManifest:
		if r.Has(FlagSealed) {
			return r, errf(CatSection, "R7", "record %d: manifest is SEALED", index)
		}
		if r.Has(FlagPlayerVisible) {
			return r, errf(CatSection, "R8", "record %d: manifest is PLAYER_VISIBLE", index)
		}
		if r.Has(FlagExternal) {
			return r, errf(CatSection, "R9", "record %d: manifest is EXTERNAL", index)
		}
	}
	if containerV1 {
		if r.Kind == KindManifest && (r.Enc != EncNone || r.Comp != CompNone) {
			return r, errf(CatSection, "R20", "record %d: manifest carries enc=%d comp=%d", index, r.Enc, r.Comp)
		}
		if r.Has(FlagSealed) && r.Enc == EncNone {
			return r, errf(CatSection, "R21", "record %d: SEALED with enc=0", index)
		}
		if r.Has(FlagExternal) && (r.Enc != EncNone || r.Comp != CompNone) {
			return r, errf(CatSection, "R22", "record %d: EXTERNAL carries enc=%d comp=%d", index, r.Enc, r.Comp)
		}
	}
	if r.Enc > EncStream {
		return r, errf(CatSection, "R10", "record %d: enc %d not assigned", index, r.Enc)
	}
	if r.Comp > CompZstd {
		return r, errf(CatSection, "R10", "record %d: comp %d not assigned", index, r.Comp)
	}
	if r.External() {
		if r.Offset != 0 || r.LenStored != 0 {
			return r, errf(CatSection, "R11", "record %d: EXTERNAL offset=%d len_stored=%d", index, r.Offset, r.LenStored)
		}
	} else {
		if r.Offset < HeaderLen {
			return r, errf(CatSection, "R12", "record %d: offset %d below %d", index, r.Offset, HeaderLen)
		}
		if r.Offset%PayloadAlign != 0 {
			return r, errf(CatSection, "R12", "record %d: offset %d not aligned to %d", index, r.Offset, PayloadAlign)
		}
		if _, ok := checkedAdd(r.Offset, r.LenStored); !ok {
			return r, errf(CatSection, "R12", "record %d: offset+len_stored overflows", index)
		}
	}
	if !r.External() && r.Enc == EncNone && r.Comp == CompNone && r.LenStored != r.LenPlain {
		return r, errf(CatSection, "R13", "record %d: len_stored %d != len_plain %d", index, r.LenStored, r.LenPlain)
	}
	if r.ChunkSize != 0 {
		if r.ChunkSize < MinChunkSize || r.ChunkSize > MaxChunkSize || r.ChunkSize&(r.ChunkSize-1) != 0 {
			return r, errf(CatSection, "R14", "record %d: chunk_size %d not a power of two in [%d,%d]", index, r.ChunkSize, MinChunkSize, MaxChunkSize)
		}
	}
	if r.Enc == EncStream && r.ChunkSize == 0 {
		return r, errf(CatSection, "R15", "record %d: enc=1 with chunk_size=0", index)
	}
	if r.ChunkIndexOff != 0 && r.ChunkSize == 0 {
		return r, errf(CatSection, "R16", "record %d: chunk_index_off set with chunk_size=0", index)
	}
	if r.ChunkIndexOff != 0 {
		if r.ChunkIndexOff < HeaderLen || r.ChunkIndexOff%TableAlign != 0 {
			return r, errf(CatSection, "R17", "record %d: chunk_index_off %d bad alignment", index, r.ChunkIndexOff)
		}
		count, ok := chunkCount(r.LenPlain, uint64(r.ChunkSize))
		if !ok {
			return r, errf(CatSection, "R19", "record %d: chunk count overflows", index)
		}
		if count < 2 {
			return r, errf(CatSection, "R19", "record %d: chunk index would have %d entries", index, count)
		}
	}
	return r, nil
}
