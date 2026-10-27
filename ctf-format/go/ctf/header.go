package ctf

import "encoding/binary"

// Header is the fixed 64-byte header of spec §4.
type Header struct {
	VersionMajor      uint16
	VersionMinor      uint16
	HeaderLen         uint32
	SuiteID           uint16
	Flags             uint16
	SectionTableCount uint32
	SectionTableOff   uint64
	FooterOff         uint64
	FeatIncompat      uint32
	FeatROCompat      uint32
}

func (h Header) hasContainerV1() bool {
	return h.FeatROCompat&FeatROCompatContainerV1 != 0
}

// MayRewrite reports whether spec §4.4 permits rewriting a file with this
// header: every feat_ro_compat bit must be implemented.
func (h Header) MayRewrite() bool {
	return h.FeatROCompat&^SupportedROCompat == 0
}

// ParseHeader validates and decodes a header whose bytes start at b[0]. It
// accepts legacy 0.1/0.2 headers (§4.3 note on H14, §16); callers that need the
// container structures must check the CONTAINER_V1 bit themselves.
func ParseHeader(b []byte) (Header, error) {
	var h Header
	if len(b) < HeaderLen {
		return h, errf(CatHeader, "H1", "have %d bytes, need %d", len(b), HeaderLen)
	}
	if [8]byte(b[0:8]) != Magic {
		return h, errf(CatHeader, "H2", "bad file signature")
	}
	h.VersionMajor = binary.LittleEndian.Uint16(b[8:10])
	h.VersionMinor = binary.LittleEndian.Uint16(b[10:12])
	h.HeaderLen = binary.LittleEndian.Uint32(b[12:16])
	h.SuiteID = binary.LittleEndian.Uint16(b[16:18])
	h.Flags = binary.LittleEndian.Uint16(b[18:20])
	h.SectionTableCount = binary.LittleEndian.Uint32(b[20:24])
	h.SectionTableOff = binary.LittleEndian.Uint64(b[24:32])
	h.FooterOff = binary.LittleEndian.Uint64(b[32:40])
	h.FeatIncompat = binary.LittleEndian.Uint32(b[40:44])
	h.FeatROCompat = binary.LittleEndian.Uint32(b[44:48])

	if h.VersionMajor != VersionMajor {
		return h, errf(CatHeader, "H3", "unsupported major version %d", h.VersionMajor)
	}
	if h.HeaderLen != HeaderLen {
		return h, errf(CatHeader, "H4", "header_len %d != %d", h.HeaderLen, HeaderLen)
	}
	// H14 MUST be evaluated before H5, H6 and every structural rule.
	if h.FeatIncompat&^SupportedIncompat != 0 {
		return h, errf(CatHeader, "H14", "unsupported feat_incompat bits 0x%08x", h.FeatIncompat&^SupportedIncompat)
	}
	for i := 48; i < 64; i++ {
		if b[i] != 0 {
			return h, errf(CatHeader, "H5", "reserved byte at offset %d is non-zero", i)
		}
	}
	if h.Flags != 0 {
		return h, errf(CatHeader, "H6", "flags 0x%04x not assigned", h.Flags)
	}
	if h.SectionTableCount > MaxSections {
		return h, errf(CatHeader, "H7", "section_table_count %d exceeds %d", h.SectionTableCount, MaxSections)
	}
	if h.SectionTableOff < HeaderLen {
		return h, errf(CatHeader, "H8", "section_table_off %d below %d", h.SectionTableOff, HeaderLen)
	}
	if h.SectionTableOff%TableAlign != 0 {
		return h, errf(CatHeader, "H9", "section_table_off %d not aligned to %d", h.SectionTableOff, TableAlign)
	}
	tableLen, ok := checkedMul(uint64(h.SectionTableCount), SectionRecordLen)
	if !ok {
		return h, errf(CatHeader, "H10", "section table length overflows")
	}
	tableEnd, ok := checkedAdd(h.SectionTableOff, tableLen)
	if !ok {
		return h, errf(CatHeader, "H10", "section table end overflows")
	}
	if h.FooterOff < tableEnd {
		return h, errf(CatHeader, "H11", "footer_off %d below table end %d", h.FooterOff, tableEnd)
	}
	fileLen := uint64(len(b))
	if tableEnd > fileLen {
		return h, errf(CatHeader, "H12", "section table end %d beyond file length %d", tableEnd, fileLen)
	}
	if h.FooterOff > fileLen {
		return h, errf(CatHeader, "H13", "footer_off %d beyond file length %d", h.FooterOff, fileLen)
	}
	return h, nil
}
