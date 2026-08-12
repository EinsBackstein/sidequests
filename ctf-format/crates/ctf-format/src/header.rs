//! The 64-byte file header.
//!
//! Normative layout, little-endian, all fields naturally aligned:
//!
//! ```text
//! off  size  field
//!   0     8  magic                = 89 43 54 46 0d 0a 1a 0a
//!   8     2  version_major
//!  10     2  version_minor
//!  12     4  header_len           = 64
//!  16     2  suite_id             crypto suite (design §7)
//!  18     2  flags                MUST be 0 in this version
//!  20     4  section_table_count
//!  24     8  section_table_off
//!  32     8  footer_off
//!  40     4  feat_incompat        unsupported bit => reject the file
//!  44     4  feat_ro_compat       unsupported bit => read-only
//!  48    16  reserved             MUST be zero
//! ```
//!
//! Normative: `spec/SPEC.md` §4, whose rules H1–H14 this module implements
//! one-for-one.

use crate::{
    Error, HEADER_LEN, MAGIC, MAX_SECTIONS, Result, SECTION_RECORD_LEN, SUPPORTED_INCOMPAT,
    SUPPORTED_RO_COMPAT, TABLE_ALIGN, VERSION_MAJOR, all_zero, u16_at, u32_at, u64_at,
};

const OFF_MAGIC: usize = 0;
const OFF_VERSION_MAJOR: usize = 8;
const OFF_VERSION_MINOR: usize = 10;
const OFF_HEADER_LEN: usize = 12;
const OFF_SUITE_ID: usize = 16;
const OFF_FLAGS: usize = 18;
const OFF_SECTION_TABLE_COUNT: usize = 20;
const OFF_SECTION_TABLE_OFF: usize = 24;
const OFF_FOOTER_OFF: usize = 32;
const OFF_FEAT_INCOMPAT: usize = 40;
const OFF_FEAT_RO_COMPAT: usize = 44;
const OFF_RESERVED: usize = 48;
const RESERVED_LEN: usize = 16;

/// No header flag bits are assigned in this version, so any set bit is a reject.
const KNOWN_HEADER_FLAGS: u16 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub version_major: u16,
    pub version_minor: u16,
    /// Crypto suite selector. Not validated here — the suite registry arrives in
    /// phase 2. Recorded verbatim so an unknown suite fails at the point where a
    /// primitive is actually needed, with a useful message.
    pub suite_id: u16,
    pub flags: u16,
    pub section_table_count: u32,
    pub section_table_off: u64,
    pub footer_off: u64,
    /// Features a reader must implement to read the file at all. Any bit outside
    /// [`crate::SUPPORTED_INCOMPAT`] is a reject.
    pub feat_incompat: u32,
    /// Features a reader must implement to *rewrite* the file. Unknown bits leave
    /// the file readable; see [`Header::may_rewrite`].
    pub feat_ro_compat: u32,
}

impl Header {
    /// Parse and validate a header for *self*-consistency.
    ///
    /// Deliberately does not know the file length; call [`Header::check_file_len`]
    /// for that. Splitting them keeps this usable on a streaming reader that has
    /// only the first 64 bytes.
    pub fn parse(b: &[u8]) -> Result<Self> {
        let need = HEADER_LEN as usize;
        if b.len() < need {
            return Err(Error::Truncated { need, got: b.len() });
        }

        let magic: [u8; 8] = b
            .get(OFF_MAGIC..OFF_MAGIC + 8)
            .and_then(|s| s.try_into().ok())
            .ok_or(Error::Truncated { need, got: b.len() })?;
        if magic != MAGIC {
            return Err(Error::BadMagic { got: magic });
        }

        let trunc = || Error::Truncated { need, got: b.len() };

        let version_major = u16_at(b, OFF_VERSION_MAJOR).ok_or_else(trunc)?;
        let version_minor = u16_at(b, OFF_VERSION_MINOR).ok_or_else(trunc)?;
        if version_major != VERSION_MAJOR {
            return Err(Error::UnsupportedVersion {
                major: version_major,
                minor: version_minor,
            });
        }

        // Strict for now. A future major may grow the header; this major may not,
        // so a mismatch is a corrupt file rather than a newer writer.
        let header_len = u32_at(b, OFF_HEADER_LEN).ok_or_else(trunc)?;
        if header_len != HEADER_LEN {
            return Err(Error::BadHeaderLen { got: header_len });
        }

        // Feature negotiation comes before every structural check, and before the
        // reserved-zero check in particular. A file built for a future minor may
        // legitimately put data where this version sees reserved space, so asking
        // "do I implement what this file needs" first is what turns a confusing
        // `ReservedNotZero` into an accurate "unsupported feature".
        let feat_incompat = u32_at(b, OFF_FEAT_INCOMPAT).ok_or_else(trunc)?;
        let unsupported = feat_incompat & !SUPPORTED_INCOMPAT;
        if unsupported != 0 {
            return Err(Error::UnsupportedFeature {
                class: "incompat",
                bits: unsupported,
            });
        }
        // Unknown ro_compat bits are deliberately *not* an error: everything this
        // reader understands is still true of the file. Only rewriting is unsafe,
        // which `may_rewrite` reports.
        let feat_ro_compat = u32_at(b, OFF_FEAT_RO_COMPAT).ok_or_else(trunc)?;

        if !all_zero(b, OFF_RESERVED, RESERVED_LEN).ok_or_else(trunc)? {
            return Err(Error::ReservedNotZero { at: "header" });
        }

        let flags = u16_at(b, OFF_FLAGS).ok_or_else(trunc)?;
        if flags & !KNOWN_HEADER_FLAGS != 0 {
            return Err(Error::UnknownFlagBits {
                at: "header.flags",
                bits: flags & !KNOWN_HEADER_FLAGS,
            });
        }

        // Cap before any caller can turn this into an allocation.
        let section_table_count = u32_at(b, OFF_SECTION_TABLE_COUNT).ok_or_else(trunc)?;
        if section_table_count > MAX_SECTIONS {
            return Err(Error::TooManySections {
                got: section_table_count,
                max: MAX_SECTIONS,
            });
        }

        let section_table_off = u64_at(b, OFF_SECTION_TABLE_OFF).ok_or_else(trunc)?;
        if section_table_off < u64::from(HEADER_LEN) {
            return Err(Error::BadOffset {
                at: "header.section_table_off",
                got: section_table_off,
            });
        }
        if section_table_off % TABLE_ALIGN != 0 {
            return Err(Error::Misaligned {
                at: "header.section_table_off",
                got: section_table_off,
                align: TABLE_ALIGN,
            });
        }

        let footer_off = u64_at(b, OFF_FOOTER_OFF).ok_or_else(trunc)?;
        let table_end = Self::table_end_of(section_table_off, section_table_count)?;
        if footer_off < table_end {
            return Err(Error::BadOffset {
                at: "header.footer_off",
                got: footer_off,
            });
        }

        Ok(Self {
            version_major,
            version_minor,
            suite_id: u16_at(b, OFF_SUITE_ID).ok_or_else(trunc)?,
            flags,
            section_table_count,
            section_table_off,
            footer_off,
            feat_incompat,
            feat_ro_compat,
        })
    }

    /// Whether this build may rewrite the file without losing data.
    ///
    /// False when the file carries a read-only-compatible feature this build does
    /// not implement: the bytes are readable, but re-emitting them would silently
    /// drop whatever that feature added — and since the footer commits to the whole
    /// file, "silently drop" means the rewritten bundle no longer says what the
    /// author signed.
    pub fn may_rewrite(&self) -> bool {
        self.feat_ro_compat & !SUPPORTED_RO_COMPAT == 0
    }

    /// Byte range of the section table: `[off, off + count * 128)`.
    pub fn table_range(&self) -> Result<(u64, u64)> {
        Ok((
            self.section_table_off,
            Self::table_end_of(self.section_table_off, self.section_table_count)?,
        ))
    }

    fn table_end_of(off: u64, count: u32) -> Result<u64> {
        u64::from(count)
            .checked_mul(SECTION_RECORD_LEN as u64)
            .and_then(|len| off.checked_add(len))
            .ok_or(Error::LengthOverflow {
                at: "header.section_table",
            })
    }

    /// Cross-check the header's offsets against the real file length.
    pub fn check_file_len(&self, file_len: u64) -> Result<()> {
        let (_, table_end) = self.table_range()?;
        if table_end > file_len {
            return Err(Error::ExceedsFile {
                at: "section table",
                end: table_end,
                file_len,
            });
        }
        if self.footer_off > file_len {
            return Err(Error::ExceedsFile {
                at: "footer",
                end: self.footer_off,
                file_len,
            });
        }
        Ok(())
    }

    /// Serialize. Round-trips [`Header::parse`] byte-for-byte.
    pub fn to_bytes(&self) -> [u8; HEADER_LEN as usize] {
        let mut b = [0u8; HEADER_LEN as usize];
        let mut put = |off: usize, src: &[u8]| {
            if let Some(dst) = b.get_mut(off..off + src.len()) {
                dst.copy_from_slice(src);
            }
        };
        put(OFF_MAGIC, &MAGIC);
        put(OFF_VERSION_MAJOR, &self.version_major.to_le_bytes());
        put(OFF_VERSION_MINOR, &self.version_minor.to_le_bytes());
        put(OFF_HEADER_LEN, &HEADER_LEN.to_le_bytes());
        put(OFF_SUITE_ID, &self.suite_id.to_le_bytes());
        put(OFF_FLAGS, &self.flags.to_le_bytes());
        put(
            OFF_SECTION_TABLE_COUNT,
            &self.section_table_count.to_le_bytes(),
        );
        put(OFF_SECTION_TABLE_OFF, &self.section_table_off.to_le_bytes());
        put(OFF_FOOTER_OFF, &self.footer_off.to_le_bytes());
        put(OFF_FEAT_INCOMPAT, &self.feat_incompat.to_le_bytes());
        put(OFF_FEAT_RO_COMPAT, &self.feat_ro_compat.to_le_bytes());
        // Reserved bytes stay zero from initialization.
        b
    }
}
