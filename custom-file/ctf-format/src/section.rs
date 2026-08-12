//! The section table: fixed-width 128-byte records.
//!
//! Normative layout, little-endian, all fields naturally aligned:
//!
//! ```text
//! off  size  field
//!   0     2  kind
//!   2     2  name_id           index into the manifest's name table
//!   4     2  flags
//!   6     1  enc
//!   7     1  comp
//!   8     8  offset            0 when EXTERNAL
//!  16     8  len_stored        0 when EXTERNAL
//!  24     8  len_plain
//!  32     4  chunk_size        0 = single chunk
//!  36     4  reserved          MUST be zero
//!  40     8  chunk_index_off   0 when single chunk
//!  48    32  root              BLAKE3 root of the *plaintext*
//!  80    48  reserved          MUST be zero
//! ```
//!
//! # Divergence from design §6
//!
//! The design doc lists `external` as both a section *kind* and a section *flag*.
//! It is only a flag here. A section's kind says what it semantically is; whether
//! its bytes live inline or elsewhere is orthogonal — an external artifact and an
//! external forensics image are both sensible, so folding "external" into the kind
//! enum would make those unrepresentable. `SectionKind::External` is therefore
//! gone and `SectionFlags::EXTERNAL` is the single source of truth.
//!
//! # Layout freedom
//!
//! Sections may live anywhere in `[HEADER_LEN, footer_off)`. The design doc's
//! layout diagram is illustrative, not normative: a writer streaming a multi-GB
//! payload does not know final sizes until it is done, so forcing a fixed region
//! order would force it to buffer. The only structural rules are the ones
//! [`validate_layout`] enforces — no overlaps, everything in bounds.

use crate::{
    Error, HEADER_LEN, Header, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE, PAYLOAD_ALIGN, Result,
    SECTION_RECORD_LEN, TABLE_ALIGN, all_zero, u16_at, u32_at, u64_at,
};

const OFF_KIND: usize = 0;
const OFF_NAME_ID: usize = 2;
const OFF_FLAGS: usize = 4;
const OFF_ENC: usize = 6;
const OFF_COMP: usize = 7;
const OFF_OFFSET: usize = 8;
const OFF_LEN_STORED: usize = 16;
const OFF_LEN_PLAIN: usize = 24;
const OFF_CHUNK_SIZE: usize = 32;
const OFF_RESERVED_A: usize = 36;
const RESERVED_A_LEN: usize = 4;
const OFF_CHUNK_INDEX_OFF: usize = 40;
const OFF_ROOT: usize = 48;
const ROOT_LEN: usize = 32;
const OFF_RESERVED_B: usize = 80;
const RESERVED_B_LEN: usize = 48;

/// What a section semantically is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SectionKind {
    /// Canonical CBOR manifest. Exactly one per bundle.
    Manifest = 1,
    /// A challenge artifact, whether player-facing or generator-internal.
    Artifact = 2,
    /// `gen.wasm`.
    Generator = 3,
    /// `solver.wasm`. Always sealed.
    Solver = 4,
    /// Author writeup. Always sealed.
    Writeup = 5,
    /// Entitlement chain records (design §9).
    Entitlement = 6,
    /// Hybrid KEM key envelopes.
    Keys = 7,
    /// Sealed per-holder progress blob.
    Progress = 8,
}

impl SectionKind {
    /// Kind 0 is never valid, which is what makes a zero-filled record a reject
    /// rather than a plausible manifest section.
    fn from_u16(v: u16) -> Result<Self> {
        Ok(match v {
            1 => Self::Manifest,
            2 => Self::Artifact,
            3 => Self::Generator,
            4 => Self::Solver,
            5 => Self::Writeup,
            6 => Self::Entitlement,
            7 => Self::Keys,
            8 => Self::Progress,
            got => return Err(Error::InvalidSectionKind { got }),
        })
    }

    /// Kinds that must never be readable during the event.
    fn must_be_sealed(self) -> bool {
        matches!(self, Self::Solver | Self::Writeup | Self::Progress)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Encryption {
    None = 0,
    AeadStream = 1,
}

impl Encryption {
    fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            0 => Self::None,
            1 => Self::AeadStream,
            got => {
                return Err(Error::UnknownDiscriminant {
                    at: "section.enc",
                    got,
                });
            }
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Compression {
    None = 0,
    Zstd = 1,
}

impl Compression {
    fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            0 => Self::None,
            1 => Self::Zstd,
            got => {
                return Err(Error::UnknownDiscriminant {
                    at: "section.comp",
                    got,
                });
            }
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionFlags(pub u16);

impl SectionFlags {
    /// Encrypted to the seal recipient, which the platform does not hold during
    /// the event (design §4).
    pub const SEALED: u16 = 1 << 0;
    /// Eligible to be served to players. An allowlist, never a blocklist.
    pub const PLAYER_VISIBLE: u16 = 1 << 1;
    /// Bytes live outside the file; `offset` and `len_stored` are 0 and the
    /// manifest carries the mirror list.
    pub const EXTERNAL: u16 = 1 << 2;

    const KNOWN: u16 = Self::SEALED | Self::PLAYER_VISIBLE | Self::EXTERNAL;

    pub const fn empty() -> Self {
        Self(0)
    }
    pub const fn contains(self, bit: u16) -> bool {
        self.0 & bit != 0
    }
    pub const fn sealed(self) -> bool {
        self.contains(Self::SEALED)
    }
    pub const fn player_visible(self) -> bool {
        self.contains(Self::PLAYER_VISIBLE)
    }
    pub const fn external(self) -> bool {
        self.contains(Self::EXTERNAL)
    }

    fn validate(self) -> Result<()> {
        let unknown = self.0 & !Self::KNOWN;
        if unknown != 0 {
            return Err(Error::UnknownFlagBits {
                at: "section.flags",
                bits: unknown,
            });
        }
        // The leak-prevention invariant, enforced in the container itself rather
        // than only in the serving layer. Design §10 wants two independent
        // checks; this is the one that cannot be forgotten by a caller.
        if self.sealed() && self.player_visible() {
            return Err(Error::Inconsistent {
                what: "section is both SEALED and PLAYER_VISIBLE",
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionRecord {
    pub kind: SectionKind,
    pub name_id: u16,
    pub flags: SectionFlags,
    pub enc: Encryption,
    pub comp: Compression,
    /// Byte offset of the stored bytes. 0 when [`SectionFlags::EXTERNAL`].
    pub offset: u64,
    /// Stored length: after compression and encryption. 0 when EXTERNAL.
    pub len_stored: u64,
    /// Plaintext length, before compression and encryption.
    pub len_plain: u64,
    /// 0 means the section is a single chunk.
    pub chunk_size: u32,
    /// 0 when single-chunk.
    pub chunk_index_off: u64,
    /// BLAKE3 root of the plaintext, so the commitment is independent of how the
    /// bytes happen to be stored.
    pub root: [u8; ROOT_LEN],
}

impl SectionRecord {
    /// Parse and validate one record for self-consistency. Whole-table invariants
    /// are [`validate_layout`]'s job.
    pub fn parse(b: &[u8]) -> Result<Self> {
        if b.len() < SECTION_RECORD_LEN {
            return Err(Error::Truncated {
                need: SECTION_RECORD_LEN,
                got: b.len(),
            });
        }
        let trunc = || Error::Truncated {
            need: SECTION_RECORD_LEN,
            got: b.len(),
        };

        if !all_zero(b, OFF_RESERVED_A, RESERVED_A_LEN).ok_or_else(trunc)?
            || !all_zero(b, OFF_RESERVED_B, RESERVED_B_LEN).ok_or_else(trunc)?
        {
            return Err(Error::ReservedNotZero { at: "section" });
        }

        let kind = SectionKind::from_u16(u16_at(b, OFF_KIND).ok_or_else(trunc)?)?;
        let flags = SectionFlags(u16_at(b, OFF_FLAGS).ok_or_else(trunc)?);
        flags.validate()?;

        if kind.must_be_sealed() && !flags.sealed() {
            return Err(Error::Inconsistent {
                what: "solver, writeup and progress sections must be SEALED",
            });
        }
        if kind == SectionKind::Manifest {
            // The manifest is needed to do anything at all, so it cannot wait for
            // a seal key that is offline during the event. It also carries the
            // flag template, so it is never player-facing.
            if flags.sealed() {
                return Err(Error::Inconsistent {
                    what: "manifest section must not be SEALED",
                });
            }
            if flags.player_visible() {
                return Err(Error::Inconsistent {
                    what: "manifest section must not be PLAYER_VISIBLE",
                });
            }
            if flags.external() {
                return Err(Error::Inconsistent {
                    what: "manifest section must not be EXTERNAL",
                });
            }
        }

        let enc = Encryption::from_u8(*b.get(OFF_ENC).ok_or_else(trunc)?)?;
        let comp = Compression::from_u8(*b.get(OFF_COMP).ok_or_else(trunc)?)?;

        let offset = u64_at(b, OFF_OFFSET).ok_or_else(trunc)?;
        let len_stored = u64_at(b, OFF_LEN_STORED).ok_or_else(trunc)?;
        let len_plain = u64_at(b, OFF_LEN_PLAIN).ok_or_else(trunc)?;
        let chunk_size = u32_at(b, OFF_CHUNK_SIZE).ok_or_else(trunc)?;
        let chunk_index_off = u64_at(b, OFF_CHUNK_INDEX_OFF).ok_or_else(trunc)?;

        if flags.external() {
            if offset != 0 || len_stored != 0 {
                return Err(Error::Inconsistent {
                    what: "EXTERNAL section must have offset and len_stored of 0",
                });
            }
        } else {
            if offset < u64::from(HEADER_LEN) {
                return Err(Error::BadOffset {
                    at: "section.offset",
                    got: offset,
                });
            }
            if offset % PAYLOAD_ALIGN != 0 {
                return Err(Error::Misaligned {
                    at: "section.offset",
                    got: offset,
                    align: PAYLOAD_ALIGN,
                });
            }
            offset
                .checked_add(len_stored)
                .ok_or(Error::LengthOverflow {
                    at: "section range",
                })?;
        }

        // Without compression or encryption, stored and plaintext lengths are the
        // same thing. Letting them disagree would let a writer smuggle bytes past
        // the commitment.
        if enc == Encryption::None
            && comp == Compression::None
            && !flags.external()
            && len_stored != len_plain
        {
            return Err(Error::Inconsistent {
                what: "unencrypted, uncompressed section has len_stored != len_plain",
            });
        }

        if chunk_size != 0
            && (!chunk_size.is_power_of_two()
                || !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size))
        {
            return Err(Error::BadChunkSize { got: chunk_size });
        }
        // STREAM is defined over a chunk sequence; a chunk size of 0 would leave
        // the nonce counter undefined.
        if enc == Encryption::AeadStream && chunk_size == 0 {
            return Err(Error::Inconsistent {
                what: "AEAD-STREAM section requires a non-zero chunk_size",
            });
        }
        if chunk_index_off != 0 {
            if chunk_size == 0 {
                return Err(Error::Inconsistent {
                    what: "chunk_index_off set on a single-chunk section",
                });
            }
            if chunk_index_off < u64::from(HEADER_LEN) {
                return Err(Error::BadOffset {
                    at: "section.chunk_index_off",
                    got: chunk_index_off,
                });
            }
            if chunk_index_off % TABLE_ALIGN != 0 {
                return Err(Error::Misaligned {
                    at: "section.chunk_index_off",
                    got: chunk_index_off,
                    align: TABLE_ALIGN,
                });
            }
            // ponytail: the chunk index's own length is not checked yet — its
            // record format lands with verified streaming in phase 1. Bound it
            // against footer_off once the entry size is defined.
        }

        let root: [u8; ROOT_LEN] = b
            .get(OFF_ROOT..OFF_ROOT + ROOT_LEN)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(trunc)?;

        Ok(Self {
            kind,
            name_id: u16_at(b, OFF_NAME_ID).ok_or_else(trunc)?,
            flags,
            enc,
            comp,
            offset,
            len_stored,
            len_plain,
            chunk_size,
            chunk_index_off,
            root,
        })
    }

    /// Serialize. Round-trips [`SectionRecord::parse`] byte-for-byte.
    pub fn to_bytes(&self) -> [u8; SECTION_RECORD_LEN] {
        let mut b = [0u8; SECTION_RECORD_LEN];
        let mut put = |off: usize, src: &[u8]| {
            if let Some(dst) = b.get_mut(off..off + src.len()) {
                dst.copy_from_slice(src);
            }
        };
        put(OFF_KIND, &(self.kind as u16).to_le_bytes());
        put(OFF_NAME_ID, &self.name_id.to_le_bytes());
        put(OFF_FLAGS, &self.flags.0.to_le_bytes());
        put(OFF_ENC, &[self.enc as u8]);
        put(OFF_COMP, &[self.comp as u8]);
        put(OFF_OFFSET, &self.offset.to_le_bytes());
        put(OFF_LEN_STORED, &self.len_stored.to_le_bytes());
        put(OFF_LEN_PLAIN, &self.len_plain.to_le_bytes());
        put(OFF_CHUNK_SIZE, &self.chunk_size.to_le_bytes());
        put(OFF_CHUNK_INDEX_OFF, &self.chunk_index_off.to_le_bytes());
        put(OFF_ROOT, &self.root);
        b
    }

    /// Inclusive-exclusive byte range of the stored bytes, or `None` if EXTERNAL.
    fn stored_range(&self) -> Option<(u64, u64)> {
        if self.flags.external() {
            return None;
        }
        Some((self.offset, self.offset.saturating_add(self.len_stored)))
    }
}

/// Parse the whole section table.
///
/// `count` comes from the header, which has already capped it at
/// [`crate::MAX_SECTIONS`] — so the `Vec` below cannot be sized by an attacker.
pub fn parse_table(b: &[u8], count: u32) -> Result<Vec<SectionRecord>> {
    let count = count as usize;
    let need = count
        .checked_mul(SECTION_RECORD_LEN)
        .ok_or(Error::LengthOverflow {
            at: "section table",
        })?;
    if b.len() < need {
        return Err(Error::Truncated { need, got: b.len() });
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let start = i * SECTION_RECORD_LEN;
        let rec = b
            .get(start..start + SECTION_RECORD_LEN)
            .ok_or(Error::Truncated { need, got: b.len() })?;
        out.push(SectionRecord::parse(rec)?);
    }
    Ok(out)
}

/// Whole-table invariants: uniqueness, bounds, and non-overlap.
///
/// Overlap matters beyond tidiness: two sections sharing bytes is exactly the
/// ambiguity that turns into a parser-differential exploit, where two readers
/// disagree about what a bundle contains.
pub fn validate_layout(records: &[SectionRecord], header: &Header, file_len: u64) -> Result<()> {
    header.check_file_len(file_len)?;
    let (table_start, table_end) = header.table_range()?;

    let manifests = records
        .iter()
        .filter(|r| r.kind == SectionKind::Manifest)
        .count();
    if manifests != 1 {
        return Err(Error::ManifestCount { got: manifests });
    }

    let mut names: Vec<u16> = records.iter().map(|r| r.name_id).collect();
    names.sort_unstable();
    if let Some(dup) = names.windows(2).find(|w| w.first() == w.get(1)) {
        return Err(Error::DuplicateSectionName {
            name_id: dup.first().copied().unwrap_or_default(),
        });
    }

    // (start, end, name_id) for every inline section, plus the table itself so a
    // section cannot be laid over it.
    let mut ranges: Vec<(u64, u64, u16)> = Vec::with_capacity(records.len() + 1);
    for r in records {
        let Some((start, end)) = r.stored_range() else {
            continue;
        };
        if end > header.footer_off {
            return Err(Error::ExceedsFile {
                at: "section payload",
                end,
                file_len: header.footer_off,
            });
        }
        if end > start {
            ranges.push((start, end, r.name_id));
        }
    }
    if table_end > table_start {
        ranges.push((table_start, table_end, u16::MAX));
    }

    ranges.sort_unstable();
    for w in ranges.windows(2) {
        let (Some(a), Some(b)) = (w.first(), w.get(1)) else {
            continue;
        };
        if b.0 < a.1 {
            return Err(Error::OverlappingSections { a: a.2, b: b.2 });
        }
    }
    Ok(())
}
