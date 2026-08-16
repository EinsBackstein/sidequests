//! The section table: fixed-width 128-byte records.
//!
//! Normative layout, little-endian, all fields naturally aligned:
//!
//! ```text
//! off  size  field
//!   0     2  kind              >8 only with OPTIONAL
//!   2     2  name_id           name table index; the section's crypto identity
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
//! Normative: `spec/SPEC.md` §5 (record rules R1–R18) and §6 (table rules
//! T1–T5), which this module implements one-for-one. Rationale is design §6.
//!
//! # Why unknown kinds are a separate type
//!
//! A reader must be able to carry a section whose `kind` a later version of the
//! format defines (spec §5.2), so [`SectionKind`] needs a variant holding a
//! discriminant this build does not name. The obvious spelling, `Unknown(u16)`,
//! admits a state the format does not have: `Unknown(1)` is a perfectly good Rust
//! value, and [`SectionRecord::to_bytes`] would write it as `kind = 1`, emitting a
//! section that claims to be the manifest. Nothing in the file caused that — it is
//! a writer building a record wrong — but a bundle is signed and long-lived, and a
//! mislabelled section is not the kind of bug that surfaces quickly.
//!
//! [`FutureKind`] closes it by construction: a newtype whose field is private to
//! this module, reachable only through [`SectionKind::unknown`], which rejects
//! every discriminant this version defines. The invalid pairing stops being
//! something callers are trusted not to write and starts being something they
//! cannot write, which is the property worth having in a format implementation that
//! a second language will be checked against.
//!
//! The cost is one accessor: match on [`SectionKind::Unknown`] and call
//! [`FutureKind::get`] for the raw discriminant.

use crate::{
    Error, HEADER_LEN, Header, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE, PAYLOAD_ALIGN, Result,
    SECTION_RECORD_LEN, TABLE_ALIGN, all_zero, chunk, footer::ROOT_LEN, u16_at, u32_at, u64_at,
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
const OFF_RESERVED_B: usize = 80;
const RESERVED_B_LEN: usize = 48;

/// A section kind defined by some later version of the format.
///
/// The inner value is private, and that is the entire point of the type. It exists
/// so that [`SectionKind::Unknown`] cannot be built holding a discriminant this
/// version *does* define — `Unknown(1)` would otherwise be constructible, and
/// [`SectionRecord::to_bytes`] would write it as `kind = 1`, silently producing a
/// file whose section claims to be the manifest.
///
/// The invariant is therefore that the value always exceeds the largest kind this
/// version defines, and it is held by construction rather than by assertion:
/// inside this module only the record parser builds one, having already
/// range-checked the value it read from the file; outside it,
/// [`SectionKind::unknown`] is the only door and it range-checks too. A caller that
/// wants the invalid pairing cannot write it, which is the difference between an
/// invariant and a convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FutureKind(u16);

impl FutureKind {
    /// The on-disk discriminant. Always greater than the largest kind this version
    /// defines.
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// What a section semantically is.
///
/// [`SectionKind::Unknown`] carries a kind this build does not implement, which
/// only [`SectionFlags::OPTIONAL`] sections may use (spec §5.2, R18).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionKind {
    /// `1` — canonical CBOR manifest. Exactly one per bundle.
    Manifest,
    /// `2` — a challenge artifact, whether player-facing or generator-internal.
    Artifact,
    /// `3` — `gen.wasm`.
    Generator,
    /// `4` — `solver.wasm`. Always sealed.
    Solver,
    /// `5` — author writeup. Always sealed.
    Writeup,
    /// `6` — entitlement chain records (design §9).
    Entitlement,
    /// `7` — hybrid KEM key envelopes.
    Keys,
    /// `8` — sealed per-holder progress blob.
    Progress,
    /// A kind defined by a later version of the format. Only ever produced for a
    /// section marked [`SectionFlags::OPTIONAL`]; see [`FutureKind`] for why the
    /// payload is opaque.
    Unknown(FutureKind),
}

/// Largest kind this version defines. A value above it is a future kind.
const MAX_KNOWN_KIND: u16 = 8;

impl SectionKind {
    /// Kind 0 is never valid, which is what makes a zero-filled record a reject
    /// rather than a plausible manifest section.
    ///
    /// An undefined kind is an error *unless* the writer marked the section
    /// optional, which is the promise that skipping it cannot change the meaning of
    /// the rest of the file.
    fn from_u16(v: u16, flags: SectionFlags) -> Result<Self> {
        Ok(match v {
            1 => Self::Manifest,
            2 => Self::Artifact,
            3 => Self::Generator,
            4 => Self::Solver,
            5 => Self::Writeup,
            6 => Self::Entitlement,
            7 => Self::Keys,
            8 => Self::Progress,
            got if got > MAX_KNOWN_KIND && flags.optional() => Self::Unknown(FutureKind(got)),
            got => return Err(Error::InvalidSectionKind { got }),
        })
    }

    /// The kind for a discriminant this version does not define, for a writer that
    /// carries a section from a newer format version.
    ///
    /// `None` when `v` names a kind this version *does* define, including `0`:
    /// those have their own variants, and letting them through here would put a
    /// known discriminant inside `Unknown`, where it would serialize as the kind it
    /// names rather than as the unknown one the caller meant.
    ///
    /// Returning `Option` rather than [`Error`] on purpose — [`Error`] describes
    /// what can be wrong with a byte stream, and this is a caller passing the wrong
    /// number, which no file can cause.
    pub fn unknown(v: u16) -> Option<Self> {
        (v > MAX_KNOWN_KIND).then_some(Self::Unknown(FutureKind(v)))
    }

    /// The on-disk discriminant.
    pub fn to_u16(self) -> u16 {
        match self {
            Self::Manifest => 1,
            Self::Artifact => 2,
            Self::Generator => 3,
            Self::Solver => 4,
            Self::Writeup => 5,
            Self::Entitlement => 6,
            Self::Keys => 7,
            Self::Progress => 8,
            // No assertion needed: `FutureKind` cannot hold a known discriminant.
            Self::Unknown(v) => v.get(),
        }
    }

    /// Whether this build understands what the section contains. A section it does
    /// not understand may be carried and committed to, never served or executed.
    pub fn is_known(self) -> bool {
        !matches!(self, Self::Unknown(_))
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
    /// The plaintext requires a key the platform does not hold during the event.
    ///
    /// Defined by who *cannot* open the section rather than by which recipient can,
    /// so it covers both a writeup encrypted to the offline seal recipient and a
    /// `progress` blob encrypted to a player's holder key (design §4, §9). A
    /// stage-gated section is *not* sealed: it is served as ciphertext, and
    /// [`SectionFlags::PLAYER_VISIBLE`] excludes this bit.
    pub const SEALED: u16 = 1 << 0;
    /// Eligible to be served to players. An allowlist, never a blocklist.
    pub const PLAYER_VISIBLE: u16 = 1 << 1;
    /// Bytes live outside the file; `offset` and `len_stored` are 0 and the
    /// manifest carries the mirror list.
    pub const EXTERNAL: u16 = 1 << 2;
    /// A reader that does not know this section's `kind` MUST skip it rather than
    /// reject the file. The writer's promise is that skipping cannot cause a reader
    /// to serve, execute, or mis-locate anything — anything stronger than that is an
    /// incompatible feature, not an optional section.
    ///
    /// On a *known* kind the bit is legal and means nothing, which it must be: a
    /// kind that is unknown today becomes known tomorrow, and files written in
    /// between have to stay valid.
    pub const OPTIONAL: u16 = 1 << 3;

    const KNOWN: u16 = Self::SEALED | Self::PLAYER_VISIBLE | Self::EXTERNAL | Self::OPTIONAL;

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
    pub const fn optional(self) -> bool {
        self.contains(Self::OPTIONAL)
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
    /// Index into the manifest's name table, and the section's stable cryptographic
    /// identity: phase 2 binds it into the AEAD nonce and AAD (design §7). That is
    /// why it must be unique, and why a rewriter MUST NOT reassign it — reusing a
    /// `name_id` under an unchanged content key would repeat a nonce.
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

        // Flags before kind: whether an undefined kind is a reject or a skippable
        // section is decided by SectionFlags::OPTIONAL, so the flags have to be
        // validated first.
        let flags = SectionFlags(u16_at(b, OFF_FLAGS).ok_or_else(trunc)?);
        flags.validate()?;
        let kind = SectionKind::from_u16(u16_at(b, OFF_KIND).ok_or_else(trunc)?, flags)?;

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

        // R20. The manifest says which key opens everything else and where every
        // external payload lives, so it has to be readable with no key and no
        // codec — otherwise the file stops being self-describing, and a reader
        // would have to decompress untrusted input to learn the very limits that
        // make decompressing it safe.
        if kind == SectionKind::Manifest && (enc != Encryption::None || comp != Compression::None) {
            return Err(Error::Inconsistent {
                what: "manifest section must be neither encrypted nor compressed",
            });
        }

        // R21. `SEALED` means the plaintext requires a key the platform does not
        // hold during the event (§5.3). With `enc = 0` there is no key, so the flag
        // is a claim the container does not back — and a reader that trusts it hands
        // out the "sealed" writeup in cleartext. Making the pair unrepresentable is
        // the same move as `SEALED`/`PLAYER_VISIBLE` being mutually exclusive: the
        // invariant belongs in the container, where a caller cannot forget it.
        //
        // The consequence is deliberate. R6 forces `solver`, `writeup` and
        // `progress` to carry `SEALED`, and this version has no encryption, so a
        // phase 1 writer can no longer emit those kinds at all. Refusing is honest;
        // emitting a fake-sealed section is strictly worse.
        if flags.sealed() && enc == Encryption::None {
            return Err(Error::Inconsistent {
                what: "SEALED section must be encrypted",
            });
        }

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
            // R19. An index of fewer than two entries cannot be checked against
            // anything: one chaining value carries no root finalization, and zero
            // describe an empty section. `chunk_index_off = 0` is how a section
            // that fits in a single chunk says it has no index.
            if chunk::chunk_count(len_plain, chunk_size)? < 2 {
                return Err(Error::Inconsistent {
                    what: "chunk index on a section of fewer than two chunks",
                });
            }
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
        put(OFF_KIND, &self.kind.to_u16().to_le_bytes());
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

    /// Byte range of this section's chunk index, or `None` if it has none.
    ///
    /// The length is derived, never read from the file:
    /// `ceil(len_plain / chunk_size) × 32`. That is what lets the index be bounds-
    /// and overlap-checked like every other region — 0.2 had to exempt it,
    /// because its entry size was undefined and so its length was unknowable.
    ///
    /// An `EXTERNAL` section may still have one. Its payload lives elsewhere; the
    /// index that proves the payload does not.
    pub fn index_range(&self) -> Result<Option<(u64, u64)>> {
        if self.chunk_index_off == 0 {
            return Ok(None);
        }
        let len = chunk::index_len(self.len_plain, self.chunk_size)?;
        let end = self
            .chunk_index_off
            .checked_add(len)
            .ok_or(Error::LengthOverflow { at: "chunk index" })?;
        Ok(Some((self.chunk_index_off, end)))
    }
}

/// What owns a byte range, for overlap diagnostics.
///
/// An explicit owner rather than a sentinel `name_id`, so a real section numbered
/// 65535 stays distinguishable from the section table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Region {
    Table,
    Payload(u16),
    Index(u16),
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
pub fn validate_layout(records: &[SectionRecord], header: &Header, file: &[u8]) -> Result<()> {
    let file_len = file.len() as u64;
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

    // Every region that owns bytes: inline payloads, chunk indices, and the table
    // itself so nothing can be laid over it.
    let mut ranges: Vec<(u64, u64, Region)> = Vec::with_capacity(records.len() * 2 + 1);
    for r in records {
        if let Some((start, end)) = r.stored_range() {
            if end > header.footer_off {
                return Err(Error::ExceedsFile {
                    at: "section payload",
                    end,
                    file_len: header.footer_off,
                });
            }
            if end > start {
                ranges.push((start, end, Region::Payload(r.name_id)));
            }
        }
        if let Some((start, end)) = r.index_range()? {
            if end > header.footer_off {
                return Err(Error::ExceedsFile {
                    at: "chunk index",
                    end,
                    file_len: header.footer_off,
                });
            }
            ranges.push((start, end, Region::Index(r.name_id)));
        }
    }
    if table_end > table_start {
        ranges.push((table_start, table_end, Region::Table));
    }

    ranges.sort_unstable();
    for w in ranges.windows(2) {
        let (Some(a), Some(b)) = (w.first(), w.get(1)) else {
            continue;
        };
        if b.0 < a.1 {
            return Err(overlap_error(a.2, b.2));
        }
    }

    check_padding(file, header, &ranges)
}

/// T8: every byte in `[HEADER_LEN, footer_off)` that no region claims MUST be zero.
///
/// **Why a MUST and not the SHOULD this started as.** The commitment root spans the
/// header and the section table; each section's `root` spans its own plaintext.
/// Nothing spans the gaps. So a padding byte can be changed in place without moving
/// the root, without moving `total_len`, and therefore without invalidating the
/// signature transcript of §8.4 — one signature would verify two different files.
/// That is signature malleability and a covert channel, and no amount of phase 2
/// crypto fixes it, because the transcript is already correct and these bytes were
/// simply never in scope of anything.
///
/// The alternative was to extend the commitment root to cover the padding. Spec §15
/// states the root definition is unchangeable without a major version, and requiring
/// zero buys the same guarantee — one canonical byte string per bundle — without
/// touching it.
///
/// This is also the rule the format already applied twice elsewhere and skipped
/// here: F5 forbids footer slack, and §3 forbids bytes after the footer, both on the
/// grounds that bytes belonging to no structure and covered by no commitment are the
/// ambiguity behind a long line of archive-format vulnerabilities.
///
/// Cost, stated rather than discovered: this touches every unclaimed byte, so it is
/// linear in the padding rather than in the structure count. Legitimate padding is
/// bounded by alignment — at most 4095 bytes before each payload — so a real bundle
/// pays almost nothing. A hostile file declaring one small section and a `footer_off`
/// far away pays a scan proportional to a gap it had to supply the bytes for, over a
/// file the caller has already mapped.
///
/// `ranges` must be sorted and already known not to overlap, which is exactly the
/// state [`validate_layout`] leaves it in.
fn check_padding(file: &[u8], header: &Header, ranges: &[(u64, u64, Region)]) -> Result<()> {
    let mut cursor = u64::from(HEADER_LEN);
    for &(start, end, _) in ranges {
        if start > cursor {
            check_zero(file, cursor, start)?;
        }
        // `max` rather than plain assignment: a zero-length payload is not in
        // `ranges` at all, but nothing else guarantees the sort put a longer region
        // before a shorter one starting at the same offset.
        cursor = cursor.max(end);
    }
    if header.footer_off > cursor {
        check_zero(file, cursor, header.footer_off)?;
    }
    Ok(())
}

/// Every byte of `file[start..end]` must be zero, naming the offset of the first
/// that is not.
fn check_zero(file: &[u8], start: u64, end: u64) -> Result<()> {
    let (Ok(s), Ok(e)) = (usize::try_from(start), usize::try_from(end)) else {
        return Err(Error::ExceedsFile {
            at: "padding",
            end,
            file_len: file.len() as u64,
        });
    };
    let bytes = file.get(s..e).ok_or(Error::ExceedsFile {
        at: "padding",
        end,
        file_len: file.len() as u64,
    })?;
    match bytes.iter().position(|&b| b != 0) {
        Some(i) => Err(Error::PaddingNotZero {
            at: start.saturating_add(i as u64),
        }),
        None => Ok(()),
    }
}

fn overlap_error(a: Region, b: Region) -> Error {
    match (a, b) {
        (Region::Table, Region::Payload(name_id) | Region::Index(name_id))
        | (Region::Payload(name_id) | Region::Index(name_id), Region::Table) => {
            Error::OverlapsSectionTable { name_id }
        }
        // The same section's payload and index colliding is a writer laying one
        // over the other, which reads as nonsense through the generic message.
        (Region::Payload(x), Region::Index(y)) | (Region::Index(x), Region::Payload(y))
            if x == y =>
        {
            Error::Inconsistent {
                what: "a section's chunk index overlaps its own payload",
            }
        }
        (Region::Payload(a) | Region::Index(a), Region::Payload(b) | Region::Index(b)) => {
            Error::OverlappingSections { a, b }
        }
        // Unreachable: the table is pushed once, so two table ranges cannot exist.
        // Reported rather than panicked on, per design §14.
        (Region::Table, Region::Table) => Error::Inconsistent {
            what: "section table listed twice in layout validation",
        },
    }
}
