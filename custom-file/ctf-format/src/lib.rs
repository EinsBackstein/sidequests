//! Reader and writer for the `.ctf` challenge transport format.
//!
//! See `docs/FORMAT-DESIGN.md` for the design rationale and `docs/ROADMAP.md` for
//! what is implemented. Currently: the header and the section table (phase 0 and
//! the container half of phase 1).
//!
//! # Reading order
//!
//! A reader MUST work outside-in and MUST NOT act on anything it has not yet
//! authenticated:
//!
//! 1. [`Header::parse`] — self-consistency only.
//! 2. [`Header::check_file_len`] — cross-check against the real file length.
//! 3. [`section::parse_table`] — per-record well-formedness.
//! 4. [`section::validate_layout`] — whole-table invariants (overlap, uniqueness).
//! 5. *Not yet implemented:* verify the footer commitment root and both
//!    signatures. Until that step exists, nothing downstream may treat a parsed
//!    bundle as trusted.
//!
//! # Endianness
//!
//! Little-endian throughout, normatively. Every integer field is read and written
//! explicitly, so a big-endian host produces identical bytes.

pub mod error;
pub mod header;
pub mod section;

pub use error::{Error, Result};
pub use header::Header;
pub use section::{Compression, Encryption, SectionFlags, SectionKind, SectionRecord};

/// File signature: PNG's construction with `CTF` as the tag. Every byte earns its
/// place — see design §6 for the per-byte rationale.
pub const MAGIC: [u8; 8] = [0x89, b'C', b'T', b'F', 0x0d, 0x0a, 0x1a, 0x0a];

/// Format version. Major 0 means the byte layout is not yet frozen; a reader MUST
/// reject any major it does not implement.
pub const VERSION_MAJOR: u16 = 0;
pub const VERSION_MINOR: u16 = 1;

/// Header size in bytes. Fixed for this major version.
pub const HEADER_LEN: u32 = 64;

/// Section table record size in bytes. Fixed width is what lets a reader seek to
/// record *N* without parsing records `0..N`.
pub const SECTION_RECORD_LEN: usize = 128;

/// Inline section payloads start on a page boundary, so a section can be mmap'd
/// without a misaligned first page.
pub const PAYLOAD_ALIGN: u64 = 4096;

/// The section table itself is 8-byte aligned: the maximum alignment of any field
/// in a record, so the array stays castable if the `from_le_bytes` decode is ever
/// replaced by a zero-copy one.
pub const TABLE_ALIGN: u64 = 8;

/// Hard cap on section count, enforced *before* allocating. A real challenge has
/// tens of sections; this is four orders of magnitude of headroom and still only
/// 512 KiB of table.
pub const MAX_SECTIONS: u32 = 4096;

/// Chunk size bounds. Powers of two only, so chunk index arithmetic is a shift.
pub const MIN_CHUNK_SIZE: u32 = 4096;
pub const MAX_CHUNK_SIZE: u32 = 64 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Little-endian readers.
//
// These return `Option` rather than indexing directly. A length check at the top
// of each `parse` would make direct indexing correct today, but it puts the "is
// this in bounds" reasoning one step away from the read. Returning `Option` makes
// a panic on hostile input unrepresentable instead of merely absent, which is what
// design §14 actually asks for. The cost is nil — these all inline away.
// ---------------------------------------------------------------------------

#[inline]
pub(crate) fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(off..off + 2)?.try_into().ok()?))
}

#[inline]
pub(crate) fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

#[inline]
pub(crate) fn u64_at(b: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(off..off + 8)?.try_into().ok()?))
}

/// True when every byte in `b[range]` is zero. Used for reserved fields.
#[inline]
pub(crate) fn all_zero(b: &[u8], off: usize, len: usize) -> Option<bool> {
    Some(b.get(off..off + len)?.iter().all(|&x| x == 0))
}
