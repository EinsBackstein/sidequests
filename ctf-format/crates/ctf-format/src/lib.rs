//! Reader and writer for the `.ctf` challenge transport format.
//!
//! `spec/SPEC.md` is normative for every byte and every rule below; this crate is
//! its reference implementation. `docs/FORMAT-DESIGN.md` carries the rationale and
//! `docs/ROADMAP.md` what is implemented. Currently: the whole container — header,
//! section table, canonical CBOR manifest, chunk indices, and the footer commitment
//! (phases 0 and 1).
//!
//! # Reading order
//!
//! [`Bundle::parse`] performs all of it. The stages are public individually because
//! a streaming reader may only have the first 64 bytes, and because the order is
//! normative — each stage depends on values the previous one validated:
//!
//! 1. [`Header::parse`] — self-consistency only.
//! 2. [`Header::check_file_len`] — cross-check against the real file length.
//! 3. [`section::parse_table`] — per-record well-formedness.
//! 4. [`section::validate_layout`] — whole-table invariants (overlap, uniqueness).
//! 5. [`footer::Footer::parse`] — `total_len`, no trailing bytes, no slack.
//! 6. [`footer::commitment_root`] — recomputed over the header and table bytes.
//! 7. [`manifest::Manifest::decode`] — after the manifest section's own root
//!    verifies, never before.
//!
//! # Intact is not authentic
//!
//! A bundle that survives all seven stages is **intact**: it commits to its own
//! bytes and nothing has been appended, moved, or flipped without detection. It is
//! not **authentic**. The signature slots exist and are parsed, but verifying them
//! needs the crypto suite registry, which is phase 2 — so [`Bundle::signing`]
//! reports whether signatures are present and there is deliberately no API here
//! that reports them as valid.
//!
//! Nothing downstream may serve, execute, or trust a bundle on the strength of a
//! successful parse alone.
//!
//! # Endianness
//!
//! Little-endian throughout, normatively. Every integer field is read and written
//! explicitly, so a big-endian host produces identical bytes.

pub mod bundle;
pub mod cbor;
pub mod chunk;
pub mod error;
pub mod footer;
pub mod header;
pub mod manifest;
pub mod section;

pub use bundle::{Bundle, Payload, SectionSpec, VerifyReport, write_bundle};
pub use error::{Error, Result};
pub use footer::{Footer, Signing};
pub use header::Header;
pub use manifest::Manifest;
pub use section::{Compression, Encryption, FutureKind, SectionFlags, SectionKind, SectionRecord};

/// File signature: PNG's construction with `CTF` as the tag. Every byte earns its
/// place — see design §6 for the per-byte rationale.
pub const MAGIC: [u8; 8] = [0x89, b'C', b'T', b'F', 0x0d, 0x0a, 0x1a, 0x0a];

/// Format version. Major 0 means the byte layout is not yet frozen; a reader MUST
/// reject any major it does not implement. Minors are always accepted: what a newer
/// minor may rely on is negotiated through the feature words below, not the number.
pub const VERSION_MAJOR: u16 = 0;
pub const VERSION_MINOR: u16 = 3;

/// The file carries the complete container: a footer with a commitment root, a
/// canonical CBOR manifest, and chunk indices whose length is derived rather than
/// unknown. Every 0.3 writer sets it.
///
/// # Why `ro_compat` and not `incompat`
///
/// Run the criticality test (spec §2.3) against a 0.2 reader meeting a 0.3 file,
/// clause by clause. It serves nothing new — no flag, kind, or record rule
/// changed. It trusts nothing, because 0.2 forbids treating a parse as authentic.
/// It reports nothing as verified, having no verification. And it does not
/// *mis-locate* the chunk index: 0.2 §5.5 forbids dereferencing
/// `chunk_index_off` at all, so the region is never read. It merely fails to
/// *account* for bytes it never touches, which is under-checking, not misreading.
///
/// A valid 0.3 file also satisfies every 0.2 rule, since R19, R20, T6 and T7 only
/// narrow. So a 0.2 reader gets a correct — if incomplete — answer, which is
/// exactly the guarantee 0.2 always offered: structure, and nothing more.
///
/// The hazard is entirely on the **rewriter** side, and it is severe: a 0.2 tool
/// re-emitting a 0.3 file drops the footer, the manifest, and every chunk index,
/// producing a bundle that no longer says what the author signed. That is the
/// definition of `feat_ro_compat` in spec §4.4, so that is where the bit lives.
///
/// Result: 0.3 files stay readable by 0.2 readers and unrewritable by them, which
/// is what forward compatibility is for. A 0.3 reader still recognizes a file that
/// does *not* set the bit as one with no container to read — see
/// [`Bundle::parse`] — so backward compatibility keeps its accurate diagnostic
/// without costing forward compatibility.
pub const FEAT_RO_COMPAT_CONTAINER_V1: u32 = 1 << 0;

/// Incompatible features this build implements. A file requesting any bit outside
/// this mask cannot be read at all — the reader would be guessing at bytes whose
/// meaning changed.
///
/// This is the one place a future capability is switched on. Adding a feature means
/// setting its bit here *and* implementing it; the two cannot drift apart, because
/// a file that sets the bit is rejected until the bit is listed.
pub const SUPPORTED_INCOMPAT: u32 = 0;

/// Read-only-compatible features this build implements. A file requesting a bit
/// outside this mask is still readable — nothing about the bytes a reader already
/// understands has changed — but it MUST NOT be rewritten, because a rewrite would
/// drop whatever the unknown feature added. See [`Header::may_rewrite`].
pub const SUPPORTED_RO_COMPAT: u32 = FEAT_RO_COMPAT_CONTAINER_V1;

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
