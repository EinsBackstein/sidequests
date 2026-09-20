//! Chunk indices: verified streaming without a second commitment.
//!
//! Normative: `spec/SPEC.md` §9, rules C1–C8.
//!
//! # What a chunk index is
//!
//! A flat array of 32-byte BLAKE3 **chaining values**, one per chunk, in address
//! order. Entry *i* is the chaining value of the subtree covering
//! `[i × chunk_size, min((i+1) × chunk_size, len_plain))` of the section's
//! *plaintext*. Fixed width, so entry *i* is seekable, and the whole index is
//! `ceil(len_plain / chunk_size) × 32` bytes — which is what finally gives
//! `chunk_index_off` a known length and lets it be bounds- and overlap-checked
//! like every other region (spec 0.2 §5.5 had to exempt it).
//!
//! # Why chaining values, and not per-chunk hashes
//!
//! A section's `root` is `BLAKE3(plaintext)` and nothing else — spec §5.1 fixed
//! that, and it is what makes the commitment independent of how the bytes happen
//! to be stored. An index of independent per-chunk *hashes* would not reduce to
//! that root, so it would need its own commitment somewhere in the frozen layout,
//! which would mean a new record field and therefore a `feat_incompat` bit.
//!
//! Chaining values compose. Because `chunk_size` is a power of two of at least
//! 4 KiB, every chunk boundary is also a BLAKE3 subtree boundary, so merging the
//! entries back up the tree reproduces the section root exactly. The index is
//! therefore committed *by construction*: a forged index cannot reduce to the root
//! in the section table, and the section table is inside the footer commitment. No
//! new field, no second carrier of one fact, and nothing added to the root
//! definition — which design §6 marks as being as load-bearing as the byte layout.
//!
//! # Why not `bao`
//!
//! `bao` is the reference implementation of BLAKE3 verified streaming, by BLAKE3's
//! own author, and it is a better tool than this for random access into a stream.
//! Two things rule it out here. It is pre-1.0 with a single maintainer, and — the
//! decisive one — adopting it means adopting *its* encoding as a normative part of
//! `.ctf`, which design §13's independent Go implementation would then have to
//! reproduce from a second document with no Go implementation to lean on. A flat
//! array of chaining values is one page of specification and is derived from the
//! BLAKE3 paper's tree structure directly.
//!
//! The cost is stated rather than hidden: this index proves each chunk against the
//! root but carries no interior tree nodes, so verifying a *single* chunk requires
//! reading the whole index — kilobytes, against a payload measured in gigabytes.
//! Random access into a 40 GB payload without the full index is what `bao` would
//! buy, and it is not something ingest or serving needs.

use crate::{Error, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE, Result, footer::ROOT_LEN};
use blake3::hazmat::{HasherExt, Mode, merge_subtrees_non_root, merge_subtrees_root};

/// One index entry: a BLAKE3 chaining value.
pub type ChainingValue = [u8; ROOT_LEN];

/// Size of one index entry, in bytes.
pub const ENTRY_LEN: usize = ROOT_LEN;

/// Number of chunks a section of `len_plain` bytes has at `chunk_size`.
///
/// `Err` if `chunk_size` is zero — an unchunked section has no index, and the
/// caller has already been told so by R16.
pub fn chunk_count(len_plain: u64, chunk_size: u32) -> Result<u64> {
    if chunk_size == 0 {
        return Err(Error::Inconsistent {
            what: "chunk count requested for an unchunked section",
        });
    }
    let cs = u64::from(chunk_size);
    Ok(len_plain.div_ceil(cs))
}

/// Byte length of the chunk index for a section, in bytes.
pub fn index_len(len_plain: u64, chunk_size: u32) -> Result<u64> {
    chunk_count(len_plain, chunk_size)?
        .checked_mul(ENTRY_LEN as u64)
        .ok_or(Error::LengthOverflow { at: "chunk index" })
}

/// The chaining value of the chunk at `index`, given that chunk's plaintext.
///
/// `offset` must be `index × chunk_size`, and `data` must be that chunk's bytes:
/// exactly `chunk_size` of them for every chunk but the last, which may be short.
/// Both preconditions are checked, because BLAKE3's subtree API panics on a tree
/// shape that cannot occur — and a panic on hostile input is what design §14
/// forbids.
pub fn chunk_cv(data: &[u8], index: u64, chunk_size: u32) -> Result<ChainingValue> {
    // The range is load-bearing, not a tidiness check, and leaving it out was a
    // reachable panic. A power of two alone admits `chunk_size = 1`, which makes
    // `offset = index` and hands `set_input_offset` a value that is not a multiple
    // of BLAKE3's 1024-byte chunk — which asserts. `Bundle::parse` never gets here
    // with such a value because R14 range-checks the record first, but this function
    // is `pub` and reachable directly, and `fuzz/fuzz_targets/chunk_index.rs`
    // generates exactly that input.
    if !chunk_size.is_power_of_two() || !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) {
        return Err(Error::BadChunkSize { got: chunk_size });
    }
    if data.is_empty() {
        // An empty subtree has no chaining value. It also cannot arise from a
        // correct chunk count, so reaching here means the caller's chunking is
        // wrong, not that the input is unusual.
        return Err(Error::Inconsistent {
            what: "chunk has no bytes",
        });
    }
    if data.len() as u64 > u64::from(chunk_size) {
        return Err(Error::Inconsistent {
            what: "chunk longer than chunk_size",
        });
    }
    let offset = index
        .checked_mul(u64::from(chunk_size))
        .ok_or(Error::LengthOverflow { at: "chunk offset" })?;
    let mut h = blake3::Hasher::new();
    // Safe by the checks above: `offset` is a multiple of `chunk_size`, which is a
    // power of two of at least 4096, so it is also a multiple of BLAKE3's 1024-byte
    // chunk; and the largest subtree permitted at such an offset is at least
    // `chunk_size`, so `data` cannot overrun it.
    h.set_input_offset(offset);
    h.update(data);
    Ok(h.finalize_non_root())
}

/// Merge a full list of chunk chaining values into the section root.
///
/// This is BLAKE3's tree shape, not a Merkle tree of our own: at every level the
/// left subtree covers the largest power-of-two number of chunks strictly below the
/// total, and the right subtree covers the rest. Because each chunk is itself an
/// aligned power-of-two subtree, that reproduces `BLAKE3(plaintext)` exactly — the
/// property the whole design rests on, and the one the tests check against
/// `blake3::hash` directly rather than trusting this comment.
///
/// `None` for fewer than two entries: a single chaining value carries no root
/// finalization, so a one-entry index could not be checked against anything. C4
/// rejects such an index at parse time.
pub fn root_from_cvs(cvs: &[ChainingValue]) -> Option<[u8; ROOT_LEN]> {
    let (left, right) = split_canonical(cvs)?;
    Some(
        *merge_subtrees_root(&merge_non_root(left)?, &merge_non_root(right)?, Mode::Hash)
            .as_bytes(),
    )
}

/// Split at BLAKE3's left-subtree boundary: the largest power of two strictly less
/// than the entry count. `None` for fewer than two entries, which have no split.
fn split_canonical(cvs: &[ChainingValue]) -> Option<(&[ChainingValue], &[ChainingValue])> {
    let n = cvs.len();
    if n < 2 {
        return None;
    }
    // Largest power of two strictly less than `n`.
    let left = 1usize << (usize::BITS - 1 - (n - 1).leading_zeros());
    Some(cvs.split_at(left))
}

/// The chaining value of a subtree spanning `cvs`, without root finalization.
fn merge_non_root(cvs: &[ChainingValue]) -> Option<ChainingValue> {
    match split_canonical(cvs) {
        // Depth is `log2(len)`, so at most 64 frames even for an index describing
        // more bytes than any real storage holds.
        Some((left, right)) => Some(merge_subtrees_non_root(
            &merge_non_root(left)?,
            &merge_non_root(right)?,
            Mode::Hash,
        )),
        None => cvs.first().copied(),
    }
}

/// A parsed chunk index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkIndex {
    cvs: Vec<ChainingValue>,
}

impl ChunkIndex {
    /// Build the index for a section's whole plaintext.
    pub fn build(plaintext: &[u8], chunk_size: u32) -> Result<Self> {
        let count = chunk_count(plaintext.len() as u64, chunk_size)?;
        let cs = chunk_size as usize;
        let mut cvs = Vec::new();
        for i in 0..count {
            let start = usize::try_from(i)
                .ok()
                .and_then(|i| i.checked_mul(cs))
                .ok_or(Error::LengthOverflow { at: "chunk offset" })?;
            let end = start.saturating_add(cs).min(plaintext.len());
            let data = plaintext.get(start..end).ok_or(Error::Inconsistent {
                what: "chunk range",
            })?;
            cvs.push(chunk_cv(data, i, chunk_size)?);
        }
        Ok(Self { cvs })
    }

    /// Parse an index of `count` entries.
    ///
    /// `count` comes from `ceil(len_plain / chunk_size)`, never from the file, so
    /// there is no length field here for an attacker to inflate. The input must be
    /// **exactly** `count × 32` bytes: accepting a longer buffer and silently
    /// dropping the excess would break the byte-for-byte round trip this type
    /// documents, and a structure with two accepted spellings is what the
    /// commitment cannot tolerate.
    pub fn parse(b: &[u8], count: u64) -> Result<Self> {
        // C4. A zero-entry index describes an empty section and a one-entry index
        // cannot be reduced to a root, so neither can be checked against anything.
        // Both are writer errors; `chunk_index_off = 0` is how those sections say
        // they have no index.
        if count < 2 {
            return Err(Error::Inconsistent {
                what: "chunk index needs at least two entries",
            });
        }
        let need = usize::try_from(count)
            .ok()
            .and_then(|c| c.checked_mul(ENTRY_LEN))
            .ok_or(Error::LengthOverflow { at: "chunk index" })?;
        if b.len() < need {
            return Err(Error::Truncated { need, got: b.len() });
        }
        if b.len() > need {
            return Err(Error::TrailingBytes {
                at: need,
                len: b.len(),
            });
        }
        let mut cvs = Vec::with_capacity(
            // Bounded by the bytes actually present, so the capacity cannot be
            // sized past what the file holds.
            need / ENTRY_LEN,
        );
        for i in 0..need / ENTRY_LEN {
            let start = i * ENTRY_LEN;
            let cv: ChainingValue = b
                .get(start..start + ENTRY_LEN)
                .and_then(|s| s.try_into().ok())
                .ok_or(Error::Truncated { need, got: b.len() })?;
            cvs.push(cv);
        }
        Ok(Self { cvs })
    }

    /// Serialize. Round-trips [`ChunkIndex::parse`] byte-for-byte.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(self.cvs.len() * ENTRY_LEN);
        for cv in &self.cvs {
            b.extend_from_slice(cv);
        }
        b
    }

    /// The entries.
    pub fn entries(&self) -> &[ChainingValue] {
        &self.cvs
    }

    /// Check the index against the section root it claims to describe, and adopt the
    /// chunk size the section's record fixed.
    ///
    /// This is the step that makes the index trustworthy without a commitment of its
    /// own: the root lives in the section table, which the footer commits to, so an
    /// index that reduces to it is as authenticated as the table is.
    ///
    /// **Consumes the index, and that is C6 made unrepresentable rather than
    /// documented.** The only type that can check a chunk is the
    /// [`VerifiedChunkIndex`] this returns, so a chunk cannot be checked against an
    /// index that has not already been shown to reduce to the committed root. The
    /// order C6 requires is enforced by the type, not by a comment telling the caller
    /// which method to call first.
    ///
    /// It takes `chunk_size` here, from the section record, rather than letting
    /// [`VerifiedChunkIndex::verify_chunk`] accept one per call: the record already
    /// fixed it, and re-supplying it from memory is the same footgun as getting the
    /// ordering wrong.
    ///
    /// ```compile_fail
    /// use ctf_format::chunk::ChunkIndex;
    /// let index: ChunkIndex = todo!();
    /// // No such method: an index must be reduced to its root first, and the only
    /// // result that can check a chunk is a `VerifiedChunkIndex`.
    /// index.verify_chunk(0, &[]);
    /// ```
    pub fn verify_root(self, root: &[u8; ROOT_LEN], chunk_size: u32) -> Result<VerifiedChunkIndex> {
        // The size comes from the record, which R14 already range-checked in a real
        // file — but this function is `pub`, so the guard belongs here too. An
        // index of fewer than two entries likewise cannot be reduced (C4).
        if !chunk_size.is_power_of_two() || !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size)
        {
            return Err(Error::BadChunkSize { got: chunk_size });
        }
        let got = root_from_cvs(&self.cvs).ok_or(Error::Inconsistent {
            what: "chunk index needs at least two entries",
        })?;
        if got != *root {
            return Err(Error::RootMismatch { at: "chunk index" });
        }
        Ok(VerifiedChunkIndex {
            cvs: self.cvs,
            chunk_size,
        })
    }
}

/// A chunk index that has been reduced to its section's root.
///
/// **The only type that exposes per-chunk verification.** C6 requires C4 (reduce the
/// index to the root) to be checked before C5 (check a chunk against an entry), and
/// the way to make an ordering rule unbreakable is to make the reversed order
/// unwritable: a caller cannot check a chunk against a bare [`ChunkIndex`] because
/// no method for it exists. The same move as [`crate::SectionKind::Unknown`]
/// carrying a [`crate::FutureKind`] instead of a bare `u16`.
///
/// It also owns the `chunk_size` resolved from the section record, so a chunk can
/// only ever be checked at the size the record declared — a caller cannot re-supply,
/// from memory, a value the file already fixed.
///
/// **C7 is the other half, and it is an absence.** A reader MUST NOT expose a
/// chunk's bytes before that chunk passes C5. There is no method here that returns
/// chunk bytes at all — [`VerifiedChunkIndex::verify_chunk`] returns `Result<()>`,
/// and the caller supplies the bytes it is checking — so there is no non-verifying
/// accessor to reach for:
///
/// ```compile_fail
/// use ctf_format::chunk::VerifiedChunkIndex;
/// let index: VerifiedChunkIndex = todo!();
/// // No such method: chunks are checked, never handed back through the index.
/// let _bytes: &[u8] = index.chunk(0);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedChunkIndex {
    cvs: Vec<ChainingValue>,
    chunk_size: u32,
}

impl VerifiedChunkIndex {
    /// The entries, carried over from the index that verified.
    pub fn entries(&self) -> &[ChainingValue] {
        &self.cvs
    }

    /// The chunk size the section record fixed.
    pub fn chunk_size(&self) -> u32 {
        self.chunk_size
    }

    /// Check one chunk's plaintext against its entry.
    ///
    /// Chunks may be checked in any order and independently of each other, which is
    /// what lets a 40 GB payload be verified in a stream of bounded memory, and
    /// what lets a broken transfer resume rather than restart. The chunk size is the
    /// one the verified index carries, never an argument.
    pub fn verify_chunk(&self, index: u64, data: &[u8]) -> Result<()> {
        let want = usize::try_from(index)
            .ok()
            .and_then(|i| self.cvs.get(i))
            .ok_or(Error::Inconsistent {
                what: "chunk index out of range",
            })?;
        if chunk_cv(data, index, self.chunk_size)? != *want {
            return Err(Error::RootMismatch { at: "chunk" });
        }
        Ok(())
    }
}

/// Verify a whole plaintext against a section root, in bounded memory.
///
/// The streaming path for an external payload: `read` is called repeatedly with a
/// buffer and returns how many bytes it filled, zero at end of input, exactly like
/// `std::io::Read::read` — spelled as a closure so this crate stays free of an `io`
/// dependency and works the same for a file, a socket, or a mapped region.
///
/// Returns the number of bytes consumed. `expected_len` is checked as well as the
/// root: a payload that hashes correctly but is shorter than the section claims
/// would otherwise pass, because BLAKE3 over a prefix is a perfectly good hash of
/// that prefix.
pub fn verify_stream<F>(
    mut read: F,
    expected_root: &[u8; ROOT_LEN],
    expected_len: u64,
    buf: &mut [u8],
) -> Result<u64>
where
    F: FnMut(&mut [u8]) -> Result<usize>,
{
    if buf.is_empty() {
        return Err(Error::Inconsistent {
            what: "verify_stream needs a non-empty buffer",
        });
    }
    let mut h = blake3::Hasher::new();
    let mut total: u64 = 0;
    loop {
        let n = read(buf)?;
        if n == 0 {
            break;
        }
        let got = buf.get(..n).ok_or(Error::Inconsistent {
            what: "reader reported more bytes than the buffer holds",
        })?;
        total = total.checked_add(n as u64).ok_or(Error::LengthOverflow {
            at: "stream length",
        })?;
        if total > expected_len {
            return Err(Error::Inconsistent {
                what: "payload longer than len_plain",
            });
        }
        h.update(got);
    }
    if total != expected_len {
        return Err(Error::Inconsistent {
            what: "payload shorter than len_plain",
        });
    }
    if h.finalize().as_bytes() != expected_root {
        return Err(Error::RootMismatch { at: "payload" });
    }
    Ok(total)
}
