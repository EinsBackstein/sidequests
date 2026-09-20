//! zstd compression for `comp = 1` sections.
//!
//! Normative: `spec/SPEC.md` §5.4. The rules this module enforces:
//!
//! - **Compress, then encrypt.** `root` is over the plaintext, so compression is
//!   invisible to the commitment; `len_plain` is the pre-compression length and
//!   `len_stored` the post-compression one.
//! - **Frames align to chunk boundaries.** A chunked section is stored as one zstd
//!   frame per chunk, so a single chunk decodes without its predecessors — the same
//!   property that keeps a large section seekable.
//! - **Two caps, checked before decompression.** A reader MUST reject a section
//!   whose declared plaintext exceeds [`MAX_DECOMPRESSED_SECTION`], or which claims
//!   more than [`MAX_DECOMPRESSION_RATIO`] times its stored size, *before* running
//!   the decoder. A decompression bomb is refused rather than expanded.
//! - **The manifest is never compressed** (R20), enforced in [`crate::section`].
//!
//! Why the caps are checked against *declared* lengths rather than measured output:
//! `len_plain` is committed twice over — it lives in the section table, which the
//! commitment root covers, and `root` is BLAKE3 of exactly that many plaintext
//! bytes. So the declaration is authenticated, and it is safe to refuse a bundle
//! that declares an output it is not allowed to produce, without decoding a byte.

use std::io::Read;

use crate::{Error, Result};

/// Absolute cap on the plaintext a single compressed section may declare.
///
/// 64 GiB. This is above the design's largest archetype (a ~40 GB forensics image),
/// so no real challenge is refused, while a bomb cannot name an unbounded output.
/// An external payload larger than this is fetched and verified out of band (§9.4)
/// rather than decompressed by this reader, which is the intended route for
/// anything that big anyway.
pub const MAX_DECOMPRESSED_SECTION: u64 = 1 << 36;

/// Cap on `len_plain / len_stored` for a compressed section.
///
/// 65536:1. Real zstd ratios on challenge content sit in the single or low double
/// digits; a ratio this high is either a synthetic bomb or a stream of a single
/// repeated byte. A legitimate sparse image that wants to exceed it should ship
/// externally, where verification streams the payload instead of expanding it.
pub const MAX_DECOMPRESSION_RATIO: u64 = 1 << 16;

/// zstd level used by the writer. A middle default: good ratio, negligible cost
/// against the hashing and I/O around it.
const LEVEL: i32 = 3;

/// Refuse a declared plaintext length before any decompression runs.
///
/// `stored` is the section's `len_stored`. The two checks are independent on
/// purpose: the absolute cap bounds a section whose stored size is itself large,
/// and the ratio cap bounds a small stored size that claims a huge output.
pub fn check_caps(len_plain: u64, stored: u64) -> Result<()> {
    if len_plain > MAX_DECOMPRESSED_SECTION {
        return Err(Error::CompressionOutputTooLarge {
            got: len_plain,
            max: MAX_DECOMPRESSED_SECTION,
        });
    }
    // `stored == 0` with `len_plain > 0` is an infinite ratio and is rejected by
    // this branch; `len_plain == 0` is legal and produces nothing.
    if len_plain > stored.saturating_mul(MAX_DECOMPRESSION_RATIO) {
        return Err(Error::CompressionRatioExceeded {
            plain: len_plain,
            stored,
            max: MAX_DECOMPRESSION_RATIO,
        });
    }
    Ok(())
}

/// Compress a section's plaintext, framing per chunk when it is chunked.
///
/// `chunk_size = 0` emits a single frame. Otherwise each `chunk_size`-byte slice
/// of the plaintext becomes its own frame, so a reader can decode chunk *N*
/// without having retained chunk *N-1*'s output.
pub fn compress(plain: &[u8], chunk_size: u32) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for frame in compress_frames(plain, chunk_size)? {
        out.extend_from_slice(&frame);
    }
    Ok(out)
}

/// Compress a section's plaintext into one frame per chunk, as separate buffers.
///
/// This is the same framing [`compress`] emits, kept un-concatenated so the
/// encrypted path (`enc = 1` with `comp = 1`, spec §20.2) can seal each frame as
/// its own STREAM chunk. `chunk_size = 0` yields a single frame; otherwise frame
/// *i* covers `[i × chunk_size, min((i+1) × chunk_size, len(plain)))`.
pub fn compress_frames(plain: &[u8], chunk_size: u32) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    if chunk_size == 0 {
        let frame = zstd::bulk::compress(plain, LEVEL).map_err(|_| Error::DecompressionFailed)?;
        out.push(frame);
    } else {
        let chunk_size = chunk_size as usize;
        for chunk in plain.chunks(chunk_size) {
            let frame =
                zstd::bulk::compress(chunk, LEVEL).map_err(|_| Error::DecompressionFailed)?;
            out.push(frame);
        }
    }
    Ok(out)
}

/// Decompress a section's stored bytes, enforcing both caps first.
///
/// The output is bounded by `len_plain` — the decoder is given `len_plain + 1`
/// bytes of allowance, so a stream that expands past its declaration is truncated
/// and then rejected by the length check rather than allowed to allocate freely.
/// That is what makes the caps meaningful against a hostile frame whose header
/// claims a modest output but whose blocks produce more.
pub fn decompress(stored: &[u8], len_plain: u64) -> Result<Vec<u8>> {
    check_caps(len_plain, stored.len() as u64)?;

    // Deliberately not `with_capacity(len_plain)`: `len_plain` is capped at 64 GiB,
    // which is far too large to reserve up front for a small input. Grow as the
    // real output arrives, bounded by the `take` limit.
    let mut out = Vec::new();
    let decoder =
        zstd::stream::read::Decoder::new(stored).map_err(|_| Error::DecompressionFailed)?;
    // `take` counts the *decompressed* bytes on the reader side.
    let limit = len_plain.saturating_add(1);
    decoder
        .take(limit)
        .read_to_end(&mut out)
        .map_err(|_| Error::DecompressionFailed)?;

    if out.len() as u64 != len_plain {
        return Err(Error::DecompressedLength {
            got: out.len() as u64,
            want: len_plain,
        });
    }
    Ok(out)
}
