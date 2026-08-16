//! Chunk index tests.
//!
//! The first test is the one that matters. Everything in `chunk.rs` rests on the
//! claim that merging chunk-aligned chaining values reproduces `BLAKE3(plaintext)`
//! exactly — a claim about BLAKE3's tree structure, not about our code, and one
//! that BLAKE3's own `hazmat` documentation says to verify against `blake3::hash`
//! rather than reason about. So it is verified against `blake3::hash`, over every
//! shape that could go wrong: exact multiples, short final chunks, and counts on
//! both sides of a power of two.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use ctf_format::{
    Error,
    chunk::{ChunkIndex, chunk_count, index_len, root_from_cvs, verify_stream},
};

/// Deterministic filler with no short period.
///
/// The first version of this was `(i * 31) as u8`, which repeats every 256 bytes —
/// so every 4096-byte chunk was byte-identical to every other, and the chunk-swap
/// test below passed a swapped chunk because it genuinely was the same bytes. A
/// stream from the XOF has no period worth worrying about.
fn data(len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    blake3::Hasher::new()
        .update(b"ctf-format chunk test filler")
        .finalize_xof()
        .fill(&mut v);
    v
}

/// The claim the whole design rests on: a flat list of chunk chaining values merges
/// back to the plain BLAKE3 hash of the same bytes.
#[test]
fn index_reduces_to_the_blake3_hash() {
    const CS: u32 = 4096;
    let cs = CS as usize;
    // 2..=17 chunks covers both sides of 2, 4, 8 and 16, which is where the
    // left-subtree split changes shape. Each count is tried exact, one byte short,
    // and one byte long.
    for chunks in 2..=17usize {
        for delta in [0isize, -1, 1] {
            let len = (chunks * cs).saturating_add_signed(delta);
            if len <= (chunks - 1) * cs {
                continue;
            }
            let d = data(len);
            let index = ChunkIndex::build(&d, CS).unwrap();
            assert_eq!(
                index.entries().len() as u64,
                chunk_count(len as u64, CS).unwrap(),
                "entry count for {len} bytes"
            );
            assert_eq!(
                root_from_cvs(index.entries()).unwrap(),
                *blake3::hash(&d).as_bytes(),
                "merged root for {len} bytes at chunk size {CS}"
            );
        }
    }
}

/// The same claim at a different chunk size, so the result cannot be an accident of
/// 4096 happening to be four BLAKE3 chunks.
#[test]
fn index_reduces_to_the_blake3_hash_at_64k() {
    const CS: u32 = 65536;
    for chunks in [2usize, 3, 5, 8, 9] {
        let len = chunks * CS as usize - 7;
        let d = data(len);
        let index = ChunkIndex::build(&d, CS).unwrap();
        assert_eq!(
            root_from_cvs(index.entries()).unwrap(),
            *blake3::hash(&d).as_bytes()
        );
    }
}

#[test]
fn index_round_trips() {
    let d = data(4096 * 5 + 3);
    let index = ChunkIndex::build(&d, 4096).unwrap();
    let bytes = index.to_bytes();
    assert_eq!(bytes.len(), 6 * 32);
    assert_eq!(ChunkIndex::parse(&bytes, 6).unwrap(), index);
}

#[test]
fn index_verifies_each_chunk_independently() {
    let d = data(4096 * 4 + 100);
    let index = ChunkIndex::build(&d, 4096).unwrap();
    index
        .verify_root(blake3::hash(&d).as_bytes())
        .expect("index must reduce to the section root");
    for i in 0..5u64 {
        let start = i as usize * 4096;
        let end = (start + 4096).min(d.len());
        index.verify_chunk(i, &d[start..end], 4096).unwrap();
    }
}

/// A flipped byte inside one chunk is caught by that chunk's entry alone — the
/// property that lets a 40 GB payload be checked in bounded memory.
#[test]
fn index_rejects_a_flipped_chunk() {
    let d = data(4096 * 3);
    let index = ChunkIndex::build(&d, 4096).unwrap();
    let mut bad = d[4096..8192].to_vec();
    bad[0] ^= 1;
    assert!(matches!(
        index.verify_chunk(1, &bad, 4096),
        Err(Error::RootMismatch { at: "chunk" })
    ));
}

/// Two chunks swapped. Each is individually a genuine chunk of the payload, so a
/// scheme that hashed chunks without binding their position would accept both.
#[test]
fn index_rejects_swapped_chunks() {
    let d = data(4096 * 3);
    let index = ChunkIndex::build(&d, 4096).unwrap();
    assert!(index.verify_chunk(0, &d[4096..8192], 4096).is_err());
    assert!(index.verify_chunk(1, &d[0..4096], 4096).is_err());
}

/// Position binding, isolated from content: two byte-identical chunks still get
/// different entries, because a chaining value depends on where in the tree the
/// subtree sits. This is what a flat list of independent per-chunk hashes would not
/// give, and it is inherited from BLAKE3 rather than added on top.
#[test]
fn identical_chunks_get_different_chaining_values() {
    let mut d = vec![0xa5u8; 4096 * 3];
    d[8192..].fill(0x5a);
    let index = ChunkIndex::build(&d, 4096).unwrap();
    assert_eq!(&d[0..4096], &d[4096..8192]);
    assert_ne!(index.entries()[0], index.entries()[1]);
}

/// An index that does not reduce to the section root is rejected before any chunk
/// is checked against it. Without this the per-chunk checks would only prove the
/// payload matches whatever the attacker put in the index.
#[test]
fn index_rejects_a_forged_entry() {
    let d = data(4096 * 3);
    let mut index_bytes = ChunkIndex::build(&d, 4096).unwrap().to_bytes();
    index_bytes[0] ^= 1;
    let forged = ChunkIndex::parse(&index_bytes, 3).unwrap();
    assert!(matches!(
        forged.verify_root(blake3::hash(&d).as_bytes()),
        Err(Error::RootMismatch { at: "chunk index" })
    ));
}

/// C4: one entry carries no root finalization, so a one-entry index could not be
/// checked against anything. `chunk_index_off = 0` is how such a section says so.
#[test]
fn index_rejects_fewer_than_two_entries() {
    assert!(ChunkIndex::parse(&[0u8; 32], 1).is_err());
    assert!(ChunkIndex::parse(&[], 0).is_err());
    assert!(root_from_cvs(&[[0u8; 32]]).is_none());
}

#[test]
fn index_rejects_truncation() {
    let d = data(4096 * 3);
    let bytes = ChunkIndex::build(&d, 4096).unwrap().to_bytes();
    assert!(matches!(
        ChunkIndex::parse(&bytes[..bytes.len() - 1], 3),
        Err(Error::Truncated { .. })
    ));
}

#[test]
fn index_len_is_derived_not_read() {
    assert_eq!(index_len(4096 * 3, 4096).unwrap(), 3 * 32);
    assert_eq!(index_len(4096 * 3 + 1, 4096).unwrap(), 4 * 32);
    assert_eq!(index_len(0, 4096).unwrap(), 0);
    assert!(index_len(10, 0).is_err());
}

/// The streaming path an external payload takes. Bounded memory, whatever the size.
#[test]
fn stream_verifies_in_bounded_memory() {
    let d = data(100_000);
    let root = *blake3::hash(&d).as_bytes();
    let mut pos = 0usize;
    let mut buf = [0u8; 4096];
    let n = verify_stream(
        |b| {
            let n = b.len().min(d.len() - pos);
            b[..n].copy_from_slice(&d[pos..pos + n]);
            pos += n;
            Ok(n)
        },
        &root,
        d.len() as u64,
        &mut buf,
    )
    .unwrap();
    assert_eq!(n, d.len() as u64);
}

/// A truncated payload hashes to a perfectly good BLAKE3 root — of the prefix. Only
/// the length check catches it, which is why `verify_stream` takes one.
#[test]
fn stream_rejects_a_truncated_payload() {
    let d = data(100_000);
    let root = *blake3::hash(&d).as_bytes();
    let mut pos = 0usize;
    let mut buf = [0u8; 4096];
    let short = d.len() - 1;
    let r = verify_stream(
        |b| {
            let n = b.len().min(short - pos);
            b[..n].copy_from_slice(&d[pos..pos + n]);
            pos += n;
            Ok(n)
        },
        &root,
        d.len() as u64,
        &mut buf,
    );
    assert!(matches!(r, Err(Error::Inconsistent { .. })));
}

#[test]
fn stream_rejects_a_flipped_byte() {
    let mut d = data(100_000);
    let root = *blake3::hash(&d).as_bytes();
    d[50_000] ^= 1;
    let mut pos = 0usize;
    let mut buf = [0u8; 4096];
    let r = verify_stream(
        |b| {
            let n = b.len().min(d.len() - pos);
            b[..n].copy_from_slice(&d[pos..pos + n]);
            pos += n;
            Ok(n)
        },
        &root,
        d.len() as u64,
        &mut buf,
    );
    assert!(matches!(r, Err(Error::RootMismatch { at: "payload" })));
}
