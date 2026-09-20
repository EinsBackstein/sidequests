//! AEAD-STREAM section encryption tests (ticket 12, spec §20.2, design §7).
//!
//! The point of STREAM over naive per-chunk AEAD is that reordering, truncation,
//! and splicing stop being silently accepted: each chunk is bound to its position
//! and to the total plaintext length, and the last chunk carries a final flag. The
//! body frames every chunk with a `u32_le` stored length, so a `comp = 1` body can
//! be read without knowing its compressed length.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use ctf_format::crypto::stream::{
    CHUNK_LEN_LEN, chunk_aad, chunk_count, chunk_nonce, fresh_content_key, nonce_prefix,
    open_chunked, open_chunked_frames, seal_chunked, seal_chunked_frames,
};
use ctf_format::suite::{Aead, suite};

const CHUNK: u32 = 4096;

fn aead(suite_id: u16) -> &'static dyn Aead {
    suite(suite_id).unwrap().aead().unwrap()
}

fn filler(n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ctf/stream/test-filler");
    hasher.finalize_xof().fill(&mut out);
    out
}

/// The stored size of one chunk: `u32_le` prefix, ciphertext, tag.
fn unit_len(a: &dyn Aead, plaintext_chunk: usize) -> usize {
    CHUNK_LEN_LEN + plaintext_chunk + a.tag_len()
}

fn round_trip(suite_id: u16, section_id: u16, len: usize) {
    let a = aead(suite_id);
    let key = fresh_content_key(a).unwrap();
    let plaintext = filler(len);
    let ct = seal_chunked(a, &key, section_id, suite_id, CHUNK, &plaintext).unwrap();
    let back = open_chunked(
        a,
        &key,
        section_id,
        suite_id,
        CHUNK,
        plaintext.len() as u64,
        &ct,
    )
    .unwrap();
    assert_eq!(back, plaintext);
}

#[test]
fn a_single_chunk_round_trips_on_both_suites() {
    round_trip(1, 7, 100);
    round_trip(2, 7, 100);
}

#[test]
fn a_multi_chunk_section_round_trips_on_both_suites() {
    round_trip(1, 3, 3 * CHUNK as usize + 17);
    round_trip(2, 3, 3 * CHUNK as usize + 17);
}

#[test]
fn the_body_is_framed_by_a_length_prefix_per_chunk() {
    let a = aead(1);
    let key = fresh_content_key(a).unwrap();
    let plaintext = filler(2 * CHUNK as usize);
    let ct = seal_chunked(a, &key, 1, 1, CHUNK, &plaintext).unwrap();
    // Two chunks: two prefixes, two tags.
    assert_eq!(
        ct.len(),
        plaintext.len() + 2 * (CHUNK_LEN_LEN + a.tag_len())
    );
}

/// Swapping two equal-length chunks keeps every byte a valid AEAD tag, but the
/// nonce and AAD bind the chunk index, so the swap is detected.
#[test]
fn a_reordered_chunk_is_rejected() {
    let a = aead(1);
    let key = fresh_content_key(a).unwrap();
    let plaintext = filler(2 * CHUNK as usize);
    let mut ct = seal_chunked(a, &key, 9, 1, CHUNK, &plaintext).unwrap();

    let unit = unit_len(a, CHUNK as usize);
    let (first, rest) = ct.split_at_mut(unit);
    let (second, _) = rest.split_at_mut(unit);
    first.swap_with_slice(second);

    let err = open_chunked(a, &key, 9, 1, CHUNK, plaintext.len() as u64, &ct).unwrap_err();
    assert!(matches!(err, ctf_format::SuiteError::Primitive { .. }));
}

/// Dropping the final chunk leaves the body short of what its record declares, and
/// the remaining last chunk was not sealed with the final flag.
#[test]
fn a_truncated_section_is_rejected() {
    let a = aead(1);
    let key = fresh_content_key(a).unwrap();
    let plaintext = filler(2 * CHUNK as usize);
    let ct = seal_chunked(a, &key, 9, 1, CHUNK, &plaintext).unwrap();

    let truncated = &ct[..ct.len() - unit_len(a, CHUNK as usize)];
    let err = open_chunked(a, &key, 9, 1, CHUNK, plaintext.len() as u64, truncated).unwrap_err();
    assert!(matches!(err, ctf_format::SuiteError::Primitive { .. }));
}

/// A body assembled from two sections of identical plaintext under the same key is
/// rejected: the AAD and nonce bind the section identity, so the second section's
/// chunks do not open as the first section's.
#[test]
fn a_spliced_section_is_rejected() {
    let a = aead(1);
    let key = fresh_content_key(a).unwrap();
    let plaintext = filler(2 * CHUNK as usize);
    let section_a = seal_chunked(a, &key, 1, 1, CHUNK, &plaintext).unwrap();
    let section_b = seal_chunked(a, &key, 2, 1, CHUNK, &plaintext).unwrap();

    let unit = unit_len(a, CHUNK as usize);
    let mut spliced = section_a[..unit].to_vec();
    spliced.extend_from_slice(&section_b[unit..]);

    let err = open_chunked(a, &key, 1, 1, CHUNK, plaintext.len() as u64, &spliced).unwrap_err();
    assert!(matches!(err, ctf_format::SuiteError::Primitive { .. }));
}

/// Extra bytes after the body are refused, not ignored.
#[test]
fn trailing_ciphertext_bytes_are_rejected() {
    let a = aead(1);
    let key = fresh_content_key(a).unwrap();
    let plaintext = filler(100);
    let mut ct = seal_chunked(a, &key, 4, 1, CHUNK, &plaintext).unwrap();
    ct.push(0);

    let err = open_chunked(a, &key, 4, 1, CHUNK, plaintext.len() as u64, &ct).unwrap_err();
    assert!(matches!(err, ctf_format::SuiteError::Primitive { .. }));
}

/// A tampered tag is refused and returns no plaintext.
#[test]
fn a_flipped_tag_is_rejected() {
    let a = aead(1);
    let key = fresh_content_key(a).unwrap();
    let plaintext = filler(100);
    let mut ct = seal_chunked(a, &key, 4, 1, CHUNK, &plaintext).unwrap();
    let last = ct.len() - 1;
    ct[last] ^= 0x80;

    assert!(open_chunked(a, &key, 4, 1, CHUNK, plaintext.len() as u64, &ct).is_err());
}

/// Every encryption draws a fresh random content key, which is what makes
/// re-encrypting the same section under the same `name_id` safe. Two encryptions of
/// the same bytes therefore differ.
#[test]
fn re_encrypting_under_the_same_identity_uses_a_fresh_content_key() {
    let a = aead(1);
    let plaintext = filler(500);
    let key_one = fresh_content_key(a).unwrap();
    let key_two = fresh_content_key(a).unwrap();
    assert_ne!(key_one, key_two);

    let ct_one = seal_chunked(a, &key_one, 5, 1, CHUNK, &plaintext).unwrap();
    let ct_two = seal_chunked(a, &key_two, 5, 1, CHUNK, &plaintext).unwrap();
    assert_ne!(ct_one, ct_two);
}

/// The nonce layout: `prefix ‖ u32_be(chunk_index) ‖ final_flag`, exactly `nonce_len`
/// bytes, distinct for every `(index, final)` pair.
#[test]
fn the_nonce_is_position_and_final_flag_bound() {
    for suite_id in [1u16, 2] {
        let a = aead(suite_id);
        let prefix = nonce_prefix(11, a.nonce_len()).unwrap();

        let n0 = chunk_nonce(&prefix, 0, false);
        let n1 = chunk_nonce(&prefix, 1, false);
        let n_last = chunk_nonce(&prefix, 0, true);

        assert_eq!(n0.len(), a.nonce_len());
        assert_ne!(n0, n1, "chunk index must select a distinct nonce");
        assert_ne!(n0, n_last, "final flag must select a distinct nonce");
        assert_eq!(&n0[..prefix.len()], prefix.as_slice());
    }
}

/// The chunk-count derivation, including the empty and exact-boundary edges.
#[test]
fn chunk_count_is_the_ceiling_of_plaintext_over_chunk_size() {
    assert_eq!(chunk_count(0, CHUNK), 0);
    assert_eq!(chunk_count(1, CHUNK), 1);
    assert_eq!(chunk_count(CHUNK as u64, CHUNK), 1);
    assert_eq!(chunk_count(CHUNK as u64 + 1, CHUNK), 2);
    assert_eq!(chunk_count(3 * CHUNK as u64, CHUNK), 3);
}

/// The AAD binds chunk position, total plaintext length, and suite id (design §7).
#[test]
fn the_aad_binds_position_length_and_suite() {
    let base = chunk_aad(1, 0, 100, 1);
    assert_ne!(base, chunk_aad(1, 1, 100, 1));
    assert_ne!(base, chunk_aad(1, 0, 101, 1));
    assert_ne!(base, chunk_aad(2, 0, 100, 1));
    assert_ne!(base, chunk_aad(1, 0, 100, 2));
}

/// `comp = 1` + `enc = 1`: each zstd frame is one STREAM chunk. The reader walks the
/// length prefixes, decrypts each frame, and decompresses it to exactly its chunk's
/// plaintext length — without the compressed length ever being stored.
#[test]
fn a_compressed_section_round_trips_frame_by_frame() {
    let a = aead(1);
    let key = fresh_content_key(a).unwrap();
    let plaintext = filler(3 * CHUNK as usize + 17);
    let len_plain = plaintext.len() as u64;

    let mut frames: Vec<Vec<u8>> = Vec::new();
    let mut start = 0;
    while start < plaintext.len() {
        let end = (start + CHUNK as usize).min(plaintext.len());
        frames.push(zstd::bulk::compress(&plaintext[start..end], 3).unwrap());
        start = end;
    }
    let frame_refs: Vec<&[u8]> = frames.iter().map(Vec::as_slice).collect();

    let ct = seal_chunked_frames(a, &key, 9, 1, len_plain, &frame_refs).unwrap();
    let opened = open_chunked_frames(a, &key, 9, 1, len_plain, &ct).unwrap();
    assert_eq!(opened.len(), frames.len());

    let mut back = Vec::new();
    for (i, frame) in opened.iter().enumerate() {
        let chunk_start = i * CHUNK as usize;
        let this_len = (plaintext.len() - chunk_start).min(CHUNK as usize);
        let decompressed = zstd::bulk::decompress(frame, this_len).unwrap();
        assert_eq!(decompressed.len(), this_len);
        back.extend_from_slice(&decompressed);
    }
    assert_eq!(back, plaintext);
}

/// The same truncation rule holds for a compressed body: the final frame is not
/// marked final, so the tag fails.
#[test]
fn a_truncated_compressed_body_is_rejected() {
    let a = aead(1);
    let key = fresh_content_key(a).unwrap();
    let plaintext = filler(2 * CHUNK as usize);
    let len_plain = plaintext.len() as u64;

    let frames: Vec<Vec<u8>> = plaintext
        .chunks(CHUNK as usize)
        .map(|c| zstd::bulk::compress(c, 3).unwrap())
        .collect();
    let frame_refs: Vec<&[u8]> = frames.iter().map(Vec::as_slice).collect();
    let ct = seal_chunked_frames(a, &key, 9, 1, len_plain, &frame_refs).unwrap();

    let truncated = &ct[..ct.len() - (CHUNK_LEN_LEN + frames[1].len() + a.tag_len())];
    assert!(open_chunked_frames(a, &key, 9, 1, len_plain, truncated).is_err());
}
