//! The chunked AEAD: STREAM, not naive per-chunk.
//!
//! Normative: `spec/SPEC.md` §20.2. Rationale: design §7. This is ticket 12.
//!
//! Naive per-chunk AEAD is reorderable and truncatable: each chunk is individually
//! authentic, and nothing binds its position. The STREAM construction
//! (Hoang–Reyhanitabar–Rogaway–Vizár) fixes both by putting the chunk position and
//! a final-chunk flag into the nonce and binding position and total length into the
//! AAD.
//!
//! ```text
//! section_id = name_id              # the stable section identity, never the
//!                                   # record's position in the table
//! nonce = nonce_prefix(section_id) ‖ u32_be(chunk_index) ‖ final_flag
//! aad   = "ctf/stream/v1" ‖ u16_le(section_id) ‖ u32_le(chunk_index)
//!         ‖ u64_le(len_plain) ‖ u16_le(suite_id)
//! ```
//!
//! `final_flag` on the last chunk is what makes truncation detectable. The AAD
//! binds position and total length, which is what makes reordering and splicing
//! detectable.
//!
//! # Framing: every chunk carries its stored length
//!
//! The stored body is the concatenation of `u32_le(ct_len) ‖ ct` per chunk, where
//! `ct_len` is that chunk's ciphertext length including its tag. The reader needs
//! those lengths to find chunk boundaries and derive each chunk's nonce and AAD,
//! and for `comp = 1` they cannot be derived: a zstd frame header records the
//! *decompressed* size, not the compressed one. The prefix is authenticated in
//! effect — a tampered length moves the slice and the tag then fails — so it needs
//! no separate commitment.
//!
//! A reader walks the prefixes from the start. The chunk whose `ct_len` reaches the
//! end of the body is the final one, and carries `final_flag = 1` in its nonce. This
//! is what lets a `comp = 1` body be read without knowing its compressed length:
//! `len_plain` in the AAD is the section record's field (the total *decompressed*
//! length), and the per-frame compressed lengths come from the body itself.
//!
//! # Two rules that make the nonce safe
//!
//! - **`section_id` is `name_id`** (spec §5.1, T2). It is unique per file and
//!   stable across a rewrite, and is committed by the section table. It is
//!   emphatically not the record's index, because record order is free and an
//!   index-derived nonce would change on every re-emit.
//! - **Every encryption draws a fresh random `content_key`** ([`fresh_content_key`]).
//!   With a per-encryption key, re-encrypting the same section under the same
//!   `name_id` is safe, because it is a different keystream. Re-encrypting under a
//!   *reused* key is forbidden, and no field exists that would make it safe.
//!
//! `nonce_prefix(section_id)` is `u16_le(section_id)` followed by zero bytes, so
//! the nonce is exactly [`Aead::nonce_len`] bytes for the suite. The prefix carries
//! the section identity; the chunk index and final flag make every nonce within one
//! section distinct.

use crate::crypto::random_bytes;
use crate::suite::{Aead, Role, SuiteError};
use crate::{MAX_CHUNK_SIZE, MIN_CHUNK_SIZE, u32_at};

/// Domain-separates the STREAM AAD from every other use of the content key.
pub const STREAM_LABEL: &[u8] = b"ctf/stream/v1";

/// Length of the per-chunk stored-length prefix (`u32_le`).
pub const CHUNK_LEN_LEN: usize = 4;

fn primitive(reason: &'static str) -> SuiteError {
    SuiteError::Primitive {
        role: Role::Aead,
        reason,
    }
}

fn validate_chunk_size(chunk_size: u32) -> Result<(), SuiteError> {
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) || !chunk_size.is_power_of_two() {
        return Err(primitive(
            "chunk_size is not a power of two within [4096, 67108864]",
        ));
    }
    Ok(())
}

/// The derived chunk count for a flat `comp = 0` section:
/// `ceil(len_plain / chunk_size)`.
pub fn chunk_count(len_plain: u64, chunk_size: u32) -> u64 {
    if len_plain == 0 {
        return 0;
    }
    len_plain.div_ceil(u64::from(chunk_size))
}

/// `nonce_prefix(section_id)`: the section identity, zero-padded to leave room for
/// the 5-byte `u32_be(chunk_index) ‖ final_flag` suffix.
pub fn nonce_prefix(section_id: u16, nonce_len: usize) -> Result<Vec<u8>, SuiteError> {
    let prefix_len = nonce_len.checked_sub(5).ok_or_else(|| {
        primitive("AEAD nonce is too short to hold the chunk index and final flag")
    })?;
    if prefix_len < 2 {
        return Err(primitive(
            "AEAD nonce is too short to hold the section identity",
        ));
    }
    let mut prefix = Vec::with_capacity(prefix_len);
    prefix.extend_from_slice(&section_id.to_le_bytes());
    prefix.resize(prefix_len, 0);
    Ok(prefix)
}

/// `nonce_prefix ‖ u32_be(chunk_index) ‖ final_flag`, exactly `nonce_len` bytes.
pub fn chunk_nonce(prefix: &[u8], chunk_index: u32, final_chunk: bool) -> Vec<u8> {
    let mut nonce = Vec::with_capacity(prefix.len() + 5);
    nonce.extend_from_slice(prefix);
    nonce.extend_from_slice(&chunk_index.to_be_bytes());
    nonce.push(u8::from(final_chunk));
    nonce
}

/// `"ctf/stream/v1" ‖ u16_le(section_id) ‖ u32_le(chunk_index) ‖ u64_le(len_plain)
/// ‖ u16_le(suite_id)`.
pub fn chunk_aad(section_id: u16, chunk_index: u32, len_plain: u64, suite_id: u16) -> Vec<u8> {
    let mut aad = Vec::with_capacity(STREAM_LABEL.len() + 16);
    aad.extend_from_slice(STREAM_LABEL);
    aad.extend_from_slice(&section_id.to_le_bytes());
    aad.extend_from_slice(&chunk_index.to_le_bytes());
    aad.extend_from_slice(&len_plain.to_le_bytes());
    aad.extend_from_slice(&suite_id.to_le_bytes());
    aad
}

/// A fresh random content key for one section encryption.
///
/// This is not a convenience: it is the rule that makes a re-encrypt under an
/// unchanged `name_id` safe (design §7, spec §20.2). Never reuse a content key.
pub fn fresh_content_key(aead: &dyn Aead) -> Result<Vec<u8>, SuiteError> {
    let mut key = vec![0u8; aead.key_len()];
    random_bytes(&mut key, Role::Aead)?;
    Ok(key)
}

/// Seal an explicit list of frames, one STREAM chunk each. The last frame carries
/// the final flag. `len_plain` is what the AAD binds — the total decompressed
/// length, which the reader knows from the section record.
pub fn seal_chunked_frames(
    aead: &dyn Aead,
    content_key: &[u8],
    section_id: u16,
    suite_id: u16,
    len_plain: u64,
    frames: &[&[u8]],
) -> Result<Vec<u8>, SuiteError> {
    if content_key.len() != aead.key_len() {
        return Err(SuiteError::InvalidLength {
            role: Role::Aead,
            expected: aead.key_len(),
            got: content_key.len(),
        });
    }
    let prefix = nonce_prefix(section_id, aead.nonce_len())?;
    let count = frames.len();

    let mut out = Vec::new();
    for (i, frame) in frames.iter().enumerate() {
        let index = u32::try_from(i).map_err(|_| primitive("section has too many chunks"))?;
        let final_chunk = i + 1 == count;
        let nonce = chunk_nonce(&prefix, index, final_chunk);
        let aad = chunk_aad(section_id, index, len_plain, suite_id);
        let sealed = aead.seal(content_key, &nonce, &aad, frame)?;
        let ct_len = u32::try_from(sealed.len())
            .map_err(|_| primitive("encrypted chunk is longer than u32::MAX"))?;
        out.extend_from_slice(&ct_len.to_le_bytes());
        out.extend_from_slice(&sealed);
    }
    Ok(out)
}

/// Seal a flat `comp = 0` section: the plaintext is split at `chunk_size`.
pub fn seal_chunked(
    aead: &dyn Aead,
    content_key: &[u8],
    section_id: u16,
    suite_id: u16,
    chunk_size: u32,
    plaintext: &[u8],
) -> Result<Vec<u8>, SuiteError> {
    validate_chunk_size(chunk_size)?;
    let len_plain = plaintext.len() as u64;
    let count = chunk_count(len_plain, chunk_size);

    let mut frames: Vec<&[u8]> = Vec::new();
    for i in 0..count {
        let start = i * u64::from(chunk_size);
        let end = (start + u64::from(chunk_size)).min(len_plain);
        let chunk = plaintext
            .get(start as usize..end as usize)
            .ok_or_else(|| primitive("plaintext chunk out of range"))?;
        frames.push(chunk);
    }
    seal_chunked_frames(aead, content_key, section_id, suite_id, len_plain, &frames)
}

/// Walk a stored body and return each chunk's authenticated AEAD plaintext.
///
/// Each returned frame is one chunk: for a `comp = 0` section it is a plaintext
/// chunk, and for `comp = 1` it is one zstd frame the caller decompresses. The
/// final chunk is the one whose length reaches the end of the body; a body whose
/// last chunk was not sealed as final fails its tag, which is how truncation is
/// caught.
pub fn open_chunked_frames(
    aead: &dyn Aead,
    content_key: &[u8],
    section_id: u16,
    suite_id: u16,
    len_plain: u64,
    ciphertext: &[u8],
) -> Result<Vec<Vec<u8>>, SuiteError> {
    if content_key.len() != aead.key_len() {
        return Err(SuiteError::InvalidLength {
            role: Role::Aead,
            expected: aead.key_len(),
            got: content_key.len(),
        });
    }
    let prefix = nonce_prefix(section_id, aead.nonce_len())?;

    let mut frames = Vec::new();
    let mut offset: usize = 0;
    let mut index: u32 = 0;
    while offset < ciphertext.len() {
        let ct_len = u32_at(ciphertext, offset)
            .ok_or_else(|| primitive("ciphertext ended before a chunk length prefix"))?
            as usize;
        if ct_len < aead.tag_len() {
            return Err(primitive("chunk is shorter than its authentication tag"));
        }
        let ct_start = offset + CHUNK_LEN_LEN;
        let ct_end = ct_start
            .checked_add(ct_len)
            .ok_or_else(|| primitive("ciphertext offset overflowed"))?;
        let chunk = ciphertext
            .get(ct_start..ct_end)
            .ok_or_else(|| primitive("ciphertext is shorter than its chunk length declares"))?;
        let final_chunk = ct_end == ciphertext.len();
        let nonce = chunk_nonce(&prefix, index, final_chunk);
        let aad = chunk_aad(section_id, index, len_plain, suite_id);
        let opened = aead.open(content_key, &nonce, &aad, chunk)?;
        frames.push(opened);
        offset = ct_end;
        index = index
            .checked_add(1)
            .ok_or_else(|| primitive("section has too many chunks"))?;
    }
    Ok(frames)
}

/// Decrypt a `comp = 0` body and return the plaintext.
///
/// Wraps [`open_chunked_frames`] and additionally checks the chunk count and that
/// each chunk's plaintext is exactly `min(chunk_size, len_plain − i × chunk_size)`.
pub fn open_chunked(
    aead: &dyn Aead,
    content_key: &[u8],
    section_id: u16,
    suite_id: u16,
    chunk_size: u32,
    len_plain: u64,
    ciphertext: &[u8],
) -> Result<Vec<u8>, SuiteError> {
    validate_chunk_size(chunk_size)?;
    let frames = open_chunked_frames(
        aead,
        content_key,
        section_id,
        suite_id,
        len_plain,
        ciphertext,
    )?;
    if frames.len() as u64 != chunk_count(len_plain, chunk_size) {
        return Err(primitive("body has the wrong number of chunks"));
    }

    let mut plaintext = Vec::new();
    for (i, frame) in frames.iter().enumerate() {
        let chunk_start = i as u64 * u64::from(chunk_size);
        let this_len = (len_plain - chunk_start).min(u64::from(chunk_size)) as usize;
        if frame.len() != this_len {
            return Err(primitive("AEAD returned the wrong plaintext length"));
        }
        plaintext.extend_from_slice(frame);
    }
    Ok(plaintext)
}
