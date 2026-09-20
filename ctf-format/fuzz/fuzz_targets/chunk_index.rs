//! Chunk index parsing and verification.
//!
//! The entry count is derived from the record in a real file, so here it is driven
//! from the input to reach the arithmetic directly.
#![no_main]

use ctf_format::chunk::ChunkIndex;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&count, body)) = data.split_first() else {
        return;
    };
    let Ok(index) = ChunkIndex::parse(body, u64::from(count)) else {
        return;
    };
    // Parse requires the buffer to be exactly `count × 32`, so the round trip is
    // against the whole input, not a prefix.
    assert_eq!(index.to_bytes(), body);
    // Must not panic for any root or chunk size. Reducing the index to a root is the
    // only way to reach per-chunk verification (C6), and the size then travels with
    // the verified index rather than being re-supplied per chunk.
    for cs in [0u32, 1, 4096, u32::MAX] {
        if let Ok(verified) = index.clone().verify_root(&[0u8; 32], cs) {
            let _ = verified.verify_chunk(u64::MAX, body);
            let _ = verified.verify_chunk(0, body);
        }
    }
});
