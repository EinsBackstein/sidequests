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
    assert_eq!(index.to_bytes(), body[..index.entries().len() * 32]);
    // Must not panic for any root, chunk size, or index.
    let _ = index.verify_root(&[0u8; 32]);
    let _ = index.verify_chunk(u64::MAX, body, 4096);
    for cs in [0u32, 1, 4096, u32::MAX] {
        let _ = index.verify_chunk(0, body, cs);
    }
});
