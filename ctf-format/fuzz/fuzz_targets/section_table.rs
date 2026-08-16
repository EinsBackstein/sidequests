//! The section table: per-record rules R1-R20 and whole-table rules T1-T7.
//!
//! The record count is taken from the input rather than from a header, so the
//! fuzzer can drive the count and the bytes independently — which is the shape of
//! the bug where a count validated against one structure is used to index another.
#![no_main]

use ctf_format::section;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&count, body)) = data.split_first() else {
        return;
    };
    let Ok(records) = section::parse_table(body, u32::from(count)) else {
        return;
    };
    for (i, r) in records.iter().enumerate() {
        let at = i * 128;
        assert_eq!(r.to_bytes(), body[at..at + 128]);
        let _ = r.index_range();
    }
});
