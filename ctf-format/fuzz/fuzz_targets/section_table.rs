//! The section table: per-record rules R1-R21 and whole-table rules T1-T8.
//!
//! The record count is taken from the input rather than from a header, so the
//! fuzzer can drive the count and the bytes independently — which is the shape of
//! the bug where a count validated against one structure is used to index another.
//!
//! A synthetic [`Header`] points at the input's table bytes and a synthetic
//! `footer_off` runs to the end of the input, so `validate_layout` is reached and
//! the whole-table rules are exercised on hostile input instead of only on
//! hand-built fixtures. The header is not parsed from the input, which is what lets
//! the table rules be fuzzed without a valid file around them.
#![no_main]

use ctf_format::{Header, section};
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

    // `body` starts at offset 1 in `data`, and `data.len()` is this file's length.
    // `CONTAINER_V1` is set so T8 — the padding rule — applies and is fuzzed too.
    let header = Header {
        version_major: 0,
        version_minor: 3,
        suite_id: 1,
        flags: 0,
        section_table_count: u32::from(count),
        section_table_off: 1,
        footer_off: data.len() as u64,
        feat_incompat: 0,
        feat_ro_compat: 1,
    };
    let _ = section::validate_layout(&records, &header, data);
});
