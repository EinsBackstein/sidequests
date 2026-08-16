//! The 64-byte header, reached directly so inputs that a whole-file parse would
//! reject earlier still exercise H1-H14.
#![no_main]

use ctf_format::Header;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(h) = Header::parse(data) else { return };
    assert_eq!(h.to_bytes(), data[..64]);
    assert_eq!(Header::parse(&h.to_bytes()), Ok(h));
    // Must not panic whatever the file length claims to be.
    let _ = h.check_file_len(u64::MAX);
    let _ = h.check_file_len(0);
    let _ = h.table_range();
});
