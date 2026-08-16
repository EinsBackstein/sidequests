//! Whole-file parse. The real entry point, so this is the target that matters.
//!
//! Oracle: no panic, and an accepted bundle's structures re-encode to exactly the
//! bytes they came from. Round-trip instability is a finding even when nothing
//! crashes — a file that parses one way and re-emits another has two spellings, and
//! the commitment root is over bytes.
#![no_main]

use ctf_format::{Bundle, SectionKind};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(b) = Bundle::parse(data) else { return };

    assert_eq!(b.header.to_bytes(), data[..64]);
    assert_eq!(
        b.footer.to_bytes().expect("a parsed footer must re-encode"),
        &data[b.header.footer_off as usize..]
    );

    let (start, _) = b.header.table_range().expect("table range");
    for (i, r) in b.sections.iter().enumerate() {
        let at = start as usize + i * 128;
        assert_eq!(r.to_bytes(), data[at..at + 128]);
        // Never panics, and never returns bytes it has not verified.
        let _ = b.section_bytes(r);
        let _ = b.chunk_index(r);
    }

    let record = b
        .sections
        .iter()
        .find(|r| r.kind == SectionKind::Manifest)
        .expect("a parsed bundle has exactly one manifest");
    let bytes = b.section_bytes(record).expect("manifest was verified in parse");
    assert_eq!(b.manifest.encode().expect("re-encode"), bytes);
});
