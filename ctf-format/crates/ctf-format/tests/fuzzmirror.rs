//! Compile-check for the `fuzz/` targets' bodies.
//!
//! `cargo-fuzz` needs a nightly toolchain and sanitizer instrumentation, and
//! `rust-toolchain.toml` pins stable on purpose (design §8), so `fuzz/` is not built
//! by `cargo test`. Without this, an API change would silently rot the fuzz targets
//! and nobody would notice until the next nightly CI run. Each function below is the
//! body of the target named after it, minus the `fuzz_target!` wrapper.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use ctf_format::{
    Bundle, Error, Header, Manifest, SectionKind, cbor::Value, chunk::ChunkIndex, section,
};

fn bundle(data: &[u8]) {
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
        let _ = b.section_bytes(r);
        let _ = b.chunk_index(r);
    }
    let record = b
        .sections
        .iter()
        .find(|r| r.kind == SectionKind::Manifest)
        .expect("one manifest");
    let bytes = b
        .section_bytes(record)
        .expect("manifest was verified in parse");
    assert_eq!(b.manifest.encode().expect("re-encode"), bytes);
}

fn header(data: &[u8]) {
    let Ok(h) = Header::parse(data) else { return };
    assert_eq!(h.to_bytes(), data[..64]);
    assert_eq!(Header::parse(&h.to_bytes()), Ok(h));
    let _ = h.check_file_len(u64::MAX);
    let _ = h.check_file_len(0);
    let _ = h.table_range();
}

/// The body of `fuzz/fuzz_targets/section_table.rs`, returning the layout
/// validator's error so the seed's reach can be asserted rather than assumed.
fn section_table(data: &[u8]) -> Option<Error> {
    let (&count, body) = data.split_first()?;
    let Ok(records) = section::parse_table(body, u32::from(count)) else {
        return None;
    };
    for (i, r) in records.iter().enumerate() {
        let at = i * 128;
        assert_eq!(r.to_bytes(), body[at..at + 128]);
        let _ = r.index_range();
    }
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
    section::validate_layout(&records, &header, data).err()
}

fn manifest(data: &[u8]) {
    if let Ok(v) = Value::decode(data) {
        assert_eq!(v.encode().expect("a decoded value must re-encode"), data);
    }
    if let Ok(m) = Manifest::decode(data) {
        assert_eq!(m.encode().expect("re-encode"), data);
        let _ = m.names();
        let _ = m.name_of(u16::MAX);
        let _ = m.external(0);
    }
}

fn chunk_index(data: &[u8]) {
    let Some((&count, body)) = data.split_first() else {
        return;
    };
    let Ok(index) = ChunkIndex::parse(body, u64::from(count)) else {
        return;
    };
    // Parse requires exactly `count × 32` bytes, so the round trip is against the
    // whole input rather than a prefix.
    assert_eq!(index.to_bytes(), body);
    // Must not panic for any root or chunk size. Reducing the index to a root is the
    // only way to reach per-chunk verification at all — the ordering C6 requires,
    // held by the type rather than by a comment.
    for cs in [0u32, 1, 4096, u32::MAX] {
        if let Ok(verified) = index.clone().verify_root(&[0u8; 32], cs) {
            let _ = verified.verify_chunk(u64::MAX, body);
            let _ = verified.verify_chunk(0, body);
        }
    }
}

/// Runs each target over the seed corpus, so the mirror is exercised rather than
/// merely compiled.
#[test]
fn fuzz_targets_still_compile_and_run() {
    let file = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fuzz/corpus/bundle/demo.ctf"
    ))
    .expect("seed corpus is committed");
    // The section-table seed exists to reach T8, the padding rule. Without it the
    // whole-table rules would be reachable only by mutation.
    let table_seed = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fuzz/corpus/section_table/padding.ctf"
    ))
    .expect("the section-table seed corpus is committed");
    for data in [file.as_slice(), table_seed.as_slice(), &[], &[0u8; 200]] {
        bundle(data);
        header(data);
        section_table(data);
        manifest(data);
        chunk_index(data);
    }

    // The seed must actually reach the padding rule, or its coverage can rot with
    // nothing failing. Offset 200 holds the planted non-zero byte.
    assert!(
        matches!(
            section_table(&table_seed),
            Some(Error::PaddingNotZero { at: 200 })
        ),
        "the section-table seed must reach T8"
    );
}
