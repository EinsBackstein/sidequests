//! Compile-check for the `fuzz/` targets' bodies.
//!
//! `cargo-fuzz` needs a nightly toolchain and sanitizer instrumentation, and
//! `rust-toolchain.toml` pins stable on purpose (design §8), so `fuzz/` is not built
//! by `cargo test`. Without this, an API change would silently rot the fuzz targets
//! and nobody would notice until the next mirror run. Each function below is the
//! body of the target named after it, minus the `fuzz_target!` wrapper.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use ctf_format::{
    Bundle, EntitlementChain, Error, Header, Manifest, RecordType, SectionKind, cbor::Value,
    chunk::ChunkIndex, section,
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
    assert_eq!(b.manifest.encode().expect("re-encode"), bytes.as_ref());
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

/// The body of `fuzz/fuzz_targets/entitlement.rs`, returning whether the input was
/// accepted so the seed's reach can be asserted rather than assumed.
fn entitlement(data: &[u8]) -> bool {
    let Ok(chain) = EntitlementChain::from_bytes(data) else {
        return false;
    };
    // Canonicality: `from_bytes` accepted one spelling, so re-encoding must produce
    // exactly the bytes it came from. `encode` and its `to_bytes` alias are both
    // checked because callers use both names.
    assert_eq!(
        chain.to_bytes().expect("an accepted chain must re-encode"),
        data
    );
    assert_eq!(chain.encode().expect("encode is to_bytes"), data);
    // Parsing is a pure function of the input.
    assert_eq!(
        EntitlementChain::from_bytes(data).expect("an accepted chain must re-parse"),
        chain
    );

    // Accessors must not panic on any accepted chain, including out-of-range indexes.
    let _ = chain.validate();
    let _ = chain.len();
    let _ = chain.is_empty();
    let records = chain.records();
    let _ = EntitlementChain::new().records();
    for n in [
        0,
        records.len().saturating_sub(1),
        records.len(),
        records.len().saturating_add(1),
        usize::MAX,
    ] {
        let _ = chain.get(n);
        let _ = chain.record_id(n);
    }

    // `validate_against_root` is a second validation entry point; it must not panic
    // for a root that does or does not match the genesis binding.
    let _ = chain.validate_against_root(&[0u8; 32]);
    if let Some(genesis) = records.first() {
        let _ = chain.validate_against_root(&genesis.root.unwrap_or([0u8; 32]));
    }

    for record in records {
        let _ = record.check();
        let _ = record.record_id();
        let _ = record.record_type.name();
        let _ = RecordType::from_name(record.record_type.name());
        if let Some(timestamp) = record.timestamp {
            let _ = timestamp.to_value();
        }
    }
    true
}

/// Every committed corpus file, sorted for a deterministic run order.
///
/// The corpus is the seed set rather than a fixed list, so a crashing input that a
/// maintainer copies out of `fuzz/artifacts/<target>/` into
/// `fuzz/corpus/<target>/` becomes a regression test on the next run without any
/// code change. A new target directory is picked up for free.
fn corpus() -> Vec<(std::path::PathBuf, Vec<u8>)> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus");
    let mut seeds = Vec::new();
    let mut dirs: Vec<_> = std::fs::read_dir(&root)
        .expect("the committed fuzz corpus exists")
        .map(|entry| entry.expect("a readable corpus directory entry").path())
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    for dir in dirs {
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .expect("a readable target corpus directory")
            .map(|entry| entry.expect("a readable corpus file entry").path())
            .filter(|path| path.is_file())
            .collect();
        files.sort();
        for file in files {
            let bytes = std::fs::read(&file)
                .unwrap_or_else(|e| panic!("cannot read corpus seed {}: {e}", file.display()));
            seeds.push((file, bytes));
        }
    }
    assert!(
        seeds.len() >= 6,
        "the corpus should carry a seed for every target, found {}",
        seeds.len()
    );
    seeds
}

/// Runs each target over the seed corpus, so the mirror is exercised rather than
/// merely compiled.
#[test]
fn fuzz_targets_still_compile_and_run() {
    // The section-table seed exists to reach T8, the padding rule. Without it the
    // whole-table rules would be reachable only by mutation.
    let table_seed = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fuzz/corpus/section_table/padding.ctf"
    ))
    .expect("the section-table seed corpus is committed");
    // The entitlement seed is a real signed chain (grant -> transfer -> progress),
    // so the accepted-and-re-encoded branch is reached rather than only mutated into.
    let entitlement_seed = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fuzz/corpus/entitlement/chain.cbor"
    ))
    .expect("the entitlement seed corpus is committed");

    // Every committed seed, plus the empty and all-zero inputs that reach the
    // earliest rejection paths.
    let seeds = corpus();
    let mut inputs: Vec<&[u8]> = seeds.iter().map(|(_, bytes)| bytes.as_slice()).collect();
    inputs.push(&[]);
    inputs.push(&[0u8; 200]);
    for data in inputs {
        bundle(data);
        header(data);
        section_table(data);
        manifest(data);
        chunk_index(data);
        let _ = entitlement(data);
    }

    // The seed must actually reach the accepted-and-re-encoded path, or its coverage
    // can rot with nothing failing. The mirror reports acceptance, so this asserts
    // the round trip ran rather than assuming it did.
    assert!(
        entitlement(&entitlement_seed),
        "the entitlement seed must reach the accepted-and-re-encoded path"
    );

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
