//! The conformance runner's own tests.
//!
//! The runner is the thing under test, so these assert five things: every
//! committed vector passes, the corpus is reproducible from the builder, the
//! committed index is reproducible from the same catalog, every §14 hardening
//! bullet is either covered or explicitly recorded as not file-shaped, and a
//! deliberately wrong expectation is reported as a failure that names the vector.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::collections::BTreeSet;
use std::path::Path;

use ctf_conformance::{
    Expectation, Vector, VectorKind, build_minimal_golden, catalog, corpus_json, emit,
    fixtures_root, hardening_coverage, run, run_vectors,
};

#[test]
fn every_committed_vector_passes() {
    let report = run();
    for outcome in &report.outcomes {
        assert!(
            outcome.passed,
            "vector {} ({:?}) failed: {}",
            outcome.name, outcome.kind, outcome.detail
        );
    }
    assert!(!report.outcomes.is_empty(), "the vector set is empty");
    for kind in [VectorKind::Golden, VectorKind::Hostile, VectorKind::Future] {
        assert!(
            report.outcomes.iter().any(|o| o.kind == kind),
            "the vector set has no {kind:?} vector"
        );
    }
}

#[test]
fn a_deliberately_wrong_expectation_names_the_vector_and_the_observation() {
    let bytes = build_minimal_golden().expect("the minimal bundle must build");
    let report = run_vectors(vec![Vector {
        name: "negative-control",
        bytes,
        expect: Expectation::Error("BadMagic"),
    }]);
    let outcome = &report.outcomes[0];
    assert_eq!(outcome.name, "negative-control");
    assert!(!outcome.passed, "a wrong expectation must be a failure");
    assert!(
        outcome.detail.contains("BadMagic"),
        "the failure must name the expected result: {}",
        outcome.detail
    );
    assert!(
        outcome.detail.contains("succeeded"),
        "the failure must name the observed result: {}",
        outcome.detail
    );
    assert!(!report.passed());
}

#[test]
fn the_committed_minimal_fixture_is_reproducible_via_the_public_api() {
    let built = build_minimal_golden().expect("the minimal bundle must build");
    let path = fixtures_root().join("golden/minimal.ctf");
    let committed =
        std::fs::read(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    assert_eq!(
        built, committed,
        "golden/minimal.ctf must be exactly what the public API builds"
    );
}

/// The corpus is a committed artifact, not an opaque binary blob: every byte must
/// be what the builder produces, and `corpus.json` must be what the same catalog
/// renders. Regenerate with `cargo run -p ctf-conformance -- --emit
/// spec/vectors/conformance`.
#[test]
fn every_committed_fixture_and_the_index_are_reproducible() {
    let cases = catalog().expect("the catalog must build from the goldens");
    for case in &cases {
        assert!(
            case.file.starts_with("golden/")
                || case.file.starts_with("hostile/")
                || case.file.starts_with("future/"),
            "fixture {} is not in a corpus subdirectory: {}",
            case.name,
            case.file
        );
        let path = fixtures_root().join(case.file);
        let committed = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("cannot read committed fixture {}: {e}", path.display()));
        assert_eq!(
            committed, case.bytes,
            "{} must be exactly what the builder produces; run --emit",
            case.file
        );
    }

    let generated = corpus_json(&cases).expect("corpus.json must render");
    let path = fixtures_root().join("corpus.json");
    let committed = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    assert_eq!(
        committed, generated,
        "corpus.json must be exactly what the catalog renders; run --emit"
    );
}

/// The maintenance mode itself is exercised, not just the in-memory builder.
#[test]
fn emit_regenerates_the_same_bytes_in_another_directory() {
    let dir = std::env::temp_dir().join(format!("ctf-conformance-emit-{}", std::process::id()));
    if dir.exists() {
        std::fs::remove_dir_all(&dir).expect("cannot clear the temporary emit directory");
    }
    let written = emit(&dir).expect("--emit must succeed");
    let cases = catalog().expect("the catalog must build");

    let derived = cases
        .iter()
        .filter(|c| c.kind != VectorKind::Golden)
        .count();
    assert_eq!(written, derived, "emit must write every derived fixture");

    for case in cases.iter().filter(|c| c.kind != VectorKind::Golden) {
        let path = dir.join(case.file);
        let emitted = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("cannot read emitted {}: {e}", path.display()));
        assert_eq!(
            emitted, case.bytes,
            "emitted {} differs from the catalog",
            case.file
        );
    }
    let emitted_index = std::fs::read_to_string(dir.join("corpus.json")).expect("emitted index");
    assert_eq!(
        emitted_index,
        corpus_json(&cases).expect("corpus.json must render")
    );

    std::fs::remove_dir_all(&dir).expect("cannot remove the temporary emit directory");
}

/// Deliverable A's coverage check: every bullet in the audit's §14 table is either
/// named by at least one fixture's `hardening` list, or explicitly recorded as not
/// file-shaped in the committed index.
#[test]
fn every_hardening_bullet_is_covered_or_marked_not_file_shaped() {
    let audit_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/HARDENING-AUDIT.md");
    let audit = std::fs::read_to_string(&audit_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", audit_path.display()));
    let bullets: BTreeSet<u32> = audit
        .lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("| ")?;
            let cell = rest.split('|').next()?.trim();
            let n: u32 = cell.parse().ok()?;
            (1..=ctf_conformance::HARDENING_BULLETS)
                .contains(&n)
                .then_some(n)
        })
        .collect();
    assert_eq!(
        bullets.len(),
        ctf_conformance::HARDENING_BULLETS as usize,
        "expected the 11-row §14 table in HARDENING-AUDIT.md, found {bullets:?}"
    );

    let index_path = fixtures_root().join("corpus.json");
    let index_text = std::fs::read_to_string(&index_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", index_path.display()));
    let index: serde_json::Value =
        serde_json::from_str(&index_text).expect("corpus.json must be valid JSON");

    let mut covered = BTreeSet::new();
    for vector in index["vectors"]
        .as_array()
        .expect("vectors must be an array")
    {
        for bullet in vector["hardening"]
            .as_array()
            .expect("hardening must be an array")
        {
            covered.insert(
                u32::try_from(bullet.as_u64().expect("hardening entries are integers"))
                    .expect("hardening entries fit u32"),
            );
        }
    }
    let mut not_file_shaped = BTreeSet::new();
    for entry in index["not_file_shaped"]
        .as_array()
        .expect("not_file_shaped must be an array")
    {
        not_file_shaped.insert(
            u32::try_from(
                entry["hardening"]
                    .as_u64()
                    .expect("not_file_shaped entries carry a bullet number"),
            )
            .expect("bullet numbers fit u32"),
        );
    }

    for bullet in &bullets {
        assert!(
            covered.contains(bullet) || not_file_shaped.contains(bullet),
            "§14 bullet {bullet} is neither covered by a fixture nor recorded as not file-shaped"
        );
    }
    for bullet in &not_file_shaped {
        assert!(
            bullets.contains(bullet),
            "the index records §14 bullet {bullet} as not file-shaped, but the audit has no such row"
        );
    }
    for bullet in &covered {
        assert!(
            bullets.contains(bullet),
            "a fixture claims §14 bullet {bullet}, but the audit has no such row"
        );
    }

    // The committed index and the in-code catalog must agree on coverage.
    let (catalog_covered, catalog_not_file_shaped) =
        hardening_coverage(&catalog().expect("the catalog must build"));
    assert_eq!(covered, catalog_covered);
    assert_eq!(not_file_shaped, catalog_not_file_shaped);
}

/// `ParsesReadOnly` is not a synonym for "parse succeeded": it must fail on a file
/// that carries no unimplemented `ro_compat` bit.
#[test]
fn a_read_only_expectation_requires_an_unknown_bit() {
    let bytes = build_minimal_golden().expect("the minimal bundle must build");
    let report = run_vectors(vec![Vector {
        name: "read-only-negative",
        bytes,
        expect: Expectation::ParsesReadOnly,
    }]);
    let outcome = &report.outcomes[0];
    assert!(!outcome.passed);
    assert!(
        outcome.detail.contains("ro_compat"),
        "the failure must name the API result it checked: {}",
        outcome.detail
    );
}

/// `ParsesUnknownOptional` is not a synonym for "parse succeeded" either: it must
/// fail when the named section is a kind this build does implement.
#[test]
fn an_unknown_optional_expectation_checks_the_serving_apis() {
    let bytes = build_minimal_golden().expect("the minimal bundle must build");
    let report = run_vectors(vec![Vector {
        name: "unknown-optional-negative",
        bytes,
        expect: Expectation::ParsesUnknownOptional { name_id: 0 },
    }]);
    let outcome = &report.outcomes[0];
    assert!(!outcome.passed);
    assert!(
        outcome.detail.contains("unknown kind"),
        "the failure must name the API result it checked: {}",
        outcome.detail
    );
}
