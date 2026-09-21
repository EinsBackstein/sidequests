//! The conformance runner's own tests.
//!
//! The runner is the thing under test, so these assert three things: every
//! committed vector passes, the set actually covers both golden and hostile
//! inputs, and a deliberately wrong expectation is reported as a failure that
//! names the vector it came from.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use ctf_conformance::{
    Expectation, Vector, VectorKind, build_minimal_golden, fixtures_root, run, run_vectors,
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
    assert!(
        report.outcomes.iter().any(|o| o.kind == VectorKind::Golden),
        "the vector set has no golden vector"
    );
    assert!(
        report
            .outcomes
            .iter()
            .any(|o| o.kind == VectorKind::Hostile),
        "the vector set has no hostile vector"
    );
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
