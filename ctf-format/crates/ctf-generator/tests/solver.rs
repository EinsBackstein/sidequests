//! The offline solver gate (ticket 28, spec §25) and seed injection (ticket 62,
//! spec §26).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ctf_generator::{
    GeneratorError, Limits, OfflineGate, SeedError, Solver, check_flag, offline_gate, parse_seed,
    seed_from_file,
};

fn wat(source: &str) -> Vec<u8> {
    wat::parse_str(source).unwrap()
}

/// A generator whose output block is `chal = "A"`, flag `"abc"`.
const GENERATOR: &str = r#"
(module
  (memory (export "memory") 1)
  (data (i32.const 1024) "\01\00\00\00\04\00\00\00chal\01\00\00\00A\03\00\00\00abc")
  (func (export "ctf_alloc") (param i32) (result i32) i32.const 2048)
  (func (export "ctf_generate") (param i32 i32) (result i32) i32.const 1024)
  (func (export "ctf_output_len") (result i32) i32.const 24)
)
"#;

/// A solver that always answers `"abc"`, ignoring its input.
const SOLVER_CORRECT: &str = r#"
(module
  (memory (export "memory") 1)
  (data (i32.const 1024) "\03\00\00\00abc")
  (func (export "ctf_alloc") (param i32) (result i32) i32.const 2048)
  (func (export "ctf_solve") (param i32 i32) (result i32) i32.const 1024)
  (func (export "ctf_output_len") (result i32) i32.const 7)
)
"#;

/// A solver that answers the wrong flag.
const SOLVER_WRONG: &str = r#"
(module
  (memory (export "memory") 1)
  (data (i32.const 1024) "\05\00\00\00wrong")
  (func (export "ctf_alloc") (param i32) (result i32) i32.const 2048)
  (func (export "ctf_solve") (param i32 i32) (result i32) i32.const 1024)
  (func (export "ctf_output_len") (result i32) i32.const 9)
)
"#;

/// A solver that imports a capability: refused before it runs.
const SOLVER_IMPORTS: &str = r#"
(module
  (import "env" "now" (func $now (result i64)))
  (memory (export "memory") 1)
  (func (export "ctf_alloc") (param i32) (result i32) i32.const 2048)
  (func (export "ctf_solve") (param i32 i32) (result i32) i32.const 1024)
  (func (export "ctf_output_len") (result i32) i32.const 0)
)
"#;

#[test]
fn a_correct_solver_passes_the_offline_gate() {
    let report = offline_gate(
        OfflineGate {
            generator: Some(&wat(GENERATOR)),
            solver: Some(&wat(SOLVER_CORRECT)),
            seed: b"reference-seed",
            expected_flag: "abc",
            runtime_declared: false,
            offline_declared: true,
        },
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(report.status.to_string(), "passed");
    assert_eq!(report.solver_flag.as_deref(), Some("abc"));
    assert!(report.generator_root.is_some());
}

#[test]
fn a_failing_solver_fails_the_gate_and_blocks_publication() {
    let report = offline_gate(
        OfflineGate {
            generator: Some(&wat(GENERATOR)),
            solver: Some(&wat(SOLVER_WRONG)),
            seed: b"reference-seed",
            expected_flag: "abc",
            runtime_declared: false,
            offline_declared: true,
        },
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(report.status.to_string(), "failed");
}

#[test]
fn a_runtime_bearing_bundle_is_unverified_never_passed() {
    let report = offline_gate(
        OfflineGate {
            generator: Some(&wat(GENERATOR)),
            solver: Some(&wat(SOLVER_CORRECT)),
            seed: b"reference-seed",
            expected_flag: "abc",
            runtime_declared: true,
            offline_declared: true,
        },
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(report.status.to_string(), "unverified");
    assert!(report.generator_root.is_none());
}

#[test]
fn a_bundle_with_no_generator_or_solver_is_unverified() {
    let report = offline_gate(
        OfflineGate {
            generator: None,
            solver: None,
            seed: b"seed",
            expected_flag: "abc",
            runtime_declared: false,
            offline_declared: true,
        },
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(report.status.to_string(), "unverified");
}

#[test]
fn a_solver_that_imports_a_capability_is_rejected() {
    let err = match Solver::new(&wat(SOLVER_IMPORTS)) {
        Ok(_) => panic!("a solver with an import must be rejected"),
        Err(e) => e,
    };
    assert_eq!(err, GeneratorError::ImportsNotAllowed);
}

#[test]
fn a_solver_runs_in_the_same_capability_free_sandbox() {
    // No imports, fuel-limited: an endless loop is stopped rather than hanging.
    let spins = r#"
    (module
      (memory (export "memory") 1)
      (func (export "ctf_alloc") (param i32) (result i32) i32.const 2048)
      (func (export "ctf_solve") (param i32 i32) (result i32)
        (loop $l br $l)
        i32.const 1024)
      (func (export "ctf_output_len") (result i32) i32.const 0)
    )
    "#;
    let limits = Limits {
        fuel: 10_000,
        ..Limits::default()
    };
    let err = Solver::new(&wat(spins))
        .unwrap()
        .run(b"", &limits)
        .unwrap_err();
    assert_eq!(err, GeneratorError::OutOfFuel);
}

#[test]
fn a_seed_round_trips_through_hex() {
    let hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let seed = parse_seed(hex).unwrap();
    assert_eq!(seed[0], 0);
    assert_eq!(seed[31], 0x1f);
    assert!(matches!(parse_seed("00ff"), Err(SeedError::BadValue(_))));
    assert!(matches!(
        parse_seed("ZZ0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
        Err(SeedError::BadValue(_))
    ));
}

#[test]
fn a_seed_file_accepts_raw_bytes_or_hex() {
    let dir = std::env::temp_dir().join(format!("ctf-seed-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let raw = dir.join("raw");
    std::fs::write(&raw, [0x11u8; 32]).unwrap();
    assert_eq!(seed_from_file(&raw).unwrap(), [0x11u8; 32]);

    let hex = dir.join("hex");
    std::fs::write(&hex, "1f".repeat(32)).unwrap();
    assert_eq!(seed_from_file(&hex).unwrap(), [0x1fu8; 32]);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_missing_seed_file_is_reported_not_guessed() {
    let missing = std::env::temp_dir().join("ctf-seed-does-not-exist");
    let _ = std::fs::remove_file(&missing);
    assert_eq!(seed_from_file(&missing), Err(SeedError::Missing));
}

#[test]
fn the_generator_flag_must_match_the_injected_flag() {
    assert!(check_flag("abc", "abc").is_ok());
    assert!(
        check_flag("abc", "").is_ok(),
        "no injected flag means no check"
    );
    assert!(check_flag("abc", "wrong").is_err());
}
