//! The offline solver gate (ticket 28, spec §25) and seed injection (ticket 62,
//! spec §26).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ctf_generator::{
    DeterminismDeclaration, DeterminismMode, GateStage, GateStatus, GeneratorError, Limits,
    OfflineGate, SeedError, Solver, UnverifiedReason, check_flag, offline_gate, parse_seed,
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

/// A generator that emits an output the document does not declare: `chal` plus
/// `extra.bin` (rule G8).
const GENERATOR_EXTRA: &str = r#"
(module
  (memory (export "memory") 1)
  (data (i32.const 1024) "\02\00\00\00\04\00\00\00chal\01\00\00\00A\09\00\00\00extra.bin\01\00\00\00B\03\00\00\00abc")
  (func (export "ctf_alloc") (param i32) (result i32) i32.const 2048)
  (func (export "ctf_generate") (param i32 i32) (result i32) i32.const 1024)
  (func (export "ctf_output_len") (result i32) i32.const 42)
)
"#;

/// A generator whose output depends on its own call count, so it fails the
/// determinism gate (rule G9).
const STATEFUL: &str = r#"
(module
  (memory (export "memory") 1)
  (global $n (mut i32) (i32.const 0))
  (data (i32.const 1024) "\01\00\00\00\04\00\00\00chal\01\00\00\00A\03\00\00\00abc")
  (func (export "ctf_alloc") (param i32) (result i32) i32.const 2048)
  (func (export "ctf_generate") (param i32 i32) (result i32)
    i32.const 1040
    global.get $n
    i32.store8
    global.get $n
    i32.const 1
    i32.add
    global.set $n
    i32.const 1024)
  (func (export "ctf_output_len") (result i32) i32.const 24)
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
            determinism: DeterminismDeclaration::Mode(ctf_generator::DeterminismMode::Strict),
            declared_outputs: &["chal".to_owned()],
        },
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(report.status.to_string(), "passed");
    assert_eq!(report.solver_flag.as_deref(), Some("abc"));
    assert!(report.generator_root.is_some());
    // Stage detail the CLI reports (tickets 29/30): determinism runs, the second
    // engine, and how many artifacts crossed to the solver.
    assert_eq!(report.generator_runs, Some(2));
    assert!(report.cross_engine.is_some());
    assert_eq!(report.artifact_count, Some(1));
    assert!(report.unverified_reason.is_none());
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
            determinism: DeterminismDeclaration::Mode(ctf_generator::DeterminismMode::Strict),
            declared_outputs: &["chal".to_owned()],
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
            determinism: DeterminismDeclaration::Mode(ctf_generator::DeterminismMode::Strict),
            declared_outputs: &["chal".to_owned()],
        },
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(report.status.to_string(), "unverified");
    assert!(report.generator_root.is_none());
    assert_eq!(
        report.unverified_reason,
        Some(ctf_generator::UnverifiedReason::RuntimeDeclared)
    );
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
            determinism: DeterminismDeclaration::Mode(ctf_generator::DeterminismMode::Strict),
            declared_outputs: &["chal".to_owned()],
        },
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(report.status.to_string(), "unverified");
}

#[test]
fn every_emitted_output_must_be_declared_by_generate_outputs() {
    // The generator emits `chal` and `extra.bin`; only `chal` is declared. The
    // block is canonical, so the refusal is G8 rather than an ABI error (spec §23.3).
    let err = offline_gate(
        OfflineGate {
            generator: Some(&wat(GENERATOR_EXTRA)),
            solver: Some(&wat(SOLVER_CORRECT)),
            seed: b"reference-seed",
            expected_flag: "abc",
            runtime_declared: false,
            offline_declared: true,
            determinism: DeterminismDeclaration::Mode(DeterminismMode::Strict),
            declared_outputs: &["chal".to_owned()],
        },
        &Limits::default(),
    )
    .unwrap_err();
    assert_eq!(err.stage, GateStage::Determinism);
    assert_eq!(
        err.source,
        GeneratorError::UndeclaredOutput("extra.bin".to_owned())
    );
    // The stage did not complete, so the record's determinism fields stay null.
    assert!(err.determinism.is_none(), "{err:?}");
    let sentence = err.to_string();
    assert!(sentence.contains("G8"), "the rule is named: {sentence}");
    assert!(
        sentence.contains("extra.bin"),
        "the offending name is named: {sentence}"
    );
}

#[test]
fn an_undeclared_output_name_cannot_inject_terminal_output() {
    // The name is guest-controlled. §13 requires a tool that writes it to a terminal
    // to escape control characters, or a crafted module could forge the gate's own
    // status lines.
    let err = GeneratorError::UndeclaredOutput("x\u{1b}[2K\n  determinism passed".to_owned());
    let sentence = err.to_string();
    assert!(
        !sentence.contains('\u{1b}') && !sentence.contains('\n'),
        "control characters are escaped: {sentence}"
    );
    assert!(sentence.contains("determinism passed"), "{sentence}");
}

#[test]
fn an_emitted_subset_of_the_declared_outputs_is_legal() {
    // The rule is one-directional: fewer outputs than declared is fine.
    let report = offline_gate(
        OfflineGate {
            generator: Some(&wat(GENERATOR)),
            solver: Some(&wat(SOLVER_CORRECT)),
            seed: b"reference-seed",
            expected_flag: "abc",
            runtime_declared: false,
            offline_declared: true,
            determinism: DeterminismDeclaration::Mode(DeterminismMode::Strict),
            declared_outputs: &["chal".to_owned(), "key.pem".to_owned()],
        },
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(report.status, GateStatus::Passed);
    assert_eq!(report.artifact_count, Some(1));
}

/// Spec §23.7: `none` declares that reproducibility is not required, so the gate
/// does not run. The generator would fail G9 if it did.
#[test]
fn determinism_none_is_unverified_and_does_not_run_the_generator() {
    let report = offline_gate(
        OfflineGate {
            generator: Some(&wat(STATEFUL)),
            solver: Some(&wat(SOLVER_CORRECT)),
            seed: b"reference-seed",
            expected_flag: "abc",
            runtime_declared: false,
            offline_declared: true,
            determinism: DeterminismDeclaration::Mode(DeterminismMode::None),
            declared_outputs: &["chal".to_owned()],
        },
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(report.status, GateStatus::Unverified);
    assert_eq!(
        report.unverified_reason,
        Some(UnverifiedReason::DeterminismNone(DeterminismMode::None))
    );
    // Nothing ran: no root, runs, cross-engine result, artifact count, or flag.
    assert!(report.generator_root.is_none());
    assert!(report.generator_runs.is_none());
    assert!(report.cross_engine.is_none());
    assert!(report.artifact_count.is_none());
    assert!(report.solver_flag.is_none());
    assert!(
        report
            .unverified_reason
            .unwrap()
            .to_string()
            .contains("§23.7")
    );
}

/// `flag_only` also declares that no gate exists (§23.7). Suppression is checked
/// before the missing-module conditions, so the reason names the mode.
#[test]
fn determinism_flag_only_is_unverified_rather_than_no_generator() {
    let report = offline_gate(
        OfflineGate {
            // Contradictory on purpose (§7.6 is not validated by the container):
            // a module is supplied to prove the gate does not run it.
            generator: Some(&wat(STATEFUL)),
            solver: Some(&wat(SOLVER_CORRECT)),
            seed: b"reference-seed",
            expected_flag: "abc",
            runtime_declared: false,
            offline_declared: true,
            determinism: DeterminismDeclaration::Mode(DeterminismMode::FlagOnly),
            declared_outputs: &[],
        },
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(report.status, GateStatus::Unverified);
    assert_eq!(
        report.unverified_reason,
        Some(UnverifiedReason::DeterminismNone(DeterminismMode::FlagOnly))
    );
    assert!(report.generator_runs.is_none());
}

/// An absent declaration is not a suppression: the gate still runs (scope: the
/// container does not validate §7.6 shapes).
#[test]
fn an_absent_determinism_declaration_still_runs_the_gate() {
    let err = offline_gate(
        OfflineGate {
            generator: Some(&wat(STATEFUL)),
            solver: Some(&wat(SOLVER_CORRECT)),
            seed: b"reference-seed",
            expected_flag: "abc",
            runtime_declared: false,
            offline_declared: true,
            determinism: DeterminismDeclaration::Absent,
            declared_outputs: &["chal".to_owned()],
        },
        &Limits::default(),
    )
    .unwrap_err();
    assert_eq!(err.stage, GateStage::Determinism);
    assert!(
        matches!(err.source, GeneratorError::Nondeterministic { run: 1 }),
        "{err:?}"
    );
}

/// §23.7/§25.6: a declaration that is present but not one of the three modes is not
/// absent. The gate cannot tell whether it may run, so it does not: the status is
/// `unverified` with [`UnverifiedReason::DeterminismUnrecognized`]. The generator
/// would fail G9 if it ran, so observing `unverified` proves neither module ran.
#[test]
fn an_unrecognised_determinism_declaration_is_unverified_and_runs_nothing() {
    let report = offline_gate(
        OfflineGate {
            // Contradictory on purpose (§7.6 is not validated by the container): a
            // module is supplied to prove the gate does not run it.
            generator: Some(&wat(STATEFUL)),
            solver: Some(&wat(SOLVER_CORRECT)),
            seed: b"reference-seed",
            expected_flag: "abc",
            runtime_declared: true,
            offline_declared: true,
            determinism: DeterminismDeclaration::Unrecognized,
            declared_outputs: &["chal".to_owned()],
        },
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(report.status, GateStatus::Unverified);
    assert_eq!(
        report.unverified_reason,
        Some(UnverifiedReason::DeterminismUnrecognized)
    );
    // The determinism declaration is checked first, before `runtime`: an
    // unrecognised mode is named even when another condition also holds.
    assert!(report.generator_root.is_none());
    assert!(report.generator_runs.is_none());
    assert!(report.cross_engine.is_none());
    assert!(report.artifact_count.is_none());
    assert!(report.solver_flag.is_none());
    let reason = report.unverified_reason.unwrap().to_string();
    assert!(reason.contains("§23.7"), "the section is named: {reason}");
    assert!(
        reason.contains("not a mode"),
        "the condition is named: {reason}"
    );
    assert!(!reason.contains('/'), "the reason is path-free: {reason}");
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
    assert!(check_flag("abc", Some("abc")).is_ok());
    assert!(
        check_flag("abc", None).is_ok(),
        "no injected flag means no check"
    );
    assert!(
        check_flag("abc", Some("")).is_err(),
        "a present-but-empty flag is a value the generator must match (§26 I4)"
    );
    assert!(check_flag("", Some("")).is_ok());
    assert!(check_flag("abc", Some("wrong")).is_err());
}
