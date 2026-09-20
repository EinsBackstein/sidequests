//! Generator host tests: the sandbox, the ABI, the output root, and the
//! determinism gate (spec §23).
//!
//! The fixture is a real module built from the Rust guest SDK
//! (`sdk/sample-generator`), so these tests exercise the whole guest path, not a
//! hand-written stand-in. The WAT modules cover the negative cases the sandbox
//! exists to reject.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use ctf_generator::abi::{INTERFACE_VERSION, WASM_PROFILE, ensure_interface, ensure_profile};
use ctf_generator::{Generator, GeneratorError, Limits, determinism_gate};

/// A real generator built with the Rust SDK.
const SAMPLE: &[u8] = include_bytes!("fixtures/generator.wasm");

/// A well-formed block: one output `chal` = `A`, flag `abc`.
const WELL_FORMED_BLOCK: &str = r#"
(module
  (memory (export "memory") 1)
  (data (i32.const 1024) "\01\00\00\00\04\00\00\00chal\01\00\00\00A\03\00\00\00abc")
  (func (export "ctf_alloc") (param i32) (result i32) i32.const 0)
  (func (export "ctf_generate") (param i32 i32) (result i32) i32.const 1024)
  (func (export "ctf_output_len") (result i32) i32.const 24)
)
"#;

/// A module that imports a clock. The sandbox provides no import, so it must be
/// refused before it runs (rule G2).
const IMPORTS_A_CLOCK: &str = r#"
(module
  (import "env" "now" (func $now (result i64)))
  (memory (export "memory") 1)
  (func (export "ctf_alloc") (param i32) (result i32) i32.const 0)
  (func (export "ctf_generate") (param i32 i32) (result i32) i32.const 1024)
  (func (export "ctf_output_len") (result i32) i32.const 0)
)
"#;

/// A module whose output depends on its own call count: the second call in one
/// instance writes a different data byte, so the two roots differ (rule G9).
const STATEFUL: &str = r#"
(module
  (memory (export "memory") 1)
  (global $n (mut i32) (i32.const 0))
  (data (i32.const 1024) "\01\00\00\00\04\00\00\00chal\01\00\00\00A\03\00\00\00abc")
  (func (export "ctf_alloc") (param i32) (result i32) i32.const 0)
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

/// A module with no exit: fuel must stop it (rule G5).
const SPINS_FOREVER: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "ctf_alloc") (param i32) (result i32) i32.const 0)
  (func (export "ctf_generate") (param i32 i32) (result i32)
    (loop $l br $l)
    i32.const 1024)
  (func (export "ctf_output_len") (result i32) i32.const 0)
)
"#;

/// A module missing `ctf_output_len` (rule G3).
const MISSING_EXPORT: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "ctf_alloc") (param i32) (result i32) i32.const 0)
  (func (export "ctf_generate") (param i32 i32) (result i32) i32.const 1024)
)
"#;

fn wat(source: &str) -> Vec<u8> {
    wat::parse_str(source).unwrap()
}

#[test]
fn the_rust_sdk_sample_runs_and_produces_its_declared_outputs() {
    let generator = Generator::new(SAMPLE).unwrap();
    let out = generator.run(b"seed-123", &Limits::default()).unwrap();

    assert_eq!(out.flag, "ctf{example}");
    assert_eq!(out.outputs.len(), 2);
    assert_eq!(out.outputs[0].name, "chal");
    assert_eq!(out.outputs[1].name, "key.bin");

    // The same transform the sample's `generate` performs.
    let mut expected = b"artifact-v1:".to_vec();
    for (i, byte) in b"seed-123".iter().enumerate() {
        expected.push(byte.wrapping_add((i as u8).wrapping_mul(31)));
    }
    assert_eq!(out.outputs[0].bytes, expected);
    assert_eq!(out.outputs[1].bytes, b"321-dees");
}

#[test]
fn the_gate_passes_and_the_second_engine_agrees() {
    let report = determinism_gate(SAMPLE, b"reference-seed", &Limits::default(), 2).unwrap();
    assert_eq!(report.runs, 2);
    assert!(report.cross_engine, "wasmi should run this scalar module");
    assert_eq!(report.output_root, report.outputs.output_root());
}

#[test]
fn a_seed_dependent_generator_changes_its_root_with_the_seed() {
    let generator = Generator::new(SAMPLE).unwrap();
    let a = generator.run(b"alpha", &Limits::default()).unwrap();
    let b = generator.run(b"beta", &Limits::default()).unwrap();
    assert_ne!(a.output_root(), b.output_root());
}

#[test]
fn a_module_that_imports_a_capability_is_rejected_before_it_runs() {
    let err = match Generator::new(&wat(IMPORTS_A_CLOCK)) {
        Ok(_) => panic!("a module with an import must be rejected"),
        Err(e) => e,
    };
    assert_eq!(err, GeneratorError::ImportsNotAllowed);
}

#[test]
fn a_module_that_changes_between_calls_fails_the_gate() {
    let err = determinism_gate(&wat(STATEFUL), b"", &Limits::default(), 2).unwrap_err();
    assert!(
        matches!(err, GeneratorError::Nondeterministic { run: 1 }),
        "{err:?}"
    );
}

#[test]
fn an_endless_loop_is_stopped_by_fuel() {
    let limits = Limits {
        fuel: 10_000,
        ..Limits::default()
    };
    let err = Generator::new(&wat(SPINS_FOREVER))
        .unwrap()
        .run(b"", &limits)
        .unwrap_err();
    assert_eq!(err, GeneratorError::OutOfFuel);
}

#[test]
fn a_missing_export_is_reported_by_name() {
    let err = Generator::new(&wat(MISSING_EXPORT))
        .unwrap()
        .run(b"", &Limits::default())
        .unwrap_err();
    assert_eq!(err, GeneratorError::MissingExport("ctf_output_len"));
}

#[test]
fn the_output_block_round_trips_through_the_host_abi() {
    let generator = Generator::new(&wat(WELL_FORMED_BLOCK)).unwrap();
    let out = generator.run(b"", &Limits::default()).unwrap();
    assert_eq!(out.flag, "abc");
    assert_eq!(out.outputs.len(), 1);
    assert_eq!(out.outputs[0].name, "chal");
    assert_eq!(out.outputs[0].bytes, b"A");
}

#[test]
fn an_unknown_interface_or_profile_is_refused() {
    assert_eq!(INTERFACE_VERSION, 1);
    assert_eq!(WASM_PROFILE, 1);
    assert!(ensure_interface(1).is_ok());
    assert_eq!(ensure_interface(2), Err(2));
    assert!(ensure_profile(1).is_ok());
    assert_eq!(ensure_profile(2), Err(2));
}

#[test]
fn a_truncated_output_block_is_rejected() {
    // A `ctf_output_len` that overruns the declared block: decode sees trailing
    // nothing, but the data length points past the end.
    let truncated = r#"
    (module
      (memory (export "memory") 1)
      (data (i32.const 1024) "\01\00\00\00\04\00\00\00chal\ff\00\00\00A\00\00\00\00")
      (func (export "ctf_alloc") (param i32) (result i32) i32.const 0)
      (func (export "ctf_generate") (param i32 i32) (result i32) i32.const 1024)
      (func (export "ctf_output_len") (result i32) i32.const 21)
    )
    "#;
    let err = Generator::new(&wat(truncated))
        .unwrap()
        .run(b"", &Limits::default())
        .unwrap_err();
    assert!(matches!(err, GeneratorError::Abi(_)), "{err:?}");
}
