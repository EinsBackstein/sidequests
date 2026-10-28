//! The container entrypoint (ticket 67): the `ctf-generator` binary runs a sample
//! generator end to end with an injected seed and writes its artifacts. Also the
//! §26 precedence rules and §23.7 `--determinism` modes, which are properties of
//! the executable rather than of the library.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::Command;

const SAMPLE: &[u8] = include_bytes!("fixtures/generator.wasm");

/// chal's only data byte is the seed's first byte, so a test can see which seed
/// the binary chose even though it does not print the seed.
const SEED_REVEALING: &str = r#"
(module
  (memory (export "memory") 1)
  (data (i32.const 1024) "\01\00\00\00\04\00\00\00chal\01\00\00\00X\03\00\00\00abc")
  (func (export "ctf_alloc") (param i32) (result i32) i32.const 2048)
  (func (export "ctf_generate") (param i32 i32) (result i32)
    i32.const 1040
    local.get 0
    i32.load8_u
    i32.store8
    i32.const 1024)
  (func (export "ctf_output_len") (result i32) i32.const 24)
)
"#;

/// A generator whose output depends on its own call count (rule G9). Under
/// §23.7 `none` the gate is not run, so this module is legal there.
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

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ctf-bin-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_module(dir: &Path, source: &str) -> PathBuf {
    let module = dir.join("gen.wasm");
    std::fs::write(&module, wat::parse_str(source).unwrap()).unwrap();
    module
}

/// Run the binary with a controlled environment: `CTF_SEED` and `CTF_FLAG` are
/// removed first so an ambient value cannot decide the test.
fn run(dir: &Path, module: &Path, extra: &[&str], env: &[(&str, &str)]) -> std::process::Output {
    let out = dir.join("data");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ctf-generator"));
    cmd.arg("--module")
        .arg(module)
        .arg("--out")
        .arg(&out)
        .env_remove("CTF_SEED")
        .env_remove("CTF_FLAG");
    for (key, value) in env {
        cmd.env(key, value);
    }
    for arg in extra {
        cmd.arg(arg);
    }
    cmd.output().unwrap()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn the_binary_runs_a_sample_generator_with_an_injected_seed() {
    let dir = scratch("sample");
    let module = dir.join("gen.wasm");
    let seed = dir.join("seed");
    let out = dir.join("data");
    let flag = dir.join("flag");
    std::fs::write(&module, SAMPLE).unwrap();
    std::fs::write(&seed, [0x5au8; 32]).unwrap();

    let status = Command::new(env!("CARGO_BIN_EXE_ctf-generator"))
        .arg("--module")
        .arg(&module)
        .arg("--out")
        .arg(&out)
        .arg("--seed-file")
        .arg(&seed)
        .arg("--flag-out")
        .arg(&flag)
        .env_remove("CTF_SEED")
        .env_remove("CTF_FLAG")
        .status()
        .unwrap();
    assert!(status.success(), "the generator binary must succeed");

    assert_eq!(std::fs::read(out.join("chal")).unwrap().len(), 44);
    assert!(out.join("key.bin").is_file());
    assert_eq!(std::fs::read_to_string(&flag).unwrap(), "ctf{example}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_binary_refuses_to_run_without_a_seed() {
    let dir = scratch("no-seed");
    let module = dir.join("gen.wasm");
    let out = dir.join("data");
    std::fs::write(&module, SAMPLE).unwrap();

    // A seed file that does not exist: the binary must fail, not guess.
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_ctf-generator"))
        .arg("--module")
        .arg(&module)
        .arg("--out")
        .arg(&out)
        .arg("--seed-file")
        .arg(dir.join("absent"))
        .env_remove("CTF_SEED")
        .status()
        .unwrap();
    assert!(!status.success(), "a container with no seed must fail");
    let _ = std::fs::remove_dir_all(&dir);
}

/// §26.1 / §26 I3: the environment variable takes precedence over the mount,
/// including an explicit `--seed-file`.
#[test]
fn the_environment_seed_wins_over_an_explicit_seed_file() {
    let dir = scratch("seed-env-wins");
    let module = write_module(&dir, SEED_REVEALING);
    let seed_file = dir.join("seed");
    std::fs::write(&seed_file, [0x5au8; 32]).unwrap();
    let env_seed = "11".repeat(32);

    let output = run(
        &dir,
        &module,
        &["--seed-file", seed_file.to_str().unwrap()],
        &[("CTF_SEED", &env_seed)],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        std::fs::read(dir.join("data/chal"))
            .unwrap()
            .first()
            .copied(),
        Some(0x11),
        "the environment seed, not the file's, must reach the generator"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// With no `CTF_SEED`, the explicit path is the seed source; with no flag
/// injected, there is nothing to compare the generator's flag against.
#[test]
fn an_explicit_seed_file_is_read_when_the_environment_is_absent() {
    let dir = scratch("seed-file-only");
    let module = write_module(&dir, SEED_REVEALING);
    let seed_file = dir.join("seed");
    std::fs::write(&seed_file, [0x5au8; 32]).unwrap();

    let output = run(
        &dir,
        &module,
        &["--seed-file", seed_file.to_str().unwrap()],
        &[],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        std::fs::read(dir.join("data/chal"))
            .unwrap()
            .first()
            .copied(),
        Some(0x5a),
        "the explicit seed file must be read when CTF_SEED is absent"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// §26 I3: a present but non-Unicode `CTF_SEED` is malformed, not absent. It must
/// not fall through to the explicit mount, which would generate from a seed the
/// orchestrator did not inject.
#[cfg(unix)]
#[test]
fn a_non_utf8_environment_seed_does_not_fall_through_to_the_file() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let dir = scratch("seed-env-not-utf8");
    let module = write_module(&dir, SEED_REVEALING);
    let seed_file = dir.join("seed");
    std::fs::write(&seed_file, [0x5au8; 32]).unwrap();
    let out = dir.join("data");

    let output = Command::new(env!("CARGO_BIN_EXE_ctf-generator"))
        .arg("--module")
        .arg(&module)
        .arg("--out")
        .arg(&out)
        .arg("--seed-file")
        .arg(&seed_file)
        .env_remove("CTF_FLAG")
        .env("CTF_SEED", OsString::from_vec(vec![0xff, 0xfe]))
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "a malformed CTF_SEED must fail the start, not fall back to the mount"
    );
    assert!(
        stderr(&output).contains("not UTF-8"),
        "the failure must name the malformed seed: {}",
        stderr(&output)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// §26 I4: `CTF_FLAG` present but empty is an injected value, not "no value". The
/// generator emits `abc`, so an empty injected flag is a mismatch and the
/// challenge must not start.
#[test]
fn an_empty_injected_flag_is_a_mismatch() {
    let dir = scratch("empty-flag");
    let module = write_module(&dir, SEED_REVEALING);
    let seed_file = dir.join("seed");
    std::fs::write(&seed_file, [0x5au8; 32]).unwrap();

    let output = run(
        &dir,
        &module,
        &["--seed-file", seed_file.to_str().unwrap()],
        &[("CTF_FLAG", "")],
    );
    assert!(
        !output.status.success(),
        "an empty injected flag must be rejected, not read as absent"
    );
    assert!(
        stderr(&output).contains("does not match"),
        "the diagnostic names the mismatch: {}",
        stderr(&output)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// §23.7 `none`: reproducibility is not required, so the gate does not run and a
/// module that changes between calls is still allowed to write its one run.
#[test]
fn determinism_none_runs_a_nondeterministic_module_once() {
    let dir = scratch("determinism-none");
    let module = write_module(&dir, STATEFUL);
    let seed_file = dir.join("seed");
    std::fs::write(&seed_file, [0x5au8; 32]).unwrap();

    let output = run(
        &dir,
        &module,
        &[
            "--seed-file",
            seed_file.to_str().unwrap(),
            "--determinism",
            "none",
        ],
        &[("CTF_FLAG", "abc")],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        std::fs::read(dir.join("data/chal")).unwrap(),
        [0u8],
        "the first (and only) run's output must be written"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The default is `strict`, and the same module must fail the two-run gate.
#[test]
fn the_default_strict_gate_rejects_a_nondeterministic_module() {
    let dir = scratch("determinism-strict");
    let module = write_module(&dir, STATEFUL);
    let seed_file = dir.join("seed");
    std::fs::write(&seed_file, [0x5au8; 32]).unwrap();

    let output = run(
        &dir,
        &module,
        &["--seed-file", seed_file.to_str().unwrap()],
        &[("CTF_FLAG", "abc")],
    );
    assert!(!output.status.success(), "the strict gate must reject it");
    assert!(
        stderr(&output).contains("determinis"),
        "the diagnostic names determinism: {}",
        stderr(&output)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// §23.7 `flag_only` declares no generator, so refusing is the honest answer.
#[test]
fn determinism_flag_only_is_refused() {
    let dir = scratch("determinism-flag-only");
    let module = write_module(&dir, STATEFUL);
    let seed_file = dir.join("seed");
    std::fs::write(&seed_file, [0x5au8; 32]).unwrap();

    let output = run(
        &dir,
        &module,
        &[
            "--seed-file",
            seed_file.to_str().unwrap(),
            "--determinism",
            "flag_only",
        ],
        &[],
    );
    assert!(!output.status.success(), "flag_only must be refused");
    let message = stderr(&output);
    assert!(message.contains("flag_only"), "{message}");
    assert!(message.contains("no generator"), "{message}");
    assert!(
        !dir.join("data").exists(),
        "a refused mode must not write outputs"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A value outside the three modes is a usage error that names the accepted set.
#[test]
fn an_unknown_determinism_value_is_a_usage_error() {
    let dir = scratch("determinism-unknown");
    let module = write_module(&dir, STATEFUL);

    let output = run(&dir, &module, &["--determinism", "sometimes"], &[]);
    assert!(!output.status.success(), "an unknown mode must be refused");
    let message = stderr(&output);
    assert!(message.contains("sometimes"), "{message}");
    assert!(message.contains("strict, none, flag_only"), "{message}");
    let _ = std::fs::remove_dir_all(&dir);
}
