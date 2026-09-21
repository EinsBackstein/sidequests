//! `ctf run`: staged output, exit status, and the persisted tri-state record
//! (tickets 29 and 30, spec §25.5-§25.6).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_ctf");

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("ctf-rungate-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
    fn path(&self, name: &str) -> String {
        self.0.join(name).to_str().unwrap().to_owned()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(args: &[&str]) -> (bool, String, String) {
    let output = Command::new(BIN).args(args).output().expect("run ctf");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// A WAT data-string escape: every byte as `\xx`.
fn escape(bytes: &[u8]) -> String {
    let mut s = String::new();
    for b in bytes {
        s.push_str(&format!("\\{b:02x}"));
    }
    s
}

/// The canonical generator output block (spec §23.3).
fn generator_block(flag: &str, artifacts: &[(&str, &[u8])]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&(artifacts.len() as u32).to_le_bytes());
    for (name, data) in artifacts {
        v.extend_from_slice(&(name.len() as u32).to_le_bytes());
        v.extend_from_slice(name.as_bytes());
        v.extend_from_slice(&(data.len() as u32).to_le_bytes());
        v.extend_from_slice(data);
    }
    v.extend_from_slice(&(flag.len() as u32).to_le_bytes());
    v.extend_from_slice(flag.as_bytes());
    v
}

/// The canonical solver output block (spec §25.4).
fn solver_block(flag: &str) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&(flag.len() as u32).to_le_bytes());
    v.extend_from_slice(flag.as_bytes());
    v
}

/// A generator that ignores its seed and emits a fixed block.
fn generator_wasm(block: &[u8]) -> Vec<u8> {
    let src = format!(
        r#"(module
  (memory (export "memory") 1)
  (data (i32.const 1024) "{}")
  (func (export "ctf_alloc") (param i32) (result i32) i32.const 8192)
  (func (export "ctf_generate") (param i32 i32) (result i32) i32.const 1024)
  (func (export "ctf_output_len") (result i32) i32.const {})
)
"#,
        escape(block),
        block.len()
    );
    wat::parse_str(&src).unwrap()
}

/// A solver that ignores its input and answers a fixed flag.
fn solver_wasm(flag: &str) -> Vec<u8> {
    let block = solver_block(flag);
    let src = format!(
        r#"(module
  (memory (export "memory") 1)
  (data (i32.const 1024) "{}")
  (func (export "ctf_alloc") (param i32) (result i32) i32.const 8192)
  (func (export "ctf_solve") (param i32 i32) (result i32) i32.const 1024)
  (func (export "ctf_output_len") (result i32) i32.const {})
)
"#,
        escape(&block),
        block.len()
    );
    wat::parse_str(&src).unwrap()
}

const ID: &str = "gate-test";

/// The reference seed and derived flag for `ID`, version 0, subject `reference`.
fn reference(secret_hex: &str) -> ([u8; 32], String) {
    let mut secret = Vec::with_capacity(32);
    for pair in secret_hex.as_bytes().chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16).unwrap() as u8;
        let lo = (pair[1] as char).to_digit(16).unwrap() as u8;
        secret.push((hi << 4) | lo);
    }
    let seed = ctf_format::derive::subject_seed(&secret, ID, 0, "reference").expect("subject seed");
    let flag = ctf_format::derive::flag(&seed);
    (seed, flag)
}

/// Write the gate fixture: an authoring document plus the generator/solver it names.
fn fixture(dir: &TempDir, tag: &str, solver_flag: &str) -> String {
    let secret = "00".repeat(32);
    let (_seed, expected) = reference(&secret);
    let block = generator_block(&expected, &[("artifact.bin", b"artifact bytes")]);
    std::fs::write(dir.path(&format!("{tag}-gen.wasm")), generator_wasm(&block)).unwrap();
    std::fs::write(
        dir.path(&format!("{tag}-solver.wasm")),
        solver_wasm(solver_flag),
    )
    .unwrap();
    let yaml = format!(
        "spec: 1\nid: {ID}\nname: Gate Test\nflag: derived\n\
         generate:\n  wasm: {tag}-gen.wasm\n  determinism: strict\n  outputs:\n    \
         - {{ name: artifact.bin, player_visible: true }}\n\
         verify:\n  solver: {tag}-solver.wasm\n  expect: flag\n  offline: true\n"
    );
    let p = dir.path(&format!("{tag}.yaml"));
    std::fs::write(&p, yaml).unwrap();
    p
}

const MINIMAL: &str = "\
spec: 1
id: whos-that-bird
name: \"Who's That Bird\"
category: osint
";

#[test]
fn run_names_every_stage_and_persists_a_pass() {
    let dir = TempDir::new("pass");
    let secret = "00".repeat(32);
    let (_seed, expected) = reference(&secret);
    let source = fixture(&dir, "pass", &expected);
    let status = dir.path("pass.status.json");
    let (ok, stdout, stderr) = run(&["run", &source, "--secret", &secret, "--status", &status]);
    assert!(ok, "a passing gate exits 0: {stdout}{stderr}");
    assert!(stdout.contains("gate          passed"), "status: {stdout}");
    for stage in ["determinism", "generator", "artifact", "solver", "compare"] {
        assert!(
            stdout.contains(stage),
            "stage `{stage}` must be named: {stdout}"
        );
    }
    let record = std::fs::read_to_string(&status).unwrap();
    assert!(
        record.contains("\"schema\": \"ctf/verification/v1\""),
        "record schema: {record}"
    );
    assert!(
        record.contains("\"status\": \"passed\""),
        "record: {record}"
    );
    assert!(
        record.contains("\"generator_root\": \""),
        "a passed run records the generator root: {record}"
    );
}

#[test]
fn run_names_the_compare_stage_and_persists_a_failure() {
    let dir = TempDir::new("fail");
    let secret = "00".repeat(32);
    let source = fixture(&dir, "fail", "not-the-derived-flag");
    let bundle = dir.path("challenge.ctf");
    let (ok, stdout, stderr) = run(&["run", &source, "--secret", &secret, "--bundle", &bundle]);
    assert!(!ok, "a flag mismatch must exit non-zero");
    assert!(
        stdout.contains("gate          failed"),
        "status on stdout: {stdout}"
    );
    // The stages that ran are still named on a failure (spec §25.7 S9).
    for stage in ["determinism", "generator", "artifact", "solver", "compare"] {
        assert!(
            stdout.contains(stage),
            "stage `{stage}` must be named even on failure: {stdout}"
        );
    }
    assert!(
        stderr.contains("compare:"),
        "the failing stage must be named: {stderr}"
    );
    // `--bundle` persists alongside the bundle it describes.
    let record = std::fs::read_to_string(format!("{bundle}.status.json")).unwrap();
    assert!(
        record.contains("\"status\": \"failed\""),
        "record: {record}"
    );
}

#[test]
fn run_persists_an_unverified_status_distinctly() {
    let dir = TempDir::new("unverified");
    let source = dir.path("chal.yaml");
    std::fs::write(&source, MINIMAL).unwrap();
    let status = dir.path("chal.status.json");
    let secret = "00".repeat(32);
    let (ok, stdout, stderr) = run(&["run", &source, "--secret", &secret, "--status", &status]);
    assert!(ok, "unverified is not a failure: {stdout}{stderr}");
    assert!(stdout.contains("unverified"), "status: {stdout}");
    assert!(
        stdout.contains("determinism not run"),
        "an unverified run names the condition: {stdout}"
    );
    let record = std::fs::read_to_string(&status).unwrap();
    assert!(
        record.contains("\"status\": \"unverified\""),
        "record: {record}"
    );
    assert!(
        record.contains("\"generator_root\": null"),
        "an unverified run has no root: {record}"
    );
}
