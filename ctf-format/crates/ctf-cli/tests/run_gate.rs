//! `ctf run`: staged output, exit status, and the persisted tri-state record
//! (tickets 29 and 30, spec §25.5-§25.6).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::process::Command;

use ctf_format::cbor::Value;
use ctf_format::{Bundle, SectionFlags, SectionKind, SectionSpec, write_bundle};

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

/// A generator whose output changes with its own call count (rule G9): each call
/// writes its call number over the block byte at `mutate_at`. Used to prove the
/// gate did not run.
fn stateful_generator_wasm(block: &[u8], mutate_at: usize) -> Vec<u8> {
    let src = format!(
        r#"(module
  (memory (export "memory") 1)
  (global $n (mut i32) (i32.const 0))
  (data (i32.const 1024) "{}")
  (func (export "ctf_alloc") (param i32) (result i32) i32.const 8192)
  (func (export "ctf_generate") (param i32 i32) (result i32)
    i32.const {}
    i32.const 65
    global.get $n
    i32.add
    i32.store8
    global.get $n
    i32.const 1
    i32.add
    global.set $n
    i32.const 1024)
  (func (export "ctf_output_len") (result i32) i32.const {})
)
"#,
        escape(block),
        1024 + mutate_at,
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

/// Spec §22.2 as the CLI states it: both help strings promise 64 hex digits, and
/// the derivation is length-agnostic only for library callers. An empty secret
/// derives a publicly computable flag, so it must be refused before the gate runs.
#[test]
fn run_refuses_a_secret_that_is_not_64_hex_digits() {
    let dir = TempDir::new("secret-shape");
    let source = dir.path("chal.yaml");
    std::fs::write(&source, MINIMAL).unwrap();

    for (tag, secret) in [
        ("empty", String::new()),
        ("short", "00".repeat(16)),
        ("long", "00".repeat(33)),
    ] {
        let status = dir.path(&format!("{tag}.status.json"));
        let (ok, stdout, stderr) = run(&["run", &source, "--secret", &secret, "--status", &status]);
        assert!(!ok, "a {tag} secret must be refused: {stdout}{stderr}");
        assert!(
            stderr.contains("64 hex digits"),
            "the refusal names the contract: {stderr}"
        );
        assert!(
            !std::path::Path::new(&status).exists(),
            "a refused secret writes no record"
        );
    }

    // A 32-byte secret still runs the gate exactly as before.
    let secret = "00".repeat(32);
    let status = dir.path("ok.status.json");
    let (ok, stdout, stderr) = run(&["run", &source, "--secret", &secret, "--status", &status]);
    assert!(ok, "a 64-hex-digit secret still runs: {stdout}{stderr}");
    assert!(stdout.contains("gate          unverified"), "{stdout}");
}

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
    let (ok, stdout, stderr) = run(&["pack", &source, "--out", &bundle]);
    assert!(ok, "pack failed: {stdout}{stderr}");
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

/// Spec §23.7: `determinism: none` declares that reproducibility is not required,
/// so `ctf run` must not run the gate. The module varies across calls, so a gate
/// run would report `failed`; observing `unverified` proves it did not run.
#[test]
fn run_does_not_run_the_gate_for_determinism_none() {
    let dir = TempDir::new("determinism-none");
    let secret = "00".repeat(32);
    let (_seed, expected) = reference(&secret);
    let block = generator_block(&expected, &[("artifact.bin", b"artifact bytes")]);
    // The first artifact's data begins after the count, the name length and name,
    // and the data length.
    let data_at = 4 + 4 + "artifact.bin".len() + 4;
    std::fs::write(
        dir.path("none-gen.wasm"),
        stateful_generator_wasm(&block, data_at),
    )
    .unwrap();
    std::fs::write(dir.path("none-solver.wasm"), solver_wasm(&expected)).unwrap();
    let source = dir.path("none.yaml");
    std::fs::write(
        &source,
        format!(
            "spec: 1\nid: {ID}\nname: Gate Test\nflag: derived\n\
             generate:\n  wasm: none-gen.wasm\n  determinism: none\n  outputs:\n    \
             - {{ name: artifact.bin, player_visible: true }}\n\
             verify:\n  solver: none-solver.wasm\n  expect: flag\n  offline: true\n"
        ),
    )
    .unwrap();

    let status = dir.path("none.status.json");
    let (ok, stdout, stderr) = run(&["run", &source, "--secret", &secret, "--status", &status]);
    assert!(ok, "`none` is not a failure: {stdout}{stderr}");
    assert!(
        stdout.contains("gate          unverified"),
        "status: {stdout}"
    );
    assert!(
        stdout.contains("determinism not run"),
        "the condition is named: {stdout}"
    );
    assert!(
        !stderr.contains("not deterministic"),
        "the gate must not have run: {stderr}"
    );

    let record = std::fs::read_to_string(&status).unwrap();
    assert!(
        record.contains("\"status\": \"unverified\""),
        "record: {record}"
    );
    assert!(
        record.contains("determinism: none"),
        "the record says why: {record}"
    );
    assert!(record.contains("\"generator_root\": null"), "{record}");
    assert!(record.contains("\"runs\": null"), "{record}");
}

/// Spec §25.6/S10: `--bundle` names the bundle the record describes. A document for
/// another challenge must not have its verdict persisted beside that bundle.
#[test]
fn run_refuses_to_attach_the_record_to_another_challenge() {
    let dir = TempDir::new("attribution");
    let secret = "00".repeat(32);
    let (_seed, expected) = reference(&secret);
    let source = fixture(&dir, "attribution", &expected);

    let other = dir.path("other.yaml");
    std::fs::write(&other, "spec: 1\nid: another-chal\nname: Other\n").unwrap();
    let bundle = dir.path("other.ctf");
    let (ok, stdout, stderr) = run(&["pack", &other, "--out", &bundle]);
    assert!(ok, "pack failed: {stdout}{stderr}");

    let (ok, _stdout, stderr) = run(&["run", &source, "--secret", &secret, "--bundle", &bundle]);
    assert!(
        !ok,
        "a record for another challenge must not be written: {stderr}"
    );
    assert!(
        stderr.contains("another-chal"),
        "the error names the bundle's id: {stderr}"
    );
    assert!(
        !std::path::Path::new(&format!("{bundle}.status.json")).exists(),
        "a refused attribution writes no record"
    );
}

/// Replace or insert `key` inside a decoded manifest's `generate` map.
fn set_generate_key(manifest: &mut Value, key: &str, value: Value) {
    let Value::Map(entries) = manifest else {
        panic!("a manifest is a map");
    };
    let (_, generate) = entries
        .iter_mut()
        .find(|(k, _)| k.as_text() == Some("generate"))
        .expect("the fixture declares generate");
    let Value::Map(inner) = generate else {
        panic!("`generate` is a map");
    };
    match inner.iter_mut().find(|(k, _)| k.as_text() == Some(key)) {
        Some((_, slot)) => *slot = value,
        None => inner.push((Value::Text(key.to_owned()), value)),
    }
}

/// The gate fixture's bundle with its manifest `generate.determinism` replaced.
///
/// `ctf pack` cannot produce an unrecognised mode — the authoring validator rejects
/// it — so the bundle is rebuilt through `ctf_format` from the packed manifest. The
/// document still names the modules, and a bundle that declares them without
/// carrying them is gated on the document's bytes (§25.6).
fn bundle_with_determinism(
    dir: &TempDir,
    tag: &str,
    expected: &str,
    mode: Value,
) -> (String, String, String) {
    let source = fixture(dir, tag, expected);
    let packed = dir.path(&format!("{tag}-packed.ctf"));
    let (ok, stdout, stderr) = run(&["pack", &source, "--out", &packed]);
    assert!(ok, "pack failed: {stdout}{stderr}");
    let file = std::fs::read(&packed).unwrap();
    let parsed = Bundle::parse(&file).unwrap();
    let record = parsed
        .sections
        .iter()
        .find(|r| r.kind == SectionKind::Manifest)
        .expect("a bundle has a manifest");
    let mut manifest = Value::decode(&parsed.section_bytes(record).unwrap()).unwrap();
    set_generate_key(&mut manifest, "determinism", mode);
    let manifest_bytes = manifest.encode().unwrap();
    let bundle = dir.path(&format!("{tag}-patched.ctf"));
    let bytes = write_bundle(
        1,
        &[SectionSpec::inline(
            SectionKind::Manifest,
            0,
            SectionFlags::empty(),
            &manifest_bytes,
        )],
    )
    .unwrap();
    std::fs::write(&bundle, bytes).unwrap();
    (source, packed, bundle)
}

/// Spec §23.7/§25.6: a `determinism` value that is not one of the three modes is not
/// a mode. A bundle that would otherwise pass — generator, solver, `verify.offline`,
/// no `runtime` — must be `unverified`, never `passed`, on the bundle-override path.
#[test]
fn run_reports_an_unrecognised_determinism_mode_as_unverified() {
    let dir = TempDir::new("determinism-unrecognised");
    let secret = "00".repeat(32);
    let (_seed, expected) = reference(&secret);
    let (source, control, bundle) = bundle_with_determinism(
        &dir,
        "unrecognised",
        &expected,
        Value::Text("nope".to_owned()),
    );

    // The packed bundle declares `strict`, so the same fixture passes; only the
    // replaced value can explain a non-`passed` outcome.
    let (ok, stdout, stderr) = run(&["run", &source, "--secret", &secret, "--bundle", &control]);
    assert!(ok, "the control gate passes: {stdout}{stderr}");
    assert!(stdout.contains("gate          passed"), "{stdout}");

    let (ok, stdout, stderr) = run(&["run", &source, "--secret", &secret, "--bundle", &bundle]);
    assert!(ok, "unverified is not a failure: {stdout}{stderr}");
    assert!(stdout.contains("gate          unverified"), "{stdout}");
    assert!(!stdout.contains("gate          passed"), "{stdout}");
    assert!(
        stdout.contains("not a mode"),
        "the reason names the condition: {stdout}"
    );
    assert!(
        !stderr.contains("not deterministic"),
        "the gate must not have run: {stderr}"
    );

    let record = std::fs::read_to_string(format!("{bundle}.status.json")).unwrap();
    assert!(record.contains("\"status\": \"unverified\""), "{record}");
    assert!(
        record.contains("not a mode"),
        "the record says why: {record}"
    );
    assert!(record.contains("\"generator_root\": null"), "{record}");
    assert!(record.contains("\"runs\": null"), "{record}");
}

/// §13: `ctf run` reads the same authoring document, and a schema error echoes the
/// offending key. That key is free-form text, so a control in it must be escaped
/// here too rather than reaching the operator's terminal.
#[test]
fn run_escapes_a_control_in_an_unknown_key() {
    let dir = TempDir::new("escape-schema");
    let source = dir.path("escape.yaml");
    std::fs::write(
        &source,
        "spec: 1\nid: escape-run\nname: Escape Run\n\"bad\\e[2Jkey\": 1\n",
    )
    .unwrap();

    let (_ok, stdout, stderr) = run(&["run", &source, "--secret", &"00".repeat(32)]);
    let both = format!("{stdout}{stderr}");
    assert!(
        !both.as_bytes().contains(&0x1b),
        "raw escape byte reached the terminal: {both:?}"
    );
    assert!(
        stderr.contains("\\u{1b}"),
        "the escape should be visible as text: {stderr}"
    );
}
