//! `ctf pack` tests (ticket 35).
//!
//! Packing is where an author's YAML becomes bytes a conforming reader accepts, so
//! these tests drive the binary and then parse its output with the library: a valid
//! document round-trips its manifest, and a schema violation is refused with the
//! offending key named rather than producing a bundle.

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
        p.push(format!("ctf-pack-{}-{tag}", std::process::id()));
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

fn yaml(dir: &TempDir, name: &str, body: &str) -> String {
    let p = dir.path(name);
    std::fs::write(&p, body).unwrap();
    p
}

fn pack(source: &str, out: &str) -> (bool, String, String) {
    let output = Command::new(BIN)
        .arg("pack")
        .arg(source)
        .arg("--out")
        .arg(out)
        .output()
        .expect("run ctf pack");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

const MINIMAL: &str = "\
spec: 1
id: whos-that-bird
name: \"Who's That Bird\"
";

#[test]
fn packs_a_minimal_document_and_round_trips_the_manifest() {
    let dir = TempDir::new("minimal");
    let source = yaml(&dir, "chal.yaml", MINIMAL);
    let out = dir.path("chal.ctf");

    let (ok, stdout, stderr) = pack(&source, &out);
    assert!(ok, "pack refused a valid document: {stdout}{stderr}");

    let bytes = std::fs::read(&out).unwrap();
    let bundle = ctf_format::Bundle::parse(&bytes).unwrap();
    assert_eq!(bundle.manifest.spec(), 1);
    assert_eq!(bundle.manifest.id(), "whos-that-bird");
    assert_eq!(bundle.manifest.name(), "Who's That Bird");
}

#[test]
fn refuses_an_unknown_key_and_names_it() {
    let dir = TempDir::new("unknown-key");
    let source = yaml(
        &dir,
        "bad.yaml",
        "spec: 1\nid: x\nname: X\nvisibilty: hidden\n",
    );
    let out = dir.path("bad.ctf");

    let (ok, _stdout, stderr) = pack(&source, &out);
    assert!(!ok, "a misspelled key must be refused");
    assert!(
        stderr.contains("visibilty"),
        "the key must be named: {stderr}"
    );
    assert!(
        !std::path::Path::new(&out).exists(),
        "a refused pack must not leave a bundle"
    );
}

#[test]
fn refuses_a_bad_enum_and_names_the_key() {
    let dir = TempDir::new("bad-enum");
    let source = yaml(
        &dir,
        "bad.yaml",
        "\
spec: 1
id: x
name: X
generate:
  wasm: gen.wasm
  determinism: sometimes
  outputs: []
",
    );
    let out = dir.path("bad.ctf");

    let (ok, _stdout, stderr) = pack(&source, &out);
    assert!(!ok, "an invalid enum must be refused");
    assert!(
        stderr.contains("generate.determinism"),
        "the key must be named: {stderr}"
    );
}

/// §29.1: an out-of-range port cannot be represented in the descriptor, so it must
/// fail the pack instead of being silently omitted while the committed manifest
/// still carries it.
#[test]
fn refuses_an_out_of_range_container_port() {
    let dir = TempDir::new("big-port");
    let source = yaml(
        &dir,
        "chal.yaml",
        "\
spec: 1
id: big-port
name: Big Port
runtime:
  image: \"ghcr.io/ctf/big-port@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"
  ports: [{ container: 70000, protocol: tcp }]
  resources: { cpu: \"0.5\", memory: \"256Mi\", pids: 64 }
  instancing: per_team
  ttl: 30m
  readiness: { tcp: 80, timeout: 30s }
",
    );
    let out = dir.path("chal.ctf");
    let (ok, _stdout, stderr) = pack(&source, &out);
    assert!(!ok, "an out-of-range port must fail the pack");
    assert!(stderr.contains("port"), "the port must be named: {stderr}");
    assert!(stderr.contains("must be between 1 and 65535"), "{stderr}");
    assert!(!std::path::Path::new(&out).exists());
}

#[test]
fn refuses_an_out_of_range_readiness_port() {
    let dir = TempDir::new("big-readiness");
    let source = yaml(
        &dir,
        "chal.yaml",
        "\
spec: 1
id: big-readiness
name: Big Readiness
runtime:
  image: \"ghcr.io/ctf/big-readiness@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"
  ports: [{ container: 80, protocol: tcp }]
  resources: { cpu: \"0.5\", memory: \"256Mi\", pids: 64 }
  instancing: per_team
  ttl: 30m
  readiness: { tcp: 70000, timeout: 30s }
",
    );
    let out = dir.path("chal.ctf");
    let (ok, _stdout, stderr) = pack(&source, &out);
    assert!(!ok, "an out-of-range readiness port must fail the pack");
    assert!(
        stderr.contains("readiness.tcp"),
        "the readiness port must be named: {stderr}"
    );
    assert!(stderr.contains("must be between 1 and 65535"), "{stderr}");
    assert!(!std::path::Path::new(&out).exists());
}

#[test]
fn packs_a_nested_artifact_tree_and_round_trips_its_path() {
    let dir = TempDir::new("nested");
    let assets = dir.0.join("assets");
    std::fs::create_dir_all(&assets).unwrap();
    std::fs::write(assets.join("main.c"), b"int main(void) { return 0; }\n").unwrap();

    // `source` is relative to the authoring document, not the shell's cwd.
    let source = yaml(
        &dir,
        "chal.yaml",
        "\
spec: 1
id: source-tree
name: Source Tree
artifacts:
  - name: main.c
    source: assets/main.c
    path: src/main.c
",
    );
    let out = dir.path("chal.ctf");

    let (ok, stdout, stderr) = pack(&source, &out);
    assert!(ok, "pack refused a valid tree: {stdout}{stderr}");

    let bytes = std::fs::read(&out).unwrap();
    let bundle = ctf_format::Bundle::parse(&bytes).unwrap();
    let name_id = bundle
        .manifest
        .names()
        .iter()
        .position(|n| *n == "main.c")
        .expect("the artifact has a name-table entry") as u16;
    assert_eq!(bundle.manifest.path_of(name_id), Some("src/main.c"));
}

#[test]
fn refuses_a_traversing_path_and_names_the_key() {
    for path in ["../escape", "/etc/passwd", "src/../../main.c"] {
        let dir = TempDir::new("bad-path");
        let source = yaml(
            &dir,
            "bad.yaml",
            &format!(
                "\
spec: 1
id: x
name: X
artifacts:
  - name: main.c
    source: main.c
    path: \"{path}\"
"
            ),
        );
        let out = dir.path("bad.ctf");

        let (ok, _stdout, stderr) = pack(&source, &out);
        assert!(!ok, "a traversing path must be refused: {path}");
        assert!(
            stderr.contains("artifacts[0].path"),
            "the key must be named for {path}: {stderr}"
        );
        assert!(
            !std::path::Path::new(&out).exists(),
            "a refused pack must not leave a bundle"
        );
    }
}

/// Spec §13: `ctf pack` prints the descriptor's description warning before it
/// writes the bundle, so the origin must not carry a raw ESC to the terminal.
#[test]
fn an_escape_in_a_description_is_not_written_raw() {
    let dir = TempDir::new("escape-desc");
    let source = yaml(
        &dir,
        "escape.yaml",
        "\
spec: 1
id: escape-desc
name: Escape
description: \"see http://evil\\u001b[2J.invalid/\"
",
    );
    let out = dir.path("escape.ctf");

    let (ok, _stdout, stderr) = pack(&source, &out);
    assert!(ok, "warning-only description must pack: {stderr}");
    assert!(
        !stderr.as_bytes().contains(&0x1b),
        "raw escape byte reached the terminal:\n{stderr:?}"
    );
    assert!(
        stderr.contains("\\u{1b}"),
        "the escape should be visible as text:\n{stderr}"
    );
}

/// A C1 control such as U+0085 is permitted by `check_name` and by the seed
/// rules, so `pack` must escape it when quoting a description origin.
#[test]
fn a_c1_control_in_a_description_is_not_written_raw() {
    let dir = TempDir::new("c1-desc");
    let source = yaml(
        &dir,
        "c1.yaml",
        "\
spec: 1
id: c1-desc
name: C1
description: \"see http://evil\\u0085.invalid/\"
",
    );
    let out = dir.path("c1.ctf");

    let (ok, _stdout, stderr) = pack(&source, &out);
    assert!(ok, "warning-only description must pack: {stderr}");
    assert!(
        !stderr.contains('\u{85}'),
        "raw C1 control reached the terminal:\n{stderr:?}"
    );
    assert!(
        stderr.contains("\\u{85}"),
        "the control character should be visible as text:\n{stderr}"
    );
}

/// An ordinary description is quoted unchanged; escaping must not rewrite text
/// that has no terminal effect.
#[test]
fn a_normal_description_is_printed_unchanged() {
    let dir = TempDir::new("normal-desc");
    let source = yaml(
        &dir,
        "normal.yaml",
        "\
spec: 1
id: normal-desc
name: Normal
description: \"see http://example.test/asset.png\"
",
    );
    let out = dir.path("normal.ctf");

    let (ok, _stdout, stderr) = pack(&source, &out);
    assert!(ok, "normal description must pack: {stderr}");
    assert!(
        stderr.contains("http://example.test"),
        "the origin should be quoted verbatim:\n{stderr}"
    );
    assert!(
        !stderr.contains("\\u{"),
        "nothing should have been escaped:\n{stderr}"
    );
}
