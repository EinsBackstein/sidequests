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
