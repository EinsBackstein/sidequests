//! `ctf validate` tests (ticket 34).
//!
//! The command exists so an author learns what is wrong before packing: schema
//! violations (unknown keys, bad values) and policy violations (a section both
//! sealed and player-visible) are reported with the offending key, and the exit
//! status reflects validity.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_ctf");

struct TempYaml(std::path::PathBuf);

impl TempYaml {
    fn new(tag: &str, body: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("ctf-validate-{}-{tag}.yaml", std::process::id()));
        std::fs::write(&p, body).unwrap();
        Self(p)
    }
    fn path(&self) -> &str {
        self.0.to_str().unwrap()
    }
}

impl Drop for TempYaml {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn validate(path: &str, extra: &[&str]) -> (bool, String, String) {
    let out = Command::new(BIN)
        .arg("validate")
        .args(extra)
        .arg(path)
        .output()
        .expect("run ctf validate");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

const MINIMAL: &str = "\
spec: 1
id: whos-that-bird
name: \"Who's That Bird\"
";

#[test]
fn a_valid_document_exits_zero() {
    let t = TempYaml::new("valid", MINIMAL);
    let (ok, out, err) = validate(t.path(), &[]);
    assert!(ok, "valid document rejected: {out}{err}");
    assert!(out.contains("ok"), "{out}");
}

#[test]
fn a_misspelled_optional_key_is_rejected_and_named() {
    let t = TempYaml::new("typo", "spec: 1\nid: x\nname: X\nvisibilty: true\n");
    let (ok, _out, err) = validate(t.path(), &[]);
    assert!(!ok, "a typo'd optional key must be rejected");
    assert!(
        err.contains("visibilty"),
        "the diagnostic must name the key: {err}"
    );
}

#[test]
fn a_sealed_and_player_visible_member_is_a_policy_violation() {
    let body = "\
spec: 1
id: baby-rop
name: Baby ROP
generate:
  wasm: gen.wasm
  determinism: strict
  outputs:
    - { name: writeup.md, player_visible: true }
sealed:
  release: event_end
  members: [writeup.md]
";
    let t = TempYaml::new("policy", body);
    let (ok, _out, err) = validate(t.path(), &[]);
    assert!(!ok, "sealed + player-visible must fail");
    assert!(err.contains("sealed.members"), "{err}");
    assert!(err.contains("player-visible"), "{err}");
}

#[test]
fn an_invalid_enum_names_the_key() {
    let body = "\
spec: 1
id: x
name: X
generate:
  wasm: gen.wasm
  determinism: sometimes
  outputs: []
";
    let t = TempYaml::new("enum", body);
    let (ok, _out, err) = validate(t.path(), &[]);
    assert!(!ok);
    assert!(err.contains("generate.determinism"), "{err}");
}

#[test]
fn an_invalid_id_is_reported() {
    let t = TempYaml::new("id", "spec: 1\nid: Bad_ID\nname: X\n");
    let (ok, _out, err) = validate(t.path(), &[]);
    assert!(!ok);
    assert!(err.contains("`id`"), "{err}");
}

#[test]
fn a_second_positional_is_an_error() {
    let a = TempYaml::new("one", MINIMAL);
    let b = TempYaml::new("two", MINIMAL);
    let (ok, _out, err) = validate(a.path(), &[b.path()]);
    assert!(!ok, "a second positional must be rejected");
    assert!(err.contains("one file"), "{err}");
}
