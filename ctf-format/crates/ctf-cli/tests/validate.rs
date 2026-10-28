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

/// A document with a full `runtime` block; `container`, `readiness_tcp`, and
/// `pids` are the values the descriptor's policy checks look at.
fn runtime_doc(tag: &str, container: u64, readiness_tcp: u64, pids: u64) -> String {
    format!(
        "\
spec: 1
id: {tag}
name: Runtime
runtime:
  image: \"ghcr.io/ctf/{tag}@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"
  ports: [{{ container: {container}, protocol: tcp }}]
  resources: {{ cpu: \"0.5\", memory: \"256Mi\", pids: {pids} }}
  instancing: per_team
  ttl: 30m
  readiness: {{ tcp: {readiness_tcp}, timeout: 30s }}
"
    )
}

/// `ctf validate` runs the same descriptor policy checks `ctf pack` does
/// (design §10), so an out-of-range port is reported here rather than only at
/// pack time.
#[test]
fn an_out_of_range_container_port_is_a_validate_error() {
    let body = runtime_doc("validate-port", 70_000, 1337, 64);
    let t = TempYaml::new("port-range", &body);
    let (ok, out, err) = validate(t.path(), &[]);
    assert!(!ok, "an out-of-range container port must fail: {out}{err}");
    assert!(err.contains("port"), "the key must be named: {err}");
    assert!(err.contains("must be between 1 and 65535"), "{err}");
}

#[test]
fn an_out_of_range_readiness_port_is_a_validate_error() {
    let body = runtime_doc("validate-readiness", 1337, 70_000, 64);
    let t = TempYaml::new("readiness-range", &body);
    let (ok, out, err) = validate(t.path(), &[]);
    assert!(!ok, "an out-of-range readiness port must fail: {out}{err}");
    assert!(err.contains("readiness.tcp"), "{err}");
    assert!(err.contains("must be between 1 and 65535"), "{err}");
}

#[test]
fn a_zero_pid_limit_is_a_validate_error() {
    let body = runtime_doc("validate-pids", 1337, 1337, 0);
    let t = TempYaml::new("pids-zero", &body);
    let (ok, out, err) = validate(t.path(), &[]);
    assert!(!ok, "a zero PID limit must fail: {out}{err}");
    assert!(err.contains("resources.pids"), "{err}");
}

#[test]
fn a_valid_runtime_document_still_exits_zero() {
    let body = runtime_doc("validate-runtime-ok", 1337, 1337, 64);
    let t = TempYaml::new("runtime-ok", &body);
    let (ok, out, err) = validate(t.path(), &[]);
    assert!(ok, "valid runtime document rejected: {out}{err}");
    assert!(out.contains("ok"), "{out}");
}

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
    // clap formats the diagnostic; the intent is that the extra argument is
    // rejected with an explanation, and nothing is validated.
    assert!(!err.is_empty(), "a usage error must explain itself");
    assert!(
        err.contains("unexpected argument"),
        "the extra argument must be rejected: {err}"
    );
}

/// Spec §13: `description` is free-form text, and the origin a diagnostic quotes
/// from it is still a terminal write. A raw ESC must appear as `\u{1b}`, not as
/// the start of a terminal escape sequence.
#[test]
fn an_escape_in_a_description_is_not_written_raw() {
    let body = "\
spec: 1
id: escape-desc
name: Escape
description: \"see http://evil\\u001b[2J.invalid/\"
";
    let t = TempYaml::new("escape-desc", body);
    let (_ok, _out, err) = validate(t.path(), &[]);
    assert!(
        !err.as_bytes().contains(&0x1b),
        "raw escape byte reached the terminal:\n{err:?}"
    );
    assert!(
        err.contains("\\u{1b}"),
        "the escape should be visible as text:\n{err}"
    );
}

/// A bidi-format mark `check_name` permits (LRM) is escaped in a description
/// diagnostic too: it can reorder the rest of the line around the origin.
#[test]
fn a_bidi_mark_in_a_description_is_not_written_raw() {
    let body = "\
spec: 1
id: bidi-desc
name: Bidi
description: \"see http://evil\\u200e.invalid/\"
";
    let t = TempYaml::new("bidi-desc", body);
    let (_ok, _out, err) = validate(t.path(), &[]);
    assert!(
        !err.contains('\u{200e}'),
        "raw bidi mark reached the terminal:\n{err:?}"
    );
    assert!(
        err.contains("\\u{200e}"),
        "the bidi mark should be visible as text:\n{err}"
    );
}

/// The escaping applies only when a character can act on the terminal: an
/// ordinary description is quoted unchanged.
#[test]
fn a_normal_description_is_printed_unchanged() {
    let body = "\
spec: 1
id: normal-desc
name: Normal
description: \"see http://example.test/asset.png\"
";
    let t = TempYaml::new("normal-desc", body);
    let (_ok, _out, err) = validate(t.path(), &[]);
    assert!(
        err.contains("http://example.test"),
        "the origin should be quoted verbatim:\n{err}"
    );
    assert!(
        !err.contains("\\u{"),
        "nothing should have been escaped:\n{err}"
    );
}
