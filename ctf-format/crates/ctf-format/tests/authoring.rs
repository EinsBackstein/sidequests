//! Authoring-schema tests: strict key rejection at authoring time.
//!
//! Acceptance for ticket 32. The manifest deliberately *carries* unknown keys
//! (spec §7.3); the authoring surface is the layer that rejects the typo, because
//! a carried misspelling is a silently-wrong challenge.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use ctf_format::authoring::ChallengeDoc;

const MINIMAL: &str = "\
spec: 1
id: whos-that-bird
name: \"Who's That Bird\"
category: osint
description: \"Where was this photo taken?\"
flag: derived
";

const FULL: &str = "\
spec: 1
id: baby-rop
version: 3
name: \"Baby ROP\"
category: pwn
description: |
  markdown; may reference attachments by label
flag:
  derive: hkdf-sha256
  template: \"ctf{rop_%s}\"
  scope: team
generate:
  wasm: gen.wasm
  determinism: strict
  outputs:
    - { name: chal, player_visible: true }
    - { name: key.pem, player_visible: false }
runtime:
  image: \"ghcr.io/ctf/baby-rop@sha256:abc\"
  ports:
    - { container: 1337, protocol: tcp }
  resources: { cpu: \"0.5\", memory: \"256Mi\", pids: 64 }
  instancing: per_team
  ttl: 30m
  readiness: { tcp: 1337, timeout: 30s }
sealed:
  release: event_end
  members: [solver.wasm, writeup.md]
verify:
  solver: solver.wasm
  expect: flag
  offline: true
  live:
    interval: 5m
";

#[test]
fn parses_the_minimal_document() {
    let doc = ChallengeDoc::from_yaml(MINIMAL).unwrap();
    assert_eq!(doc.id, "whos-that-bird");
    assert_eq!(doc.spec, 1);
    assert!(matches!(
        doc.flag,
        Some(ctf_format::authoring::FlagSpec::Shorthand(_))
    ));
}

#[test]
fn parses_the_full_document() {
    let doc = ChallengeDoc::from_yaml(FULL).unwrap();
    assert_eq!(doc.id, "baby-rop");
    assert_eq!(doc.version, 3);
    let runtime = doc.runtime.as_ref().unwrap();
    assert_eq!(runtime.ports.len(), 1);
    assert_eq!(runtime.resources.pids, 64);
    let verify = doc.verify.as_ref().unwrap();
    assert_eq!(verify.live.as_ref().unwrap().interval, "5m");
}

/// A typo in an optional top-level key must fail, and the message must name it.
/// This is the `visibilty` incident design §10 describes.
#[test]
fn rejects_a_misspelled_optional_top_level_key() {
    let yaml = format!("{MINIMAL}visibilty: true\n");
    let err = ChallengeDoc::from_yaml(&yaml).unwrap_err();
    assert!(
        err.message().contains("visibilty"),
        "error must name the offending key, got: {}",
        err.message()
    );
}

/// The same rule applies inside a nested mapping, which is where the interesting
/// typos live (`runtime.imag`, `generate.determinismm`).
#[test]
fn rejects_a_typo_inside_a_nested_mapping() {
    let yaml = "\
spec: 1
id: x
name: X
runtime:
  imag: \"ghcr.io/x@sha256:abc\"
  ports: []
  resources: { cpu: \"1\", memory: \"1Gi\", pids: 1 }
  instancing: shared
  ttl: 1m
  readiness: { tcp: 1, timeout: 1s }
";
    let err = ChallengeDoc::from_yaml(yaml).unwrap_err();
    assert!(
        err.message().contains("imag"),
        "error must name the offending key, got: {}",
        err.message()
    );
}

/// `flag:` accepts a scalar or a mapping without an anonymous "no variant matched"
/// error, and a typo inside the mapping still names the key.
#[test]
fn rejects_a_typo_inside_the_flag_mapping() {
    let yaml = "\
spec: 1
id: x
name: X
flag:
  deriv: hkdf-sha256
";
    let err = ChallengeDoc::from_yaml(yaml).unwrap_err();
    assert!(
        err.message().contains("deriv"),
        "error must name the offending key, got: {}",
        err.message()
    );
}

#[test]
fn rejects_an_unknown_key_in_a_generate_output_entry() {
    let yaml = "\
spec: 1
id: x
name: X
generate:
  wasm: gen.wasm
  determinism: strict
  outputs:
    - { name: chal, player_visable: true }
";
    let err = ChallengeDoc::from_yaml(yaml).unwrap_err();
    assert!(
        err.message().contains("player_visable"),
        "error must name the offending key, got: {}",
        err.message()
    );
}

/// `spec` is required: a document without it is not a document.
#[test]
fn rejects_a_missing_required_key() {
    let err = ChallengeDoc::from_yaml("id: x\nname: X\n").unwrap_err();
    assert!(
        err.message().contains("spec"),
        "error must name the missing key, got: {}",
        err.message()
    );
}

/// A schema newer than this build's is refused rather than guessed at.
#[test]
fn rejects_a_newer_authoring_spec() {
    let err = ChallengeDoc::from_yaml("spec: 99\nid: x\nname: X\n").unwrap_err();
    assert!(err.message().contains("99"));
}

/// DF5: a stage gate on a **derived** flag is legal — the 80-bit derived flag is an
/// acceptable stage key.
#[test]
fn a_stage_gate_on_a_derived_flag_is_accepted() {
    let yaml = "\
spec: 1
id: staged
name: Staged
flag:
  derive: hkdf-sha256
  stage_gate: true
";
    let doc = ChallengeDoc::from_yaml(yaml).unwrap();
    assert!(doc.validate().is_empty(), "{:?}", doc.validate());
}

/// DF5: a stage gate on a **static** flag is rejected, and the rejection says why —
/// a stage key derives from the previous stage's flag, so a guessable string is not
/// a key.
#[test]
fn a_stage_gate_on_a_static_flag_is_rejected_and_explains() {
    let yaml = "\
spec: 1
id: staged
name: Staged
flag:
  derive: static
  stage_gate: true
";
    let doc = ChallengeDoc::from_yaml(yaml).unwrap();
    let issues = doc.validate();
    let issue = issues
        .iter()
        .find(|i| i.key() == "flag.stage_gate")
        .unwrap_or_else(|| panic!("expected a flag.stage_gate finding, got {issues:?}"));
    assert!(
        issue.message().contains("derived"),
        "the finding must explain why a static flag cannot key a gate: {}",
        issue.message()
    );
}

/// The declaration is carried into the manifest as an ordinary `flag` sub-key, so a
/// platform can read it and a reader carries it.
#[test]
fn a_stage_gate_round_trips_into_the_manifest() {
    let yaml = "\
spec: 1
id: staged
name: Staged
flag:
  derive: hkdf-sha256
  stage_gate: true
";
    let doc = ChallengeDoc::from_yaml(yaml).unwrap();
    let entries = doc.manifest_entries();
    let flag = entries
        .iter()
        .find(|(k, _)| k.as_text() == Some("flag"))
        .map(|(_, v)| v)
        .unwrap();
    let entries = flag.as_map().unwrap();
    assert!(entries.iter().any(
        |(k, v)| k.as_text() == Some("stage_gate") && *v == ctf_format::cbor::Value::Bool(true)
    ));
}
