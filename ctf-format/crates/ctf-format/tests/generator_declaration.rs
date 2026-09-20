//! The `generate` declaration: determinism modes, the output-to-`names` mapping,
//! and the interface/profile versions (tickets 24, 25; spec §7.6, §23).
//!
//! The mapping and the mode pairing are the *authoring tool's* rules, not the
//! container reader's: the reader carries the declaration without acting on it
//! (§7.6). These tests drive `ChallengeDoc::validate` and `pack`, which are where
//! an author's mistake is supposed to surface.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use ctf_format::Manifest;
use ctf_format::authoring::ChallengeDoc;
use ctf_format::pack;

const BASE: &str = "\
spec: 1
id: baby-rop
name: Baby ROP
";

fn doc(body: &str) -> ChallengeDoc {
    ChallengeDoc::from_yaml(&format!("{BASE}{body}")).unwrap()
}

fn issue_keys(doc: &ChallengeDoc) -> Vec<String> {
    doc.validate().iter().map(|i| i.key().to_owned()).collect()
}

#[test]
fn flag_only_needs_no_wasm_or_outputs() {
    let doc = doc("\
flag: derived
generate:
  determinism: flag_only
");
    assert_eq!(doc.validate(), Vec::new());

    // It packs, and the manifest carries the flag-only declaration with neither
    // `wasm` nor `outputs`.
    let bundle = pack::pack(&doc).unwrap();
    let parsed = ctf_format::Bundle::parse(&bundle).unwrap();
    let generate = parsed
        .manifest
        .declaration("generate")
        .expect("generate is carried");
    assert!(generate.get("wasm").is_none());
    assert!(generate.get("outputs").is_none());
    assert_eq!(
        generate.get("determinism").and_then(|v| v.as_text()),
        Some("flag_only")
    );
}

#[test]
fn flag_only_rejects_a_generator() {
    let doc = doc("\
generate:
  determinism: flag_only
  wasm: gen.wasm
");
    let keys = issue_keys(&doc);
    assert!(keys.contains(&"generate.wasm".to_owned()), "{keys:?}");
}

#[test]
fn strict_requires_a_generator() {
    let doc = doc("\
generate:
  determinism: strict
");
    let keys = issue_keys(&doc);
    assert!(keys.contains(&"generate.wasm".to_owned()), "{keys:?}");
}

#[test]
fn strict_with_outputs_maps_every_output_into_the_name_table() {
    let doc = doc("\
flag: derived
generate:
  wasm: gen.wasm
  determinism: strict
  outputs:
    - { name: chal, player_visible: true }
    - { name: key.pem, player_visible: false }
");
    assert_eq!(doc.validate(), Vec::new());

    let names = pack::names_for(&doc);
    assert!(names.contains(&"chal".to_owned()));
    assert!(names.contains(&"key.pem".to_owned()));

    let manifest: Manifest = pack::manifest_for(&doc).unwrap();
    for output in ["chal", "key.pem"] {
        assert!(
            manifest.names().contains(&output),
            "output `{output}` has no name-table entry"
        );
    }
}

#[test]
fn a_zero_interface_or_profile_is_rejected() {
    for (yaml_key, issue_key) in [
        ("interface", "generate.interface"),
        ("profile", "generate.profile"),
    ] {
        let doc = doc(&format!(
            "\
generate:
  wasm: gen.wasm
  determinism: strict
  {yaml_key}: 0
"
        ));
        let keys = issue_keys(&doc);
        assert!(
            keys.contains(&issue_key.to_owned()),
            "{issue_key}: {keys:?}"
        );
    }
}

#[test]
fn a_higher_interface_version_is_carried_not_rejected() {
    // Forward compatibility is the host's decision (G6), not the authoring tool's:
    // an author may target a newer interface and let the host refuse to run it.
    let doc = doc("\
generate:
  wasm: gen.wasm
  determinism: strict
  interface: 2
  profile: 3
");
    assert_eq!(doc.validate(), Vec::new());
}
