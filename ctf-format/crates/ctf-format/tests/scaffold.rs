//! Archetype scaffold tests: `ctf init <archetype>` must start an author from a
//! document that parses and validates. Acceptance for ticket 26.
//!
//! The library does not re-parse its own output, so these tests are the contract
//! that a scaffold stays packable: every generated `challenge.yaml` is run
//! through the same `ChallengeDoc::from_yaml` + `validate` a `ctf pack` would.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use ctf_format::authoring::ChallengeDoc;
use ctf_format::scaffold::{ARCHETYPES, ScaffoldError, ScaffoldFile, scaffold};

const ID: &str = "my-challenge";

fn challenge_yaml(files: &[ScaffoldFile]) -> &str {
    files
        .iter()
        .find(|f| f.path == "challenge.yaml")
        .map(|f| f.contents.as_str())
        .expect("every scaffold emits challenge.yaml")
}

#[test]
fn every_archetype_scaffolds_for_a_valid_id() {
    for &archetype in ARCHETYPES {
        let files = scaffold(archetype, ID).unwrap();
        assert!(!files.is_empty(), "{archetype} produced no files");
        let doc = ChallengeDoc::from_yaml(challenge_yaml(&files)).unwrap();
        assert_eq!(doc.id, ID);
        assert_eq!(doc.spec, 1);
    }
}

#[test]
fn every_generated_yaml_parses_and_validates_with_zero_issues() {
    for &archetype in ARCHETYPES {
        let files = scaffold(archetype, ID).unwrap();
        let yaml = challenge_yaml(&files);
        let doc = ChallengeDoc::from_yaml(yaml)
            .unwrap_or_else(|e| panic!("{archetype} did not parse: {e}"));
        let issues = doc.validate();
        assert!(issues.is_empty(), "{archetype} produced issues: {issues:?}");
    }
}

#[test]
fn an_unknown_archetype_is_rejected() {
    assert_eq!(
        scaffold("nope", "x"),
        Err(ScaffoldError::UnknownArchetype("nope".to_owned()))
    );
}

#[test]
fn an_invalid_id_is_rejected() {
    assert_eq!(
        scaffold("osint", "Not_Valid"),
        Err(ScaffoldError::InvalidId)
    );
}

#[test]
fn osint_has_no_generator_and_no_generate_key() {
    let files = scaffold("osint", ID).unwrap();
    assert!(
        files.iter().all(|f| !f.path.starts_with("generator/")),
        "osint must not emit a generator directory"
    );
    let doc = ChallengeDoc::from_yaml(challenge_yaml(&files)).unwrap();
    assert!(doc.generate.is_none(), "osint must not declare `generate`");
    assert!(doc.runtime.is_none(), "osint must not declare `runtime`");
}

#[test]
fn rev_declares_a_strict_generator() {
    let files = scaffold("rev", ID).unwrap();
    let doc = ChallengeDoc::from_yaml(challenge_yaml(&files)).unwrap();
    let generate = doc.generate.as_ref().expect("rev declares `generate`");
    assert_eq!(generate.determinism, "strict");
    assert_eq!(generate.wasm.as_deref(), Some("gen.wasm"));
}

#[test]
fn rev_emits_a_generator_that_names_the_abi() {
    let files = scaffold("rev", ID).unwrap();
    let source = files
        .iter()
        .find(|f| f.path == "generator/src/lib.rs")
        .expect("rev emits a generator source");
    for export in ["ctf_alloc", "ctf_generate", "ctf_output_len"] {
        assert!(
            source.contents.contains(export),
            "generator source must reference `{export}`"
        );
    }
    let build = files
        .iter()
        .find(|f| f.path == "generator/README.md")
        .expect("rev emits a generator README");
    let command = "cargo build --target wasm32-unknown-unknown --release";
    assert!(
        build.contents.contains(command),
        "generator README must carry the exact build command"
    );
}

#[test]
fn a_sealed_member_is_never_player_visible() {
    for archetype in ["rev", "pwn", "web"] {
        let files = scaffold(archetype, ID).unwrap();
        let doc = ChallengeDoc::from_yaml(challenge_yaml(&files)).unwrap();
        let sealed = doc.sealed.as_ref().expect("archetype declares `sealed`");
        if let Some(generate) = &doc.generate {
            for member in &sealed.members {
                assert!(
                    !generate
                        .outputs
                        .iter()
                        .any(|o| &o.name == member && o.player_visible),
                    "{archetype}: `{member}` is both sealed and player-visible"
                );
            }
        }
    }
}

#[test]
fn runtime_archetypes_pin_a_digest() {
    for archetype in ["pwn", "web"] {
        let files = scaffold(archetype, ID).unwrap();
        let doc = ChallengeDoc::from_yaml(challenge_yaml(&files)).unwrap();
        let runtime = doc.runtime.as_ref().expect("archetype declares `runtime`");
        assert!(
            runtime.image.contains("@sha256:"),
            "{archetype}: image must be digest-pinned"
        );
    }
}

#[test]
fn web_declares_a_live_gate_and_pwn_verifies_offline() {
    let web = scaffold("web", ID).unwrap();
    let web_doc = ChallengeDoc::from_yaml(challenge_yaml(&web)).unwrap();
    let web_verify = web_doc.verify.as_ref().expect("web declares `verify`");
    assert!(!web_verify.offline);
    assert_eq!(
        web_verify
            .live
            .as_ref()
            .expect("web declares `live`")
            .interval,
        "5m"
    );

    let pwn = scaffold("pwn", ID).unwrap();
    let pwn_doc = ChallengeDoc::from_yaml(challenge_yaml(&pwn)).unwrap();
    let pwn_verify = pwn_doc.verify.as_ref().expect("pwn declares `verify`");
    assert!(pwn_verify.offline);
    assert!(pwn_verify.live.is_none());
}

#[test]
fn forensics_has_notes_and_no_external_key() {
    // `ChallengeDoc` has no `external` field (authoring.rs), and `from_yaml`
    // rejects unknown keys, so the scaffold must not emit an `external:` key.
    let files = scaffold("forensics", ID).unwrap();
    assert!(files.iter().any(|f| f.path == "notes.md"));
    let yaml = challenge_yaml(&files);
    assert!(
        !yaml.contains("external:"),
        "`external` is not authoring YAML"
    );
    let doc = ChallengeDoc::from_yaml(yaml).unwrap();
    assert!(doc.validate().is_empty());
}

#[test]
fn scaffolding_is_deterministic() {
    for &archetype in ARCHETYPES {
        assert_eq!(scaffold(archetype, ID), scaffold(archetype, ID));
    }
}
