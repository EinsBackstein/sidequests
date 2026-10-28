//! Authoring-time `external:` payloads: forensics-scale material whose bytes are
//! not in the bundle (design §10, spec §5.7, §7.4).
//!
//! Three properties matter and are tested here:
//!
//! - an `external` entry survives `pack` -> `Bundle::parse` as one `EXTERNAL`
//!   artifact section plus the manifest's `external` map, with no bytes read from
//!   disk and no bytes stored inline;
//! - every shape M18/the name rules reject is rejected at authoring time with the
//!   offending key, before a byte is written;
//! - a document that declares no `external` still packs byte-for-byte as it did
//!   before the key existed — checked against the committed minimal golden.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use ctf_format::authoring::ChallengeDoc;
use ctf_format::pack::{self, PackError};
use ctf_format::{Bundle, SectionKind};

const BASE: &str = "\
spec: 1
id: workstation
name: Workstation
";

const ROOT_A: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const ROOT_B: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

/// One well-formed external entry, prefixed form.
fn one_external(size: u64, root: &str) -> String {
    format!(
        "external:\n  - name: workstation.E01\n    size: {size}\n    root: \"blake3:{root}\"\n    mirrors: [\"https://mirror.example/workstation.E01\"]\n"
    )
}

fn parse(body: &str) -> ChallengeDoc {
    ChallengeDoc::from_yaml(&format!("{BASE}{body}"))
        .unwrap_or_else(|e| panic!("authoring YAML did not parse: {e}"))
}

fn issue_keys(doc: &ChallengeDoc) -> Vec<String> {
    doc.validate().iter().map(|i| i.key().to_owned()).collect()
}

#[test]
fn an_external_payload_packs_into_a_declared_section_and_no_bytes() {
    let doc = parse(&one_external(41_231_986_688, ROOT_A));
    assert_eq!(doc.validate(), Vec::new());
    assert_eq!(doc.external.len(), 1);
    assert_eq!(doc.external[0].name, "workstation.E01");
    assert_eq!(doc.external[0].root, [0x33; 32]);

    // `pack` must not read `workstation.E01`: it does not exist beside the test.
    let bytes = pack::pack(&doc).expect("an external payload needs no file on disk");
    let bundle = Bundle::parse(&bytes).expect("pack parses its own output");

    let name_id = bundle
        .manifest
        .names()
        .iter()
        .position(|n| *n == "workstation.E01")
        .expect("the external entry has a name-table entry") as u16;

    // The manifest's `external` map is keyed by that same `name_id`.
    let ext = bundle
        .manifest
        .external(name_id)
        .expect("the manifest carries the external metadata");
    assert_eq!(ext.size, 41_231_986_688);
    assert_eq!(ext.root, [0x33; 32]);
    assert_eq!(ext.mirrors, vec!["https://mirror.example/workstation.E01"]);

    let record = bundle
        .section(name_id)
        .expect("the external payload is a section");
    assert_eq!(record.kind, SectionKind::Artifact);
    assert!(record.flags.external(), "the record must carry EXTERNAL");
    assert!(
        record.flags.player_visible(),
        "served from a mirror, so it is player material"
    );
    assert_eq!(record.len_plain, 41_231_986_688);
    assert_eq!(record.root, [0x33; 32]);
    assert_eq!(record.len_stored, 0, "no inline bytes");
    assert_eq!(record.offset, 0, "no inline offset");
    assert!(
        bundle.section_bytes(record).is_err(),
        "an external section has no bytes in the file to serve"
    );

    // §7.4's map key set is exactly the EXTERNAL sections; the parse-back above
    // already enforced M20/M21, but assert the shape the author cares about.
    let external = bundle
        .manifest
        .value()
        .get("external")
        .and_then(|v| v.as_map())
        .expect("the manifest carries an `external` map");
    assert_eq!(external.len(), 1);
    assert_eq!(external[0].0.as_uint(), Some(u64::from(name_id)));

    // A forensics-scale commitment stays a small file.
    assert!(bytes.len() < 10_000, "the payload is not in the bundle");
}

#[test]
fn the_blake3_prefix_and_bare_hex_spell_the_same_digest() {
    // Two entries: one prefixed, one bare. Both are 32 bytes by the time the
    // document exists, which is what the manifest's `bstr` needs.
    let doc = parse(&format!(
        "external:\n\
         \x20 - name: a.E01\n\
         \x20   size: 1\n\
         \x20   root: \"blake3:{ROOT_A}\"\n\
         \x20   mirrors: [\"https://mirror.example/a.E01\"]\n\
         \x20 - name: b.E01\n\
         \x20   size: 2\n\
         \x20   root: \"{ROOT_B}\"\n\
         \x20   mirrors: [\"https://mirror.example/b.E01\"]\n"
    ));
    assert_eq!(doc.validate(), Vec::new());
    assert_eq!(doc.external[0].root, [0x33; 32]);
    assert_eq!(doc.external[1].root, [0xcd; 32]);

    let bytes = pack::pack(&doc).expect("an external-only document packs");
    let bundle = Bundle::parse(&bytes).unwrap();
    let names = bundle.manifest.names();
    for (name, root) in [("a.E01", [0x33; 32]), ("b.E01", [0xcd; 32])] {
        let id = names.iter().position(|n| *n == name).unwrap() as u16;
        assert_eq!(bundle.manifest.external(id).unwrap().root, root);
        assert!(bundle.section(id).unwrap().flags.external());
    }
}

/// A root that is not 64 lowercase hex digits (or `blake3:` plus them) is refused
/// by `from_yaml`, and the diagnostic names the entry's key.
#[test]
fn a_non_hex_root_is_refused_and_names_the_entry() {
    let err = ChallengeDoc::from_yaml(&format!("{BASE}{}", one_external(1, &"z".repeat(64))))
        .expect_err("non-hex must be refused");
    assert!(
        err.message().contains("external[0].root"),
        "the key must be named: {}",
        err.message()
    );
}

#[test]
fn a_root_of_the_wrong_length_is_refused_and_names_the_entry() {
    let err = ChallengeDoc::from_yaml(&format!("{BASE}{}", one_external(1, &"a".repeat(63))))
        .expect_err("63 hex digits must be refused");
    assert!(
        err.message().contains("external[0].root"),
        "the key must be named: {}",
        err.message()
    );

    let err = ChallengeDoc::from_yaml(&format!("{BASE}{}", one_external(1, &"a".repeat(65))))
        .expect_err("65 hex digits must be refused");
    assert!(
        err.message().contains("external[0].root"),
        "{}",
        err.message()
    );
}

#[test]
fn an_uppercase_root_is_refused() {
    let err = ChallengeDoc::from_yaml(&format!("{BASE}{}", one_external(1, &"A".repeat(64))))
        .expect_err("uppercase hex is not the authoring spelling");
    assert!(
        err.message().contains("external[0].root"),
        "{}",
        err.message()
    );
}

#[test]
fn an_empty_mirror_list_is_refused() {
    // `mirrors` is required at the schema level, so an entry without it is refused
    // before validation runs.
    assert!(
        ChallengeDoc::from_yaml(&format!("{BASE}external:\n  - name: e.E01\n    size: 1\n"))
            .is_err()
    );

    // An explicitly empty list parses and then fails validation under the key.
    let doc = ChallengeDoc::from_yaml(&format!(
        "{BASE}external:\n  - name: e.E01\n    size: 1\n    root: \"{ROOT_A}\"\n    mirrors: []\n"
    ))
    .unwrap();
    assert!(
        issue_keys(&doc).iter().any(|k| k == "external[0].mirrors"),
        "{:?}",
        issue_keys(&doc)
    );
    assert!(!doc.errors().is_empty());
}

#[test]
fn a_mirror_longer_than_2048_bytes_is_refused() {
    let long = "x".repeat(2049);
    let doc = ChallengeDoc::from_yaml(&format!(
        "{BASE}external:\n  - name: e.E01\n    size: 1\n    root: \"{ROOT_A}\"\n    mirrors: [\"{long}\"]\n"
    ))
    .unwrap();
    assert!(
        issue_keys(&doc)
            .iter()
            .any(|k| k == "external[0].mirrors[0]"),
        "{:?}",
        issue_keys(&doc)
    );

    // 2048 bytes exactly is the boundary and remains legal.
    let ok = "x".repeat(2048);
    let doc = ChallengeDoc::from_yaml(&format!(
        "{BASE}external:\n  - name: e.E01\n    size: 1\n    root: \"{ROOT_A}\"\n    mirrors: [\"{ok}\"]\n"
    ))
    .unwrap();
    assert_eq!(doc.validate(), Vec::new());
}

#[test]
fn duplicate_external_names_are_refused() {
    let doc = parse(&format!(
        "external:\n\
         \x20 - name: e.E01\n\
         \x20   size: 1\n\
         \x20   root: \"{ROOT_A}\"\n\
         \x20   mirrors: [\"https://mirror.example/e.E01\"]\n\
         \x20 - name: e.E01\n\
         \x20   size: 2\n\
         \x20   root: \"{ROOT_B}\"\n\
         \x20   mirrors: [\"https://mirror.example/e2.E01\"]\n"
    ));
    assert!(
        issue_keys(&doc).iter().any(|k| k == "external[1].name"),
        "{:?}",
        issue_keys(&doc)
    );
    assert!(matches!(pack::pack(&doc), Err(PackError::Invalid(_))));
}

#[test]
fn an_external_entry_cannot_also_be_an_artifact() {
    let doc = ChallengeDoc::from_yaml(&format!(
        "{BASE}artifacts:\n  - name: e.E01\n    source: e.E01\nexternal:\n  - name: e.E01\n    size: 1\n    root: \"{ROOT_A}\"\n    mirrors: [\"https://mirror.example/e.E01\"]\n"
    ))
    .unwrap();
    let issues = doc.validate();
    assert!(
        issues
            .iter()
            .any(|i| i.key() == "external[0].name" && i.message().contains("inline")),
        "{issues:?}"
    );
    assert!(matches!(pack::pack(&doc), Err(PackError::Invalid(_))));
}

#[test]
fn an_external_name_cannot_collide_with_any_other_assigned_name() {
    // `generate.outputs`
    let doc = ChallengeDoc::from_yaml(&format!(
        "{BASE}generate:\n  wasm: gen.wasm\n  determinism: strict\n  outputs:\n    - {{ name: e.E01, player_visible: true }}\nexternal:\n  - name: e.E01\n    size: 1\n    root: \"{ROOT_A}\"\n    mirrors: [\"https://mirror.example/e.E01\"]\n"
    ))
    .unwrap();
    assert!(
        doc.validate()
            .iter()
            .any(|i| i.key() == "external[0].name" && i.message().contains("generate.outputs")),
        "{:?}",
        doc.validate()
    );

    // `generate.wasm`
    let doc = ChallengeDoc::from_yaml(&format!(
        "{BASE}generate:\n  wasm: gen.wasm\n  determinism: strict\n  outputs:\n    - {{ name: chal, player_visible: true }}\nexternal:\n  - name: gen.wasm\n    size: 1\n    root: \"{ROOT_A}\"\n    mirrors: [\"https://mirror.example/gen.wasm\"]\n"
    ))
    .unwrap();
    assert!(
        doc.validate()
            .iter()
            .any(|i| i.key() == "external[0].name" && i.message().contains("generate.wasm")),
        "{:?}",
        doc.validate()
    );

    // `verify.solver`
    let doc = ChallengeDoc::from_yaml(&format!(
        "{BASE}verify:\n  solver: solver.wasm\n  expect: flag\n  offline: true\nexternal:\n  - name: solver.wasm\n    size: 1\n    root: \"{ROOT_A}\"\n    mirrors: [\"https://mirror.example/solver.wasm\"]\n"
    ))
    .unwrap();
    assert!(
        doc.validate()
            .iter()
            .any(|i| i.key() == "external[0].name" && i.message().contains("verify.solver")),
        "{:?}",
        doc.validate()
    );

    // `sealed.members`
    let doc = ChallengeDoc::from_yaml(&format!(
        "{BASE}sealed:\n  release: event_end\n  members: [solver.wasm]\nexternal:\n  - name: solver.wasm\n    size: 1\n    root: \"{ROOT_A}\"\n    mirrors: [\"https://mirror.example/solver.wasm\"]\n"
    ))
    .unwrap();
    assert!(
        doc.validate()
            .iter()
            .any(|i| i.key() == "external[0].name" && i.message().contains("sealed.members")),
        "{:?}",
        doc.validate()
    );
}

#[test]
fn manifest_is_not_an_external_name() {
    let doc = parse(&format!(
        "external:\n  - name: manifest\n    size: 1\n    root: \"{ROOT_A}\"\n    mirrors: [\"https://mirror.example/m\"]\n"
    ));
    assert!(
        issue_keys(&doc).iter().any(|k| k == "external[0].name"),
        "{:?}",
        issue_keys(&doc)
    );
}

/// The authoring key is additive: a document that does not use it packs exactly
/// as the committed minimal golden does.
#[test]
fn a_document_without_external_still_packs_byte_identically() {
    let doc = ChallengeDoc::from_yaml("spec: 1\nid: whos-that-bird\nname: \"Who's That Bird\"\n")
        .unwrap();
    let bytes = pack::pack(&doc).expect("the minimal document packs");
    let bundle = Bundle::parse(&bytes).unwrap();
    assert!(
        bundle.manifest.value().get("external").is_none(),
        "no `external` key may be synthesized"
    );

    let golden = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/vectors/conformance/golden/minimal.ctf");
    let golden = std::fs::read(&golden).unwrap_or_else(|e| panic!("{}: {e}", golden.display()));
    assert_eq!(
        bytes, golden,
        "one external key later, the no-external document is still byte-identical"
    );
}
