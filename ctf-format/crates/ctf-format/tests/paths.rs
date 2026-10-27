//! Authoring-time `paths`: the directory tree of spec §7.2 (ticket 88).
//!
//! The format-side key and its M22–M25 rules landed in 0.9.0; this is the
//! authoring front end. Three properties matter and are tested here:
//!
//! - a nested path survives `pack` -> `Bundle::parse` -> `Manifest::path_of`, and
//!   the section bytes are the file the author named;
//! - every shape the manifest rejects is rejected at authoring time with the
//!   offending key, before a byte is written;
//! - a document that declares no path packs byte-for-byte as it did before the
//!   key existed. The tree is a new feature, never a new spelling of an old file.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::path::PathBuf;

use ctf_format::authoring::ChallengeDoc;
use ctf_format::pack::{self, PackError};
use ctf_format::{Bundle, SectionKind};

/// A scratch directory, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("ctf-paths-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }

    fn write(&self, relative: &str, bytes: &[u8]) {
        let p = self.0.join(relative);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(p, bytes).unwrap();
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const BASE: &str = "\
spec: 1
id: source-tree
name: Source Tree
";

fn doc_with_artifacts(artifacts: &str) -> ChallengeDoc {
    ChallengeDoc::from_yaml(&format!("{BASE}artifacts:{artifacts}")).unwrap()
}

#[test]
fn nested_artifact_path_round_trips_through_pack() {
    let dir = TempDir::new("round-trip");
    let payload = b"int main(void) { return 0; }\n";
    dir.write("assets/main.c", payload);
    dir.write("assets/README.txt", b"build it\n");

    let doc = doc_with_artifacts(
        "
  - name: README.txt
    source: assets/README.txt
  - name: main.c
    source: assets/main.c
    path: src/main.c
",
    );
    assert_eq!(doc.validate(), Vec::new());

    let bytes = pack::pack_with_root(&doc, pack::DEFAULT_SUITE_ID, &dir.0).unwrap();
    let bundle = Bundle::parse(&bytes).unwrap();

    let name_id = bundle
        .manifest
        .names()
        .iter()
        .position(|n| *n == "main.c")
        .expect("the artifact has a name-table entry") as u16;
    assert_eq!(
        bundle.manifest.path_of(name_id),
        Some("src/main.c"),
        "the manifest must carry the tree path, not the flat name"
    );

    // The flat artifact in the same document keeps its name and gets no entry: the
    // omission is per artifact, not an all-or-nothing choice for the document.
    let flat_id = bundle
        .manifest
        .names()
        .iter()
        .position(|n| *n == "README.txt")
        .expect("the flat artifact has a name-table entry") as u16;
    assert_eq!(bundle.manifest.path_of(flat_id), None);
    let paths = bundle
        .manifest
        .value()
        .get("paths")
        .and_then(|v| v.as_map())
        .expect("the tree is present");
    assert_eq!(paths.len(), 1, "only the non-identity path is emitted");

    let record = bundle.section(name_id).expect("the artifact is a section");
    assert_eq!(record.kind, SectionKind::Artifact);
    assert_eq!(bundle.section_bytes(record).unwrap().as_ref(), payload);

    // A writer that relies on the tree names it in `crit` (§7.2), so a reader that
    // does not implement `paths` refuses rather than unpacking flat.
    let crit = bundle
        .manifest
        .value()
        .get("crit")
        .and_then(|v| v.as_array())
        .expect("`paths` is declared critical");
    assert!(crit.iter().any(|v| v.as_text() == Some("paths")));
}

#[test]
fn a_traversing_or_malformed_path_is_rejected_at_pack_time() {
    // `yaml` is the literal that follows `path:`; `label` names the case in the
    // failure message. Every one of these is a shape §7.2 makes unrepresentable.
    let cases = [
        ("traversal", "\"../escape\""),
        ("nested traversal", "\"src/../main.c\""),
        ("absolute", "\"/etc/passwd\""),
        ("double slash", "\"src//main.c\""),
        ("trailing slash", "\"src/\""),
        ("backslash", "\"src\\\\main.c\""),
        ("dot", "\".\""),
        ("dot dot", "\"..\""),
        ("bidi override", "\"src/\u{202e}main.c\""),
        ("control byte", "\"src/\\x07main.c\""),
    ];

    for (label, path) in cases {
        let doc = doc_with_artifacts(&format!(
            "
  - name: main.c
    source: main.c
    path: {path}
"
        ));
        let err = pack::pack(&doc).expect_err(label);
        let PackError::Invalid(issues) = err else {
            panic!("{label}: expected an authoring error, got {err:?}");
        };
        let issue = issues
            .iter()
            .find(|i| i.key() == "artifacts[0].path")
            .unwrap_or_else(|| panic!("{label}: no `artifacts[0].path` issue in {issues:?}"));
        assert!(
            issue.message().contains("relative POSIX"),
            "{label}: the error must state the rule: {issue}"
        );
    }
}

#[test]
fn duplicate_destinations_are_rejected_at_pack_time() {
    // Two declared paths that are the same file.
    let doc = doc_with_artifacts(
        "
  - { name: main.c, source: a, path: src/main.c }
  - { name: util.c, source: b, path: src/main.c }
",
    );
    let err = pack::pack(&doc).expect_err("two sections cannot extract to one file");
    let PackError::Invalid(issues) = err else {
        panic!("expected an authoring error, got {err:?}");
    };
    let issue = issues
        .iter()
        .find(|i| i.key() == "artifacts[1].path")
        .expect("the second declaration is the one to fix");
    assert!(
        issue.message().contains("artifacts[0]"),
        "the error must name the other declaration: {issue}"
    );

    // A declared path cannot collide with a section that has no path either: that
    // section extracts under its flat name (spec §7.2).
    let doc = doc_with_artifacts(
        "
  - { name: main.c, source: a }
  - { name: util.c, source: b, path: main.c }
",
    );
    let err = pack::pack(&doc).expect_err("a path may not overwrite a flat name");
    let PackError::Invalid(issues) = err else {
        panic!("expected an authoring error, got {err:?}");
    };
    assert!(
        issues
            .iter()
            .any(|i| i.key() == "artifacts[1].path" && i.message().contains("artifacts[0]")),
        "{issues:?}"
    );
}

#[test]
fn a_path_that_takes_another_sections_name_is_rejected() {
    // A generator output is a section in the bundle a generator produces, so a
    // declared path may not take its flat name (spec §7.8).
    let doc = ChallengeDoc::from_yaml(
        "\
spec: 1
id: tree-vs-output
name: Tree vs Output
generate:
  wasm: gen.wasm
  determinism: strict
  outputs:
    - { name: out.bin, player_visible: true }
artifacts:
  - { name: notes, source: notes.txt, path: out.bin }
",
    )
    .unwrap();
    let err = pack::pack(&doc).expect_err("a path may not take a generator output's name");
    let PackError::Invalid(issues) = err else {
        panic!("expected an authoring error, got {err:?}");
    };
    assert!(
        issues
            .iter()
            .any(|i| i.key() == "artifacts[0].path" && i.message().contains("generate.outputs[0]")),
        "the error must name the output it collides with: {issues:?}"
    );

    // The manifest section's flat name is a destination too.
    let doc = doc_with_artifacts(
        "
  - { name: notes, source: notes.txt, path: manifest }
",
    );
    let err = pack::pack(&doc).expect_err("a path may not take the manifest's name");
    let PackError::Invalid(issues) = err else {
        panic!("expected an authoring error, got {err:?}");
    };
    assert!(
        issues
            .iter()
            .any(|i| i.key() == "artifacts[0].path" && i.message().contains("manifest section")),
        "{issues:?}"
    );
}

#[test]
fn two_declared_sections_cannot_claim_one_destination() {
    // §7.8 compares the manifest, every artifact, and every generator output. An
    // output named `manifest` would otherwise be assigned `name_id` 0, the
    // manifest's own identity. (`sealed.members`/`verify.solver` name a section
    // rather than declaring one, so they are not destinations.)
    let doc = ChallengeDoc::from_yaml(
        "\
spec: 1
id: output-takes-manifest
name: Output Takes Manifest
generate:
  wasm: gen.wasm
  determinism: strict
  outputs:
    - { name: manifest, player_visible: true }
",
    )
    .unwrap();
    let err = pack::pack(&doc).expect_err("a generated output may not take the manifest's name");
    let PackError::Invalid(issues) = err else {
        panic!("expected an authoring error, got {err:?}");
    };
    assert!(
        issues
            .iter()
            .any(|i| i.key() == "generate.outputs[0].name"
                && i.message().contains("manifest section")),
        "the error must name the manifest it collides with: {issues:?}"
    );
}

#[test]
fn an_identity_path_is_not_emitted() {
    let dir = TempDir::new("identity");
    dir.write("readme.txt", b"hello\n");

    let doc = doc_with_artifacts(
        "
  - { name: readme.txt, source: readme.txt, path: readme.txt }
",
    );
    assert_eq!(doc.validate(), Vec::new());

    let bytes = pack::pack_with_root(&doc, pack::DEFAULT_SUITE_ID, &dir.0).unwrap();
    let bundle = Bundle::parse(&bytes).unwrap();
    assert!(
        bundle.manifest.value().get("paths").is_none(),
        "an identity map restates `names` and must not be emitted"
    );
    assert!(bundle.manifest.value().get("crit").is_none());
    assert_eq!(bundle.manifest.path_of(1), None);
}

#[test]
fn a_document_without_paths_packs_byte_identically() {
    // The doc from `ctf-cli/tests/pack.rs`'s minimal challenge, pinned by BLAKE3.
    // The constant was recorded from the 0.12.0 writer *before* `paths` was wired;
    // a change here means a document with no artifacts no longer packs to the same
    // bytes, which is a format-stability regression even though no rule changed.
    let doc = ChallengeDoc::from_yaml(
        "\
spec: 1
id: whos-that-bird
name: \"Who's That Bird\"
category: osint
description: \"Where was this photo taken?\"
flag: derived
",
    )
    .unwrap();
    assert_eq!(doc.validate(), Vec::new());

    let bytes = pack::pack(&doc).unwrap();
    assert_eq!(
        blake3::hash(&bytes).to_hex().to_string(),
        "d40a29c25d59e94d4479b18836bf28c2c6de0d77686be099cea756a778824423"
    );
    let bundle = Bundle::parse(&bytes).unwrap();
    assert!(bundle.manifest.value().get("paths").is_none());
    assert!(bundle.manifest.value().get("crit").is_none());
}

#[test]
fn an_unknown_key_inside_an_artifact_is_rejected() {
    // §7.8's typo guard reaches one level deeper than the top-level document.
    let err = ChallengeDoc::from_yaml(&format!(
        "{BASE}artifacts:\n  - {{ name: main.c, source: main.c, dest: src/main.c }}\n"
    ))
    .expect_err("`dest` is not an authoring key");
    assert!(err.to_string().contains("dest"), "{err}");
}
