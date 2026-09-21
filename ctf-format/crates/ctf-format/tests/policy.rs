//! Platform policy: digest-pinned images (ticket 61) and third-party origins
//! (ticket 68).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ctf_format::authoring::ChallengeDoc;
use ctf_format::manifest::Manifest;
use ctf_format::policy::{self, ImageRefError};

const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[test]
fn a_digest_pinned_image_is_accepted() {
    assert!(policy::check_image_ref(&format!("ghcr.io/ctf/baby-rop@{DIGEST}")).is_ok());
    // A registry port is part of the host, not a tag.
    assert!(policy::check_image_ref(&format!("localhost:5000/baby-rop@{DIGEST}")).is_ok());
}

#[test]
fn a_tag_is_rejected() {
    assert_eq!(
        policy::check_image_ref("ghcr.io/ctf/baby-rop:latest"),
        Err(ImageRefError::MissingDigest)
    );
    assert_eq!(
        policy::check_image_ref(&format!("ghcr.io/ctf/baby-rop:1.2@{DIGEST}")),
        Err(ImageRefError::Tagged)
    );
}

#[test]
fn a_malformed_digest_is_rejected() {
    assert_eq!(
        policy::check_image_ref("ghcr.io/ctf/baby-rop@sha256:00ff"),
        Err(ImageRefError::BadDigest)
    );
    assert_eq!(
        policy::check_image_ref("ghcr.io/ctf/baby-rop@sha512:00ff"),
        Err(ImageRefError::MissingDigest)
    );
    assert_eq!(policy::check_image_ref(""), Err(ImageRefError::Empty));
}

#[test]
fn relative_references_produce_no_origin() {
    assert!(policy::third_party_origins("see assets/logo.png and [x](docs/a.md)").is_empty());
}

#[test]
fn absolute_urls_are_reported_once_per_origin() {
    let origins = policy::third_party_origins(
        "![a](https://evil.example/a.png) ![b](https://evil.example/b.png) http://other.example/x",
    );
    assert_eq!(
        origins,
        vec!["https://evil.example", "http://other.example"]
    );
}

/// The authoring surface enforces digest pinning at authoring time (ticket 61) and
/// warns — without blocking — about a third-party origin (ticket 68).
#[test]
fn authoring_enforces_digest_pinning_and_warns_about_origins() {
    let bad_image = r#"
spec: 1
id: baby-rop
name: "Baby ROP"
category: pwn
description: "see https://evil.example/asset.png"
runtime:
  image: "ghcr.io/ctf/baby-rop:latest"
  ports: [{ container: 1337, protocol: tcp }]
  resources: { cpu: "0.5", memory: "256Mi", pids: 64 }
  instancing: per_team
  ttl: 30m
  readiness: { tcp: 1337, timeout: 30s }
"#;
    let doc = ChallengeDoc::from_yaml(bad_image).unwrap();
    let errors = doc.errors();
    assert!(
        errors.iter().any(|i| i.key() == "runtime.image"),
        "a tag must be an authoring error"
    );
    let warnings = doc.warnings();
    assert!(
        warnings.iter().any(|i| i.key() == "description"),
        "a third-party origin must be a warning"
    );
}

/// The read-time policy pass reaches the same conclusion from a parsed manifest, so
/// authoring time and read time cannot drift.
#[test]
fn the_manifest_policy_check_flags_a_tagged_image() {
    let manifest = Manifest::build(
        "baby-rop",
        "Baby ROP",
        &["manifest"],
        vec![(
            ctf_format::cbor::Value::Text("runtime".into()),
            ctf_format::cbor::Value::Map(vec![(
                ctf_format::cbor::Value::Text("image".into()),
                ctf_format::cbor::Value::Text("ghcr.io/ctf/baby-rop:latest".into()),
            )]),
        )],
    )
    .unwrap();
    let issues = policy::check_manifest(&manifest);
    assert!(
        issues.iter().any(|i| i.key() == policy::RUNTIME_IMAGE_KEY),
        "read-time policy must flag a tagged image"
    );
}
