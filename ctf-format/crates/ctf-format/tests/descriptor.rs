//! The platform ingest descriptor (ticket 60): packing produces a descriptor that
//! maps onto the platform's challenge and runtime records.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use ctf_format::authoring::ChallengeDoc;
use ctf_format::descriptor::DEFAULT_PLATFORM_NAMESPACE;
use ctf_format::pack;

const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn pwn_doc() -> ChallengeDoc {
    let yaml = format!(
        r#"
spec: 1
id: baby-rop
version: 3
name: "Baby ROP"
category: pwn
description: "a pwn challenge"
platform:
  level: 2
  storage_size: 10737418240
  read_only: true
runtime:
  image: "ghcr.io/ctf/baby-rop@{DIGEST}"
  ports: [{{ container: 1337, protocol: tcp }}]
  resources: {{ cpu: "0.5", memory: "256Mi", pids: 64 }}
  instancing: per_team
  ttl: 30m
  readiness: {{ tcp: 1337, timeout: 30s }}
"#
    );
    ChallengeDoc::from_yaml(&yaml).unwrap()
}

#[test]
fn the_descriptor_carries_every_platform_field() {
    let doc = pwn_doc();
    let descriptor = pack::descriptor_for(&doc).unwrap();
    assert_eq!(descriptor.slug, "baby-rop");
    assert_eq!(descriptor.name, "Baby ROP");
    assert_eq!(descriptor.category.as_deref(), Some("pwn"));
    assert_eq!(descriptor.version, 3);
    assert_eq!(descriptor.level, Some(2));
    assert_eq!(
        descriptor.image.as_deref(),
        Some(format!("ghcr.io/ctf/baby-rop@{DIGEST}").as_str())
    );
    assert_eq!(descriptor.port, Some(1337));
    assert_eq!(descriptor.storage_size, Some(10_737_418_240));
    assert_eq!(descriptor.read_only, Some(true));
    assert_eq!(descriptor.ttl.as_deref(), Some("30m"));
    let resources = descriptor.resources.as_ref().unwrap();
    assert_eq!(resources.cpu, "0.5");
    assert_eq!(resources.memory, "256Mi");
    assert_eq!(resources.pids, 64);
    let readiness = descriptor.readiness.as_ref().unwrap();
    assert_eq!(readiness.tcp, 1337);
    assert_eq!(readiness.timeout, "30s");
    assert_eq!(descriptor.referrer_policy, "no-referrer");
    assert!(descriptor.validate().is_empty());
}

#[test]
fn the_descriptor_serializes_to_json_the_platform_reads() {
    let doc = pwn_doc();
    let descriptor = pack::descriptor_for(&doc).unwrap();
    let json = descriptor.to_json().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["slug"], "baby-rop");
    assert_eq!(parsed["level"], 2);
    assert_eq!(parsed["port"], 1337);
    assert_eq!(parsed["referrer_policy"], "no-referrer");
    assert_eq!(parsed["resources"]["memory"], "256Mi");
}

/// A manifest-only OSINT challenge still yields a descriptor: only `slug`, `name`,
/// `version`, and the referrer policy are present, and no absent field is emitted as
/// `null`.
#[test]
fn a_minimal_challenge_yields_a_minimal_descriptor() {
    let doc = ChallengeDoc::from_yaml(
        r#"
spec: 1
id: whos-that-bird
name: "Who's That Bird"
category: osint
"#,
    )
    .unwrap();
    let descriptor = pack::descriptor_for(&doc).unwrap();
    assert_eq!(descriptor.slug, "whos-that-bird");
    assert!(descriptor.image.is_none());
    assert!(descriptor.level.is_none());
    let json = descriptor.to_json().unwrap();
    assert!(!json.contains("null"));
    assert_eq!(DEFAULT_PLATFORM_NAMESPACE, "org.flagfrenzy");
}

/// A negative overlay level is a CBOR major-type-1 integer; the descriptor reads it
/// exactly, including `i64::MIN`, which `-1 - n` must not overflow into.
#[test]
fn a_negative_level_is_read_from_the_overlay() {
    for (nint, want) in [(0u64, -1i64), (4, -5), (i64::MAX as u64, i64::MIN)] {
        let manifest = ctf_format::Manifest::build(
            "neg",
            "Neg",
            &["manifest"],
            vec![(
                ctf_format::cbor::Value::Text("platform".into()),
                ctf_format::cbor::Value::Map(vec![(
                    ctf_format::cbor::Value::Text("org.flagfrenzy".into()),
                    ctf_format::cbor::Value::Map(vec![(
                        ctf_format::cbor::Value::Text("level".into()),
                        ctf_format::cbor::Value::Nint(nint),
                    )]),
                )]),
            )],
        )
        .unwrap();
        let descriptor = ctf_format::PlatformDescriptor::from_manifest(&manifest, "org.flagfrenzy");
        assert_eq!(descriptor.level, Some(want));
    }
}

#[test]
fn a_custom_namespace_is_honored() {
    let doc = ChallengeDoc::from_yaml(
        r#"
spec: 1
id: custom-ns
name: "Custom"
platform:
  namespace: example.org
  level: 7
"#,
    )
    .unwrap();
    let manifest = pack::manifest_for(&doc).unwrap();
    let descriptor = ctf_format::PlatformDescriptor::from_manifest(&manifest, "example.org");
    assert_eq!(descriptor.level, Some(7));
    let other = ctf_format::PlatformDescriptor::from_manifest(&manifest, "other.example");
    assert_eq!(other.level, None);
}
