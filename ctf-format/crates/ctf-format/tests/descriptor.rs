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

fn runtime_doc(tag: &str, port: u64, readiness_tcp: u64) -> ChallengeDoc {
    let yaml = format!(
        r#"
spec: 1
id: {tag}
name: "Runtime"
runtime:
  image: "ghcr.io/ctf/{tag}@{DIGEST}"
  ports: [{{ container: {port}, protocol: tcp }}]
  resources: {{ cpu: "0.5", memory: "256Mi", pids: 64 }}
  instancing: per_team
  ttl: 30m
  readiness: {{ tcp: {readiness_tcp}, timeout: 30s }}
"#
    );
    ChallengeDoc::from_yaml(&yaml).unwrap()
}

/// §29.1: the descriptor is projected from the committed manifest. A port the
/// descriptor's `u16` cannot represent must stay visible to `validate` instead of
/// being silently dropped, so the pack fails rather than emitting a descriptor that
/// disagrees with the bundle.
#[test]
fn an_out_of_range_container_port_fails_the_pack() {
    let doc = runtime_doc("big-port", 70_000, 80);
    match pack::pack(&doc) {
        Err(ctf_format::pack::PackError::Policy(issues)) => {
            assert_eq!(issues.len(), 1);
            assert_eq!(issues[0].key(), "port");
            assert_eq!(issues[0].message(), "must be between 1 and 65535");
        }
        other => panic!("expected a policy refusal, got {other:?}"),
    }
}

#[test]
fn an_out_of_range_readiness_port_fails_the_pack() {
    let doc = runtime_doc("big-readiness", 80, 70_000);
    match pack::pack(&doc) {
        Err(ctf_format::pack::PackError::Policy(issues)) => {
            assert_eq!(issues.len(), 1);
            assert_eq!(issues[0].key(), "readiness.tcp");
            assert_eq!(issues[0].message(), "must be between 1 and 65535");
        }
        other => panic!("expected a policy refusal, got {other:?}"),
    }
}

/// The same projection still carries a representable port exactly, and a manifest
/// with no runtime still omits `port`/`readiness` rather than inventing them.
#[test]
fn a_representable_port_projects_and_no_runtime_omits_both() {
    let doc = runtime_doc("ok-port", 1337, 1337);
    let descriptor = pack::descriptor_for(&doc).unwrap();
    assert_eq!(descriptor.port, Some(1337));
    assert_eq!(descriptor.readiness.as_ref().unwrap().tcp, 1337);
    assert!(descriptor.validate().is_empty());

    let minimal = ChallengeDoc::from_yaml("spec: 1\nid: no-runtime\nname: No Runtime\n").unwrap();
    let descriptor = pack::descriptor_for(&minimal).unwrap();
    assert!(descriptor.port.is_none());
    assert!(descriptor.readiness.is_none());
    let json = descriptor.to_json().unwrap();
    assert!(!json.contains("\"port\""), "{json}");
    assert!(!json.contains("\"readiness\""), "{json}");
}

/// Build a manifest whose `runtime` declaration carries an arbitrary CBOR
/// integer, so a negative port can reach the descriptor exactly as it would
/// from the wire.
fn runtime_manifest(
    container: ctf_format::cbor::Value,
    readiness_tcp: ctf_format::cbor::Value,
) -> ctf_format::Manifest {
    use ctf_format::cbor::Value;
    ctf_format::Manifest::build(
        "neg-port",
        "Neg Port",
        &["manifest"],
        vec![(
            Value::Text("runtime".into()),
            Value::Map(vec![
                (
                    Value::Text("ports".into()),
                    Value::Array(vec![Value::Map(vec![
                        (Value::Text("container".into()), container),
                        (Value::Text("protocol".into()), Value::Text("tcp".into())),
                    ])]),
                ),
                (
                    Value::Text("readiness".into()),
                    Value::Map(vec![
                        (Value::Text("tcp".into()), readiness_tcp),
                        (Value::Text("timeout".into()), Value::Text("30s".into())),
                    ]),
                ),
            ]),
        )],
    )
    .unwrap()
}

/// §29.1: a negative `runtime.ports[0].container` is outside `1..=65535`, so it
/// is a policy error, never a silently omitted field.
#[test]
fn a_negative_container_port_is_out_of_range() {
    let manifest = runtime_manifest(
        ctf_format::cbor::Value::Nint(0),
        ctf_format::cbor::Value::Uint(1337),
    );
    let descriptor =
        ctf_format::PlatformDescriptor::from_manifest(&manifest, DEFAULT_PLATFORM_NAMESPACE);
    let issues = descriptor.validate();
    assert!(
        issues
            .iter()
            .any(|i| i.key() == "port" && i.message() == "must be between 1 and 65535"),
        "expected a port range issue, got {issues:?}"
    );
}

/// As above, for `runtime.readiness.tcp`.
#[test]
fn a_negative_readiness_port_is_out_of_range() {
    let manifest = runtime_manifest(
        ctf_format::cbor::Value::Uint(1337),
        ctf_format::cbor::Value::Nint(0),
    );
    let descriptor =
        ctf_format::PlatformDescriptor::from_manifest(&manifest, DEFAULT_PLATFORM_NAMESPACE);
    let issues = descriptor.validate();
    assert!(
        issues
            .iter()
            .any(|i| i.key() == "readiness.tcp" && i.message() == "must be between 1 and 65535"),
        "expected a readiness.tcp range issue, got {issues:?}"
    );
}

/// `0` and `65536` sit just outside `1..=65535`; each reports one issue, and
/// neither is projected into the `u16` field.
#[test]
fn a_zero_or_too_large_port_reports_exactly_one_issue() {
    use ctf_format::cbor::Value;
    for raw in [Value::Uint(0), Value::Uint(65536)] {
        let port_manifest = runtime_manifest(raw.clone(), Value::Uint(1337));
        let port_descriptor = ctf_format::PlatformDescriptor::from_manifest(
            &port_manifest,
            DEFAULT_PLATFORM_NAMESPACE,
        );
        assert!(port_descriptor.port.is_none());
        let issues = port_descriptor.validate();
        assert_eq!(issues.len(), 1, "port {raw:?}: {issues:?}");
        assert_eq!(issues[0].key(), "port");

        let readiness_manifest = runtime_manifest(Value::Uint(1337), raw.clone());
        let readiness_descriptor = ctf_format::PlatformDescriptor::from_manifest(
            &readiness_manifest,
            DEFAULT_PLATFORM_NAMESPACE,
        );
        assert!(readiness_descriptor.readiness.is_none());
        let issues = readiness_descriptor.validate();
        assert_eq!(issues.len(), 1, "readiness {raw:?}: {issues:?}");
        assert_eq!(issues[0].key(), "readiness.tcp");
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
