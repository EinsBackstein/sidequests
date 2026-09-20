//! Manifest declaration keys (ticket 33) and the platform overlay (ticket 57).
//!
//! The container carries both; it never consumes them. What is tested here is that
//! carrying is byte-exact, that criticality still decides what an older reader may
//! ignore, and that the overlay needs no format change.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use ctf_format::{Error, Manifest, authoring::ChallengeDoc, cbor::Value};

/// Every declaration key present, round-tripped through the canonical encoder.
#[test]
fn declaration_keys_round_trip_byte_for_byte() {
    let entries = vec![
        (
            Value::Text("flag".into()),
            Value::Map(vec![
                (
                    Value::Text("derive".into()),
                    Value::Text("hkdf-sha256".into()),
                ),
                (Value::Text("scope".into()), Value::Text("team".into())),
            ]),
        ),
        (
            Value::Text("generate".into()),
            Value::Map(vec![(
                Value::Text("wasm".into()),
                Value::Text("gen.wasm".into()),
            )]),
        ),
        (
            Value::Text("runtime".into()),
            Value::Map(vec![(
                Value::Text("image".into()),
                Value::Text("ghcr.io/x@sha256:abc".into()),
            )]),
        ),
        (
            Value::Text("sealed".into()),
            Value::Map(vec![(
                Value::Text("release".into()),
                Value::Text("event_end".into()),
            )]),
        ),
        (
            Value::Text("verify".into()),
            Value::Map(vec![(
                Value::Text("solver".into()),
                Value::Text("solver.wasm".into()),
            )]),
        ),
    ];
    let m = Manifest::build("x", "X", &["manifest"], entries).unwrap();
    let bytes = m.encode().unwrap();
    assert_eq!(Manifest::decode(&bytes).unwrap().encode().unwrap(), bytes);
    for key in ["flag", "generate", "runtime", "sealed", "verify"] {
        assert!(m.declaration(key).is_some(), "missing `{key}`");
    }
}

/// A declaration key may be marked critical, because this build understands it
/// (spec §7.6). An author who needs it interpreted gets a clean refusal from a
/// reader that predates it.
#[test]
fn a_declaration_key_may_be_marked_critical() {
    let m = Manifest::build(
        "x",
        "X",
        &["manifest"],
        vec![
            (
                Value::Text("crit".into()),
                Value::Array(vec![Value::Text("runtime".into())]),
            ),
            (
                Value::Text("runtime".into()),
                Value::Map(vec![(Value::Text("ttl".into()), Value::Text("30m".into()))]),
            ),
        ],
    )
    .unwrap();
    assert_eq!(m.spec(), 1);
}

/// A key this build does not implement is still a hard reject when critical: the
/// extension mechanism keeps working.
#[test]
fn a_critical_unimplemented_key_is_rejected() {
    let v = Value::Map(vec![
        (Value::Text("spec".into()), Value::Uint(1)),
        (Value::Text("id".into()), Value::Text("x".into())),
        (Value::Text("name".into()), Value::Text("X".into())),
        (Value::Text("names".into()), Value::Array(vec![])),
        (
            Value::Text("crit".into()),
            Value::Array(vec![Value::Text("scoring".into())]),
        ),
        (Value::Text("scoring".into()), Value::Uint(10)),
    ]);
    assert!(matches!(
        Manifest::decode(&v.encode().unwrap()),
        Err(Error::ManifestEntry {
            index: Some(0),
            name_id: None,
            ..
        })
    ));
}

/// A non-critical unknown key survives decode/encode unchanged.
#[test]
fn a_non_critical_unknown_key_is_carried() {
    let v = Value::Map(vec![
        (Value::Text("spec".into()), Value::Uint(1)),
        (Value::Text("id".into()), Value::Text("x".into())),
        (Value::Text("name".into()), Value::Text("X".into())),
        (Value::Text("names".into()), Value::Array(vec![])),
        (
            Value::Text("scoring".into()),
            Value::Array(vec![Value::Uint(1), Value::Text("weight".into())]),
        ),
    ]);
    let bytes = v.encode().unwrap();
    let m = Manifest::decode(&bytes).unwrap();
    assert_eq!(m.encode().unwrap(), bytes);
}

/// End to end: the authoring schema's declarations become manifest keys and back.
#[test]
fn authoring_entries_become_manifest_keys() {
    let yaml = "\
spec: 1
id: baby-rop
version: 3
name: Baby ROP
category: pwn
flag:
  derive: hkdf-sha256
  template: \"ctf{rop_%s}\"
  scope: team
runtime:
  image: \"ghcr.io/ctf/baby-rop@sha256:abc\"
  ports:
    - { container: 1337, protocol: tcp }
  resources: { cpu: \"0.5\", memory: \"256Mi\", pids: 64 }
  instancing: per_team
  ttl: 30m
  readiness: { tcp: 1337, timeout: 30s }
verify:
  solver: solver.wasm
  expect: flag
  offline: true
";
    let doc = ChallengeDoc::from_yaml(yaml).unwrap();
    let m = Manifest::build(&doc.id, &doc.name, &["manifest"], doc.manifest_entries()).unwrap();
    let bytes = m.encode().unwrap();
    let back = Manifest::decode(&bytes).unwrap();
    assert_eq!(back.version(), 3);
    assert_eq!(back.category(), Some("pwn"));
    assert!(back.declaration("flag").is_some());
    assert!(back.declaration("runtime").is_some());
    assert!(back.declaration("verify").is_some());
    assert!(back.declaration("generate").is_none());
    assert_eq!(back.encode().unwrap(), bytes);
}

/// Ticket 57: platform fields live under a namespaced `platform` key. The format
/// does not own them, a generic reader carries them unchanged, and adding a field
/// inside the overlay needs no version bump because it is not a format field.
#[test]
fn platform_overlay_is_carried_unchanged() {
    let overlay = Value::Map(vec![
        (
            Value::Text("acme.example".into()),
            Value::Map(vec![
                (Value::Text("track".into()), Value::Text("gold".into())),
                (Value::Text("weight".into()), Value::Uint(100)),
            ]),
        ),
        (
            Value::Text("other.example".into()),
            Value::Array(vec![Value::Uint(7)]),
        ),
    ]);
    let m = Manifest::build(
        "x",
        "X",
        &["manifest"],
        vec![(Value::Text("platform".into()), overlay.clone())],
    )
    .unwrap();
    let bytes = m.encode().unwrap();
    let back = Manifest::decode(&bytes).unwrap();
    // No reader in this build interprets `platform`; it is carried, and the bytes
    // are identical with and without understanding it.
    assert_eq!(back.encode().unwrap(), bytes);
    assert_eq!(back.value().get("platform"), Some(&overlay));
}
