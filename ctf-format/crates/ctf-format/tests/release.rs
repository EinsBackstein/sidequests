//! Sealed release interop (ticket 66): the offline seal key releases the sections a
//! bundle declares for event end, and the release is auditable.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use ctf_format::cbor::Value;
use ctf_format::suite::{KemKeyPair, suite};
use ctf_format::{
    Error, Manifest, Recipient, SectionFlags, SectionKind, SectionSpec, release_at_event_end,
    write_bundle,
};

const SUITE: u16 = 1;

fn keypair(suite_id: u16) -> KemKeyPair {
    suite(suite_id).unwrap().kem().unwrap().generate().unwrap()
}

/// A bundle carrying `declaration` (if any) and one sealed section per name in
/// `sealed_names`, each encrypted to the returned seal key.
fn sealed_bundle_with(declaration: Option<Value>, sealed_names: &[&str]) -> (Vec<u8>, KemKeyPair) {
    let recipient = keypair(SUITE);
    let mut names = vec!["manifest"];
    names.extend_from_slice(sealed_names);
    names.push("keys");
    let mut extra = Vec::new();
    if let Some(declaration) = declaration {
        extra.push((Value::Text("sealed".into()), declaration));
    }
    let manifest = Manifest::build("sealed-chal", "Sealed Challenge", &names, extra).unwrap();
    let manifest_bytes = manifest.encode().unwrap();
    let recipients = [Recipient {
        context: "seal",
        public_key: &recipient.public_key,
    }];

    let bodies: Vec<String> = sealed_names
        .iter()
        .map(|name| format!("the sealed {name} body"))
        .collect();
    let mut sections = vec![SectionSpec::inline(
        SectionKind::Manifest,
        0,
        SectionFlags::empty(),
        &manifest_bytes,
    )];
    for (i, name) in sealed_names.iter().enumerate() {
        let kind = match *name {
            "solver" => SectionKind::Solver,
            "progress" => SectionKind::Progress,
            _ => SectionKind::Writeup,
        };
        sections.push(
            SectionSpec::inline(
                kind,
                (i + 1) as u16,
                SectionFlags(SectionFlags::SEALED),
                bodies[i].as_bytes(),
            )
            .chunked(4096)
            .encrypted(&recipients),
        );
    }
    sections.push(SectionSpec::envelopes(
        SectionKind::Keys,
        (sealed_names.len() + 1) as u16,
    ));
    let file = write_bundle(SUITE, &sections).unwrap();
    (file, recipient)
}

/// A bundle with a sealed `writeup` declared for `event_end` release.
fn sealed_bundle(release: &str) -> (Vec<u8>, KemKeyPair) {
    let sealed_decl = Value::Map(vec![
        (Value::Text("release".into()), Value::Text(release.into())),
        (
            Value::Text("members".into()),
            Value::Array(vec![Value::Text("writeup".into())]),
        ),
    ]);
    sealed_bundle_with(Some(sealed_decl), &["writeup"])
}

#[test]
fn an_event_end_release_recovers_the_asset_and_records_it() {
    let (file, recipient) = sealed_bundle("event_end");
    let bundle = ctf_format::Bundle::parse(&file).unwrap();
    let release = release_at_event_end(&bundle, &recipient.secret_key).unwrap();
    assert_eq!(release.report.release, "event_end");
    assert_eq!(release.report.challenge_id, "sealed-chal");
    assert_eq!(release.report.members.len(), 1);
    assert_eq!(release.assets.len(), 1);
    assert_eq!(release.assets[0].bytes, b"the sealed writeup body");
    assert_eq!(release.assets[0].member.name, "writeup");
    // The audit record contains no plaintext.
    let json = release.report.to_json().unwrap();
    assert!(!json.contains("sealed writeup body"));
    assert!(json.contains("sealed-chal"));
}

#[test]
fn the_wrong_seal_key_releases_nothing() {
    let (file, _recipient) = sealed_bundle("event_end");
    let bundle = ctf_format::Bundle::parse(&file).unwrap();
    let wrong = keypair(SUITE);
    assert!(release_at_event_end(&bundle, &wrong.secret_key).is_err());
}

#[test]
fn a_non_event_end_release_is_refused() {
    for mode in ["manual", "stage:2"] {
        let (file, recipient) = sealed_bundle(mode);
        let bundle = ctf_format::Bundle::parse(&file).unwrap();
        assert!(
            release_at_event_end(&bundle, &recipient.secret_key).is_err(),
            "release mode {mode} must not be triggered by the event-end command"
        );
    }
}

/// §27.1/§7.6: `members` is a required sub-key of a present `sealed` declaration.
/// A declaration that omits it — or names a non-text element — must not be read as
/// "release everything"; it is refused before any section is decrypted.
#[test]
fn a_sealed_declaration_without_usable_members_is_refused() {
    let missing = Value::Map(vec![(
        Value::Text("release".into()),
        Value::Text("event_end".into()),
    )]);
    let non_array = Value::Map(vec![
        (
            Value::Text("release".into()),
            Value::Text("event_end".into()),
        ),
        (Value::Text("members".into()), Value::Text("writeup".into())),
    ]);
    let non_text_element = Value::Map(vec![
        (
            Value::Text("release".into()),
            Value::Text("event_end".into()),
        ),
        (
            Value::Text("members".into()),
            Value::Array(vec![Value::Uint(1)]),
        ),
    ]);
    for declaration in [missing, non_array, non_text_element] {
        let (file, recipient) = sealed_bundle_with(Some(declaration), &["solver", "writeup"]);
        let bundle = ctf_format::Bundle::parse(&file).unwrap();
        let err = release_at_event_end(&bundle, &recipient.secret_key).unwrap_err();
        assert!(
            matches!(err, Error::Inconsistent { .. }),
            "a malformed declaration must be refused, got {err}"
        );
        assert!(
            err.to_string().contains("sealed"),
            "the refusal must name the declaration: {err}"
        );
    }
}

/// An explicit empty `members` array is a declaration covering nothing: it releases
/// no sealed section, which is different from a declaration that omits the key.
#[test]
fn an_empty_members_list_releases_nothing() {
    let declaration = Value::Map(vec![
        (
            Value::Text("release".into()),
            Value::Text("event_end".into()),
        ),
        (Value::Text("members".into()), Value::Array(Vec::new())),
    ]);
    let (file, recipient) = sealed_bundle_with(Some(declaration), &["solver", "writeup"]);
    let bundle = ctf_format::Bundle::parse(&file).unwrap();
    let release = release_at_event_end(&bundle, &recipient.secret_key).unwrap();
    assert_eq!(release.report.release, "event_end");
    assert!(release.assets.is_empty());
}

/// §27.1 sentence 2: without any `sealed` declaration every SEALED section is
/// released. §27.2: the audit record names the operation that performed it, which is
/// `event_end` — never the invented mode `all`.
#[test]
fn no_declaration_releases_every_sealed_section_and_records_event_end() {
    let (file, recipient) = sealed_bundle_with(None, &["solver", "writeup"]);
    let bundle = ctf_format::Bundle::parse(&file).unwrap();
    let release = release_at_event_end(&bundle, &recipient.secret_key).unwrap();
    assert_eq!(release.report.release, "event_end");
    assert_eq!(release.report.members.len(), 2);
    let names: Vec<&str> = release
        .report
        .members
        .iter()
        .map(|m| m.name.as_str())
        .collect();
    assert_eq!(names, ["solver", "writeup"]);
}

/// §4.4/§10: the release is a rewrite, so a header carrying an unimplemented
/// `feat_ro_compat` bit makes it refuse before any section is touched. The vector
/// carries no `sealed` declaration, which is the point: the guard is not conditional
/// on the declaration or on the key.
#[test]
fn releasing_a_read_only_bundle_is_refused() {
    let file = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../spec/vectors/conformance/future/ro-compat-bit.ctf"
    ))
    .unwrap();
    let bundle = ctf_format::Bundle::parse(&file).unwrap();
    assert!(!bundle.header.may_rewrite());

    let key = keypair(SUITE);
    assert!(matches!(
        release_at_event_end(&bundle, &key.secret_key),
        Err(Error::ReadOnlyBundle { .. })
    ));
}
