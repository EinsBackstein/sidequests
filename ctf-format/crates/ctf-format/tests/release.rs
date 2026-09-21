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
    Manifest, Recipient, SectionFlags, SectionKind, SectionSpec, release_at_event_end, write_bundle,
};

const SUITE: u16 = 1;

fn keypair(suite_id: u16) -> KemKeyPair {
    suite(suite_id).unwrap().kem().unwrap().generate().unwrap()
}

/// A bundle with a sealed `writeup` declared for `event_end` release.
fn sealed_bundle(release: &str) -> (Vec<u8>, KemKeyPair) {
    let recipient = keypair(SUITE);
    let sealed_decl = Value::Map(vec![
        (Value::Text("release".into()), Value::Text(release.into())),
        (
            Value::Text("members".into()),
            Value::Array(vec![Value::Text("writeup".into())]),
        ),
    ]);
    let manifest = Manifest::build(
        "sealed-chal",
        "Sealed Challenge",
        &["manifest", "writeup", "keys"],
        vec![(Value::Text("sealed".into()), sealed_decl)],
    )
    .unwrap();
    let manifest_bytes = manifest.encode().unwrap();
    let recipients = [Recipient {
        context: "seal",
        public_key: &recipient.public_key,
    }];
    let writeup = SectionSpec::inline(
        SectionKind::Writeup,
        1,
        SectionFlags(SectionFlags::SEALED),
        b"the sealed writeup body",
    )
    .chunked(4096)
    .encrypted(&recipients);
    let file = write_bundle(
        SUITE,
        &[
            SectionSpec::inline(
                SectionKind::Manifest,
                0,
                SectionFlags::empty(),
                &manifest_bytes,
            ),
            writeup,
            SectionSpec::envelopes(SectionKind::Keys, 2),
        ],
    )
    .unwrap();
    (file, recipient)
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
