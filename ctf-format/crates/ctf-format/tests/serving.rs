//! The static artifact serving manifest (ticket 65): player-visible artifacts only,
//! sealed sections never, and bytes verify before they are served.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use ctf_format::suite::{KemKeyPair, suite};
use ctf_format::{
    Manifest, Recipient, SectionFlags, SectionKind, SectionSpec, ServingManifest, serve,
    write_bundle,
};

const SUITE: u16 = 1;

fn keypair(suite_id: u16) -> KemKeyPair {
    suite(suite_id).unwrap().kem().unwrap().generate().unwrap()
}

/// A bundle with a player-visible `chal`, a sealed `writeup`, and the `keys` section.
fn bundle_with_mixed_visibility() -> Vec<u8> {
    let recipient = keypair(SUITE);
    let manifest = Manifest::build(
        "mixed",
        "Mixed Visibility",
        &["manifest", "chal", "writeup", "keys"],
        Vec::new(),
    )
    .unwrap();
    let manifest_bytes = manifest.encode().unwrap();
    let chal = b"the public artifact".to_vec();
    let recipients = [Recipient {
        context: "seal",
        public_key: &recipient.public_key,
    }];
    let writeup = SectionSpec::inline(
        SectionKind::Writeup,
        2,
        SectionFlags(SectionFlags::SEALED),
        b"the sealed writeup",
    )
    .chunked(4096)
    .encrypted(&recipients);
    write_bundle(
        SUITE,
        &[
            SectionSpec::inline(
                SectionKind::Manifest,
                0,
                SectionFlags::empty(),
                &manifest_bytes,
            ),
            SectionSpec::inline(
                SectionKind::Artifact,
                1,
                SectionFlags(SectionFlags::PLAYER_VISIBLE),
                &chal,
            ),
            writeup,
            SectionSpec::envelopes(SectionKind::Keys, 3),
        ],
    )
    .unwrap()
}

#[test]
fn only_player_visible_artifacts_appear() {
    let file = bundle_with_mixed_visibility();
    let bundle = ctf_format::Bundle::parse(&file).unwrap();
    let serving = ServingManifest::from_bundle(&bundle);
    assert_eq!(serving.challenge_id, "mixed");
    assert_eq!(serving.artifacts.len(), 1);
    let a = &serving.artifacts[0];
    assert_eq!(a.name_id, 1);
    assert_eq!(a.name, "chal");
    assert_eq!(a.size, 19);
    assert!(!a.external);
    assert_eq!(a.root, *blake3::hash(b"the public artifact").as_bytes());
}

#[test]
fn a_sealed_section_never_appears() {
    let file = bundle_with_mixed_visibility();
    let bundle = ctf_format::Bundle::parse(&file).unwrap();
    let serving = ServingManifest::from_bundle(&bundle);
    assert!(
        serving.artifact(2).is_none(),
        "the sealed writeup must not be in the serving manifest"
    );
}

#[test]
fn the_serving_manifest_is_canonical_cbor() {
    let file = bundle_with_mixed_visibility();
    let bundle = ctf_format::Bundle::parse(&file).unwrap();
    let serving = ServingManifest::from_bundle(&bundle);
    let bytes = serving.to_bytes().unwrap();
    // Re-encoding the decoded value reproduces the bytes: canonical, and injective.
    assert_eq!(
        ctf_format::cbor::Value::decode(&bytes)
            .unwrap()
            .encode()
            .unwrap(),
        bytes
    );
}

#[test]
fn served_bytes_are_verified_and_sealed_bytes_are_refused() {
    let file = bundle_with_mixed_visibility();
    let bundle = ctf_format::Bundle::parse(&file).unwrap();
    assert_eq!(&*serve(&bundle, 1).unwrap(), b"the public artifact");
    // The sealed writeup is not servable, with or without a key.
    assert!(serve(&bundle, 2).is_err());
    // The manifest is not player-visible, so it is not servable either.
    assert!(serve(&bundle, 0).is_err());
    // An unknown name_id is refused.
    assert!(serve(&bundle, 999).is_err());
}

#[test]
fn an_artifact_verifies_against_its_size_and_root() {
    let file = bundle_with_mixed_visibility();
    let bundle = ctf_format::Bundle::parse(&file).unwrap();
    let serving = ServingManifest::from_bundle(&bundle);
    let a = serving.artifact(1).unwrap();
    assert!(a.verify(b"the public artifact"));
    assert!(!a.verify(b"the public artifact "));
    assert!(!a.verify(b"the public art"));
}
