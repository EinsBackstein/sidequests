//! The bundle as an OCI artifact (ticket 63): export writes an OCI image layout,
//! import round-trips the bundle byte-for-byte, and the digest is the bundle's.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use ctf_format::oci;
use ctf_format::{Manifest, SectionFlags, SectionKind, SectionSpec, write_bundle};

fn minimal_bundle() -> Vec<u8> {
    let manifest = Manifest::minimal("whos-that-bird", "Who's That Bird", &["manifest"])
        .unwrap()
        .encode()
        .unwrap();
    write_bundle(
        1,
        &[SectionSpec::inline(
            SectionKind::Manifest,
            0,
            SectionFlags::empty(),
            &manifest,
        )],
    )
    .unwrap()
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ctf-oci-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn export_then_import_round_trips_byte_for_byte() {
    let bundle = minimal_bundle();
    let dir = scratch("roundtrip");
    let layout = oci::export(&bundle, &dir).unwrap();
    assert!(dir.join("oci-layout").is_file());
    assert!(dir.join("index.json").is_file());
    assert!(dir.join("blobs/sha256").is_dir());
    assert_eq!(layout.bundle_digest, oci::digest_sha256(&bundle));

    let recovered = oci::import(&dir).unwrap();
    assert_eq!(recovered, bundle, "the bundle must survive byte-for-byte");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_digest_matches_the_bundle_content() {
    let bundle = minimal_bundle();
    let digest = oci::digest_sha256(&bundle);
    assert!(digest.starts_with("sha256:"));
    assert_eq!(digest.len(), "sha256:".len() + 64);
    // A one-byte change changes the digest.
    let mut tampered = bundle.clone();
    tampered.push(0);
    assert_ne!(oci::digest_sha256(&tampered), digest);
}

#[test]
fn import_refuses_a_directory_that_is_not_a_layout() {
    let dir = scratch("not-a-layout");
    std::fs::create_dir_all(&dir).unwrap();
    assert!(matches!(oci::import(&dir), Err(oci::OciError::NotALayout)));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn export_refuses_bytes_that_are_not_a_bundle() {
    let dir = scratch("bad-bundle");
    assert!(oci::export(b"not a ctf file", &dir).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}
