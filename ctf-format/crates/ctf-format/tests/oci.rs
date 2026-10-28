//! The bundle as an OCI artifact (ticket 63): export writes an OCI image layout,
//! import round-trips the bundle byte-for-byte, and the digest is the bundle's.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::path::{Path, PathBuf};

use ctf_format::oci;
use ctf_format::{Bundle, Manifest, SectionFlags, SectionKind, SectionSpec, write_bundle};

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

/// The image manifest the layout's index points at.
fn image_manifest(dir: &Path) -> serde_json::Value {
    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("index.json")).unwrap()).unwrap();
    let digest = index["manifests"][0]["digest"].as_str().unwrap();
    let hex = digest.strip_prefix("sha256:").unwrap();
    serde_json::from_slice(&std::fs::read(dir.join("blobs").join("sha256").join(hex)).unwrap())
        .unwrap()
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

/// §30.1/X1: the layer blob is the bundle, so a valid header is required. Bytes
/// that are not a `.ctf` at all are refused rather than wrapped under the bundle's
/// media type, and nothing is written.
#[test]
fn export_refuses_bytes_without_a_valid_header() {
    for (name, bytes) in [
        ("one-byte", &b"X"[..]),
        ("not-a-bundle", &b"not a bundle"[..]),
    ] {
        let dir = scratch(name);
        assert!(
            matches!(oci::export(bytes, &dir), Err(oci::OciError::Format(_))),
            "`{}` must be refused as a format error",
            String::from_utf8_lossy(bytes)
        );
        assert!(
            !dir.exists(),
            "a refused export must not create a layout: {}",
            dir.display()
        );
    }
}

/// A valid header is enough: §17 keeps a 0.2 bundle valid even though a 0.3
/// whole-container read refuses it (§10.2), and a current 0.3 bundle parses in
/// full. Both are byte copies and must round-trip exactly.
#[test]
fn export_round_trips_a_valid_0_2_and_a_valid_0_3_bundle() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/vectors/conformance/golden/minimal.ctf");
    let mut older = std::fs::read(path).unwrap();
    // Exactly as a 0.2 writer left it: minor 2 and CONTAINER_V1 clear.
    older[10..12].copy_from_slice(&2u16.to_le_bytes());
    older[44..48].copy_from_slice(&0u32.to_le_bytes());
    assert!(matches!(
        Bundle::parse(&older),
        Err(ctf_format::Error::LegacyContainer { minor: 2 })
    ));

    for (name, bundle) in [("0-2", older), ("0-3", minimal_bundle())] {
        let dir = scratch(name);
        oci::export(&bundle, &dir).unwrap();
        let recovered = oci::import(&dir).unwrap();
        assert_eq!(
            recovered, bundle,
            "the {name} bundle must survive byte-for-byte"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// When the bundle does parse, the layout still carries the challenge identity.
#[test]
fn export_annotates_a_parsed_bundle_with_its_title() {
    let bundle = minimal_bundle();
    let dir = scratch("annotated");
    oci::export(&bundle, &dir).unwrap();

    let manifest = image_manifest(&dir);
    assert_eq!(
        manifest["annotations"]["org.opencontainers.image.title"], "whos-that-bird",
        "the manifest names the challenge: {manifest}"
    );
    assert_eq!(
        manifest["layers"][0]["annotations"]["org.opencontainers.image.title"], "whos-that-bird",
        "the layer names the challenge: {manifest}"
    );

    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("index.json")).unwrap()).unwrap();
    assert_eq!(
        index["manifests"][0]["annotations"]["org.opencontainers.image.ref.name"],
        "whos-that-bird:0",
        "the index names the challenge and version: {index}"
    );
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
