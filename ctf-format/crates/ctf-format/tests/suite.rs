//! Suite registry and dispatch tests (ticket 9).
//!
//! The load-bearing acceptance criterion is *timing*: an unrecognized `suite_id`
//! must not fail at header parse, because the header is structurally fine and the
//! diagnostic should point at what is actually missing.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use ctf_format::{AeadId, HashId, Header, KdfId, KemId, Role, SignatureId, SuiteError, suite};

#[test]
fn known_suites_resolve_with_one_algorithm_per_role() {
    let s1 = suite(1).unwrap();
    assert_eq!(s1.id, 1);
    assert_eq!(s1.hash_id(), HashId::Blake3);
    assert_eq!(s1.kdf_id(), KdfId::HkdfSha256);
    assert_eq!(s1.kem_id(), KemId::X25519MlKem768);
    assert_eq!(s1.aead_id(), AeadId::Aes256Gcm);
    assert_eq!(s1.signature_id(), SignatureId::Ed25519MlDsa65);

    // Suite 2 differs only in the AEAD.
    let s2 = suite(2).unwrap();
    assert_eq!(s2.aead_id(), AeadId::XChaCha20Poly1305);
    assert_eq!(s2.kem_id(), KemId::X25519MlKem768);

    // Suite 3 adds SLH-DSA to the signature set.
    assert_eq!(
        suite(3).unwrap().signature_id(),
        SignatureId::Ed25519MlDsa65SlhDsa
    );

    for id in [1u16, 2, 3] {
        let s = suite(id).unwrap();
        // The hash role is implemented; it is BLAKE3.
        assert_eq!(s.hash().hash(b"abc"), *blake3::hash(b"abc").as_bytes());
    }
}

#[test]
fn an_unknown_suite_is_named() {
    assert_eq!(
        suite(9999).unwrap_err(),
        SuiteError::UnknownSuite { id: 9999 }
    );
}

/// Tickets 10–12 filled the phases 2 roles, so suites 1 and 2 resolve all five.
#[test]
fn implemented_roles_resolve_through_the_registry() {
    for id in [1u16, 2] {
        let s = suite(id).unwrap();
        assert!(s.kdf().is_ok(), "kdf role should resolve for suite {id}");
        assert!(s.kem().is_ok(), "kem role should resolve for suite {id}");
        assert!(s.aead().is_ok(), "aead role should resolve for suite {id}");
        assert!(
            s.signature().is_ok(),
            "signature role should resolve for suite {id}"
        );
    }
}

/// Suite 3's signature is Ed25519 + ML-DSA-65 + SLH-DSA. SLH-DSA is not in this
/// build, and a hybrid signature missing a component is not a working role, so it
/// fails where it is used — named, not panicking, and not at header parse.
#[test]
fn the_archive_signature_role_is_not_implemented() {
    let s3 = suite(3).unwrap();
    assert!(s3.kdf().is_ok());
    assert!(s3.kem().is_ok());
    assert!(s3.aead().is_ok());
    assert_eq!(
        s3.signature().unwrap_err(),
        SuiteError::NotImplemented {
            suite: 3,
            role: Role::Signature
        }
    );
}

/// The header parser records `suite_id` verbatim and does not consult the
/// registry. A file naming a suite this build has never heard of still parses.
#[test]
fn header_parse_does_not_reject_an_unknown_suite() {
    let mut header = [0u8; 64];
    header[..8].copy_from_slice(&ctf_format::MAGIC);
    header[8..10].copy_from_slice(&0u16.to_le_bytes()); // major
    header[10..12].copy_from_slice(&3u16.to_le_bytes()); // minor
    header[12..16].copy_from_slice(&64u32.to_le_bytes()); // header_len
    header[16..18].copy_from_slice(&9999u16.to_le_bytes()); // suite_id
    header[20..24].copy_from_slice(&1u32.to_le_bytes()); // count
    header[24..32].copy_from_slice(&64u64.to_le_bytes()); // table off
    header[32..40].copy_from_slice(&192u64.to_le_bytes()); // footer off
    header[44..48].copy_from_slice(&1u32.to_le_bytes()); // CONTAINER_V1

    let h = Header::parse(&header).expect("header parse must not consult the registry");
    assert_eq!(h.suite_id, 9999);
    assert!(matches!(
        suite(h.suite_id),
        Err(SuiteError::UnknownSuite { .. })
    ));
}
