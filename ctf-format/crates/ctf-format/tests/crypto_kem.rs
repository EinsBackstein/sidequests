//! Hybrid KEM combiner tests (ticket 11, spec §20.1, design §7).
//!
//! The combiner must be a KDF over both shared secrets *and* the full transcript:
//! steering either component ciphertext, or the context, must change the derived
//! key. The salt binds the major version only, and every variable-length transcript
//! field is length-prefixed so the concatenation is injective.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use ctf_format::crypto::{hybrid_kem::X25519MlKem768, lp};
use ctf_format::suite::{Kem, KemContext, SuiteError, suite};

fn ctx<'a>(label: &'a [u8]) -> KemContext<'a> {
    KemContext {
        suite_id: 1,
        version_major: 0,
        label,
    }
}

#[test]
fn a_sender_and_recipient_derive_the_same_key() {
    let kem = X25519MlKem768::new();
    let pair = kem.generate().unwrap();
    assert_eq!(pair.public_key.len(), kem.public_key_len());
    assert_eq!(pair.secret_key.len(), kem.secret_key_len());

    let (ct, sender_key) = kem.encapsulate(&pair.public_key, &ctx(b"storage")).unwrap();
    assert_eq!(ct.len(), kem.ciphertext_len());
    let recipient_key = kem
        .decapsulate(&pair.secret_key, &ct, &ctx(b"storage"))
        .unwrap();
    assert_eq!(sender_key, recipient_key);
}

#[test]
fn the_derived_key_is_32_bytes() {
    let kem = X25519MlKem768::new();
    assert_eq!(kem.shared_secret_len(), 32);
    let pair = kem.generate().unwrap();
    let (_, key) = kem.encapsulate(&pair.public_key, &ctx(b"seal")).unwrap();
    assert_eq!(key.len(), 32);
}

/// The transcript binds both ciphertexts: flipping a byte of the classical or the
/// post-quantum half changes the derived key, so an attacker who controls one
/// component cannot steer the other.
#[test]
fn changing_either_component_ciphertext_changes_the_key() {
    let kem = X25519MlKem768::new();
    let pair = kem.generate().unwrap();
    let (ct, key) = kem.encapsulate(&pair.public_key, &ctx(b"storage")).unwrap();

    let mut tampered = ct.clone();
    tampered[0] ^= 0x01;
    let other = kem
        .decapsulate(&pair.secret_key, &tampered, &ctx(b"storage"))
        .unwrap();
    assert_ne!(
        key, other,
        "classical half is not bound into the transcript"
    );

    let mut tampered = ct.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let other = kem
        .decapsulate(&pair.secret_key, &tampered, &ctx(b"storage"))
        .unwrap();
    assert_ne!(
        key, other,
        "post-quantum half is not bound into the transcript"
    );
}

/// The salt binds `version_major` only. A different major version must derive a
/// different key; there is no minor-version input at all, so a minor bump cannot
/// re-key a bundle.
#[test]
fn the_salt_binds_the_major_version_only() {
    let kem = X25519MlKem768::new();
    let pair = kem.generate().unwrap();
    let (ct, key_v0) = kem.encapsulate(&pair.public_key, &ctx(b"storage")).unwrap();

    let v1 = KemContext {
        suite_id: 1,
        version_major: 1,
        label: b"storage",
    };
    let key_v1 = kem.decapsulate(&pair.secret_key, &ct, &v1).unwrap();
    assert_ne!(key_v0, key_v1, "version_major must be bound into the salt");
}

#[test]
fn a_different_context_label_derives_a_different_key() {
    let kem = X25519MlKem768::new();
    let pair = kem.generate().unwrap();
    let (ct, storage) = kem.encapsulate(&pair.public_key, &ctx(b"storage")).unwrap();
    let seal = kem
        .decapsulate(&pair.secret_key, &ct, &ctx(b"seal"))
        .unwrap();
    assert_ne!(storage, seal);
}

/// The combiner's transcript is `LP(a) ‖ LP(b) ‖ …`; without the length prefix,
/// `("ab","c")` and `("a","bc")` are the same bytes and two different inputs would
/// derive the same key. This pins that the prefix makes the concatenation injective.
#[test]
fn length_prefixing_disambiguates_concatenations() {
    let mut split_a = Vec::new();
    lp(&mut split_a, b"ab");
    lp(&mut split_a, b"c");

    let mut split_b = Vec::new();
    lp(&mut split_b, b"a");
    lp(&mut split_b, b"bc");

    assert_ne!(
        split_a, split_b,
        "the same concatenation from two different splits must not encode identically"
    );

    // And the prefix is itself little-endian u32 as the spec fixes it.
    assert_eq!(lp_of(b"ab"), vec![2, 0, 0, 0, b'a', b'b']);
}

fn lp_of(x: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    lp(&mut v, x);
    v
}

#[test]
fn a_public_key_of_the_wrong_length_is_rejected() {
    let kem = X25519MlKem768::new();
    let err = kem.encapsulate(&[0u8; 10], &ctx(b"storage")).unwrap_err();
    assert!(matches!(err, SuiteError::InvalidLength { .. }));
}

#[test]
fn a_secret_key_of_the_wrong_length_is_rejected() {
    let kem = X25519MlKem768::new();
    let err = kem
        .decapsulate(&[0u8; 10], &[0u8; 10], &ctx(b"storage"))
        .unwrap_err();
    assert!(matches!(err, SuiteError::InvalidLength { .. }));
}

/// The registry resolves the `kem` role now that ticket 11 has landed.
#[test]
fn the_kem_role_resolves_through_the_registry() {
    let s1 = suite(1).unwrap();
    let kem = s1.kem().unwrap();
    assert_eq!(kem.public_key_len(), 32 + 1184);
    assert_eq!(kem.ciphertext_len(), 32 + 1088);
    assert!(suite(9999).is_err());
}
