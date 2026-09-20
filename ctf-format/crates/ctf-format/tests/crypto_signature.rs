//! Hybrid signature verification tests (ticket 10, spec §20.3, design §7).
//!
//! Both components must verify over the identical §8.4 transcript. A bundle is
//! authentic only when that two-component check has actually run — there is no API
//! that reports authenticity without it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use ctf_format::footer::ROOT_LEN;
use ctf_format::suite::{Role, SuiteError, suite};
use ctf_format::{Footer, MAGIC, verify_footer};

fn signed_footer(suite_id: u16) -> (Footer, ctf_format::HybridPublicKey) {
    let role = suite(suite_id).unwrap().signature().unwrap();
    let (sk, pk) = role.keypair().unwrap();

    let mut footer = Footer {
        root: [0x42; ROOT_LEN],
        sig_classical: vec![0u8; role.classical_signature_len()],
        sig_pq: vec![0u8; role.pq_signature_len()],
        total_len: 4096,
    };
    let transcript = footer.sig_input(suite_id);
    let signature = role.sign(&transcript, &sk).unwrap();
    footer.sig_classical = signature.classical;
    footer.sig_pq = signature.pq;
    (footer, pk)
}

#[test]
fn both_signatures_verify_over_the_transcript() {
    let (footer, pk) = signed_footer(1);
    let auth = verify_footer(1, &footer, &pk).unwrap();
    assert!(auth.is_authentic());
}

/// Suite 2 shares the same signature algorithms, so it round-trips too.
#[test]
fn suite_two_signatures_also_verify() {
    let (footer, pk) = signed_footer(2);
    verify_footer(2, &footer, &pk).unwrap();
}

#[test]
fn a_flipped_classical_bit_fails() {
    let (mut footer, pk) = signed_footer(1);
    footer.sig_classical[0] ^= 0x01;
    let err = verify_footer(1, &footer, &pk).unwrap_err();
    assert_eq!(
        err,
        SuiteError::VerificationFailed {
            component: "classical"
        }
    );
}

#[test]
fn a_flipped_post_quantum_bit_fails() {
    let (mut footer, pk) = signed_footer(1);
    let last = footer.sig_pq.len() - 1;
    footer.sig_pq[last] ^= 0x01;
    let err = verify_footer(1, &footer, &pk).unwrap_err();
    assert_eq!(err, SuiteError::VerificationFailed { component: "pq" });
}

#[test]
fn a_signature_under_one_suite_id_fails_under_another() {
    let (footer, pk) = signed_footer(1);
    // The transcript binds `suite_id`, so the same bytes do not verify as suite 2.
    let err = verify_footer(2, &footer, &pk).unwrap_err();
    assert!(matches!(err, SuiteError::VerificationFailed { .. }));
}

#[test]
fn the_wrong_public_key_fails() {
    let (footer, _pk) = signed_footer(1);
    let role = suite(1).unwrap().signature().unwrap();
    let (_sk2, other_pk) = role.keypair().unwrap();
    assert!(verify_footer(1, &footer, &other_pk).is_err());
}

/// An unsigned bundle authenticates nothing, and the API refuses to pretend
/// otherwise.
#[test]
fn an_unsigned_footer_is_never_authentic() {
    let footer = Footer {
        root: [0u8; ROOT_LEN],
        sig_classical: Vec::new(),
        sig_pq: Vec::new(),
        total_len: 4096,
    };
    let role = suite(1).unwrap().signature().unwrap();
    let (_sk, pk) = role.keypair().unwrap();
    let err = verify_footer(1, &footer, &pk).unwrap_err();
    assert!(matches!(err, SuiteError::Primitive { .. }));
}

/// A caller that constructs a footer with only one component cannot get an
/// authenticity result out of it, even though the container's parser would have
/// rejected such a footer first (F4, tested below).
#[test]
fn a_half_signed_footer_cannot_verify() {
    let (mut footer, pk) = signed_footer(1);
    footer.sig_pq.clear();
    assert!(verify_footer(1, &footer, &pk).is_err());
}

/// F4 at the container boundary: a footer carrying one signature of the hybrid pair
/// is rejected as a downgrade before any verifier sees it.
#[test]
fn the_parser_rejects_a_half_signed_footer() {
    let (footer, _pk) = signed_footer(1);

    // root ‖ classical_len ‖ pq_len(=0) ‖ classical sig ‖ total_len ‖ magic
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&footer.root);
    bytes.extend_from_slice(&(footer.sig_classical.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&footer.sig_classical);
    let total_len = 64 + bytes.len() + 16;
    bytes.extend_from_slice(&(total_len as u64).to_le_bytes());
    bytes.extend_from_slice(&MAGIC);

    let mut file = vec![0u8; 64];
    file.extend_from_slice(&bytes);
    let err = Footer::parse(&file, 64).unwrap_err();
    assert!(matches!(err, ctf_format::Error::Inconsistent { .. }));
}

#[test]
fn the_signature_role_resolves_for_suites_one_and_two() {
    for id in [1u16, 2] {
        let role = suite(id).unwrap().signature().unwrap();
        assert_eq!(role.classical_public_key_len(), 32);
        assert_eq!(role.classical_signature_len(), 64);
        assert_eq!(role.pq_public_key_len(), 1952);
        assert_eq!(role.pq_signature_len(), 3309);
    }
}

/// A minimal unsigned bundle: an OSINT challenge with a manifest only.
fn minimal_bundle() -> Vec<u8> {
    let manifest = ctf_format::Manifest::minimal("chal", "Title", &["manifest"]).unwrap();
    ctf_format::write_bundle(
        1,
        &[ctf_format::SectionSpec::inline(
            ctf_format::SectionKind::Manifest,
            0,
            ctf_format::SectionFlags::empty(),
            &manifest.encode().unwrap(),
        )],
    )
    .unwrap()
}

#[test]
fn an_unsigned_bundle_does_not_verify_through_the_bundle_api() {
    let file = minimal_bundle();
    let bundle = ctf_format::Bundle::parse(&file).unwrap();
    let role = suite(1).unwrap().signature().unwrap();
    let (_sk, pk) = role.keypair().unwrap();
    assert!(bundle.verify_signatures(&pk).is_err());
}

/// A bundle whose footer has been replaced by a signed one reads back and verifies.
/// The commitment root covers the header and section table, not the footer, so
/// swapping the footer does not move the root.
#[test]
fn a_signed_bundle_reads_back_and_verifies() {
    let file = minimal_bundle();
    let bundle = ctf_format::Bundle::parse(&file).unwrap();
    let suite_id = bundle.header.suite_id;
    let role = suite(suite_id).unwrap().signature().unwrap();
    let (sk, pk) = role.keypair().unwrap();

    let footer_len = 56 + role.classical_signature_len() + role.pq_signature_len();
    let mut footer = Footer {
        root: bundle.footer.root,
        sig_classical: vec![0u8; role.classical_signature_len()],
        sig_pq: vec![0u8; role.pq_signature_len()],
        total_len: bundle.header.footer_off + footer_len as u64,
    };
    let transcript = footer.sig_input(suite_id);
    let signature = role.sign(&transcript, &sk).unwrap();
    footer.sig_classical = signature.classical;
    footer.sig_pq = signature.pq;

    let mut signed = file[..bundle.header.footer_off as usize].to_vec();
    signed.extend_from_slice(&footer.to_bytes().unwrap());
    assert_eq!(signed.len() as u64, footer.total_len);

    let reparsed = ctf_format::Bundle::parse(&signed).unwrap();
    let auth = reparsed.verify_signatures(&pk).unwrap();
    assert!(auth.is_authentic());
}

/// Suite 3's hybrid signature includes SLH-DSA, which is not in this build, so the
/// role is reported as not implemented rather than silently reduced.
#[test]
fn the_archive_signature_role_is_not_implemented() {
    let err = suite(3).unwrap().signature().unwrap_err();
    assert_eq!(
        err,
        SuiteError::NotImplemented {
            suite: 3,
            role: Role::Signature
        }
    );
}
