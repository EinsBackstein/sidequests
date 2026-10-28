//! Suite 3's three-component hybrid signature (spec §20.3).
//!
//! Suite 3 is Ed25519 + ML-DSA-65 + SLH-DSA-SHA2-128s. The footer has two slots, so
//! the two post-quantum signatures share `sig_pq` in a fixed order. Every component
//! must verify; a failure of any one is a failure of the whole. Key generation and
//! signing are slow for SLH-DSA, so one fixture is shared by the tamper tests.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::sync::OnceLock;

use ctf_format::footer::ROOT_LEN;
use ctf_format::suite::{Role, SuiteError, suite};
use ctf_format::{
    Bundle, Footer, HybridPublicKey, HybridSignature, Manifest, SectionFlags, SectionKind,
    SectionSpec, sign_bundle, verify_footer, write_bundle,
};

const ML_DSA_65_SIGNATURE_LEN: usize = 3309;
const SLH_DSA_SIGNATURE_LEN: usize = 7856;
const PQ_SIGNATURE_LEN: usize = ML_DSA_65_SIGNATURE_LEN + SLH_DSA_SIGNATURE_LEN;

struct Fixture {
    public_key: HybridPublicKey,
    footer: Footer,
}

/// One suite-3 keypair and one signed footer, shared by the tests that only need a
/// valid starting point. SLH-DSA key generation and signing cost seconds, so paying
/// for them once is the difference between a test suite and a timeout.
fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let role = suite(3).unwrap().signature().unwrap();
        let (signing_key, public_key) = role.keypair().unwrap();

        let mut footer = Footer {
            root: [0x42; ROOT_LEN],
            sig_classical: vec![0u8; role.classical_signature_len()],
            sig_pq: vec![0u8; role.pq_signature_len()],
            total_len: 4096,
        };
        let transcript = footer.sig_input(3);
        let signature = role.sign(&transcript, &signing_key).unwrap();
        footer.sig_classical = signature.classical;
        footer.sig_pq = signature.pq;

        Fixture { public_key, footer }
    })
}

#[test]
fn suite_three_keypair_sign_verify_round_trips() {
    let f = fixture();
    let role = suite(3).unwrap().signature().unwrap();
    assert_eq!(f.footer.sig_classical.len(), 64);
    assert_eq!(f.footer.sig_pq.len(), PQ_SIGNATURE_LEN);
    assert_eq!(f.public_key.pq.len(), 1952 + 32);

    let auth = verify_footer(3, &f.footer, &f.public_key).unwrap();
    assert!(auth.is_authentic());
    role.verify(
        &f.footer.sig_input(3),
        &f.public_key,
        &HybridSignature {
            classical: f.footer.sig_classical.clone(),
            pq: f.footer.sig_pq.clone(),
        },
    )
    .unwrap();
}

#[test]
fn flipping_one_ml_dsa_byte_fails_verification() {
    let f = fixture();
    let mut footer = f.footer.clone();
    footer.sig_pq[0] ^= 0x01;
    assert_eq!(
        verify_footer(3, &footer, &f.public_key).unwrap_err(),
        SuiteError::VerificationFailed { component: "pq" }
    );
}

#[test]
fn flipping_one_slh_dsa_byte_fails_verification() {
    let f = fixture();
    let mut footer = f.footer.clone();
    // The SLH-DSA signature starts after the ML-DSA-65 half (§20.3).
    footer.sig_pq[ML_DSA_65_SIGNATURE_LEN] ^= 0x01;
    assert_eq!(
        verify_footer(3, &footer, &f.public_key).unwrap_err(),
        SuiteError::VerificationFailed {
            component: "slh-dsa"
        }
    );
}

#[test]
fn a_short_pq_signature_is_rejected_with_the_signature_role_named() {
    let f = fixture();
    let mut footer = f.footer.clone();
    footer.sig_pq.truncate(ML_DSA_65_SIGNATURE_LEN);
    assert_eq!(
        verify_footer(3, &footer, &f.public_key).unwrap_err(),
        SuiteError::InvalidLength {
            role: Role::Signature,
            expected: PQ_SIGNATURE_LEN,
            got: ML_DSA_65_SIGNATURE_LEN,
        }
    );
}

#[test]
fn a_pq_key_of_the_wrong_length_is_rejected_with_the_signature_role_named() {
    let f = fixture();
    let role = suite(3).unwrap().signature().unwrap();
    let mut public_key = f.public_key.clone();
    public_key.pq.truncate(1952);
    let signature = HybridSignature {
        classical: f.footer.sig_classical.clone(),
        pq: f.footer.sig_pq.clone(),
    };
    assert_eq!(
        role.verify(&f.footer.sig_input(3), &public_key, &signature)
            .unwrap_err(),
        SuiteError::InvalidKey {
            role: Role::Signature
        }
    );
}

/// Suites 1 and 2 keep their two-component layout: 64 and 3309 bytes.
#[test]
fn suites_one_and_two_still_sign_and_verify() {
    for suite_id in [1u16, 2] {
        let role = suite(suite_id).unwrap().signature().unwrap();
        let (signing_key, public_key) = role.keypair().unwrap();
        let mut footer = Footer {
            root: [0x11; ROOT_LEN],
            sig_classical: vec![0u8; role.classical_signature_len()],
            sig_pq: vec![0u8; role.pq_signature_len()],
            total_len: 4096,
        };
        let transcript = footer.sig_input(suite_id);
        let signature = role.sign(&transcript, &signing_key).unwrap();
        footer.sig_classical = signature.classical;
        footer.sig_pq = signature.pq;

        assert_eq!(footer.sig_classical.len(), 64);
        assert_eq!(footer.sig_pq.len(), 3309);
        verify_footer(suite_id, &footer, &public_key).unwrap();
    }
}

/// End to end: an unsigned suite-3 bundle is signed in place and reads back as
/// authentic, with the §20.3 slot sizes and nothing changed outside the footer.
#[test]
fn a_suite_three_bundle_signs_and_verifies_end_to_end() {
    let manifest = Manifest::minimal("archive", "Archive", &["manifest"])
        .unwrap()
        .encode()
        .unwrap();
    let unsigned = write_bundle(
        3,
        &[SectionSpec::inline(
            SectionKind::Manifest,
            0,
            SectionFlags::empty(),
            &manifest,
        )],
    )
    .unwrap();
    let footer_off = Bundle::parse(&unsigned).unwrap().header.footer_off as usize;

    let role = suite(3).unwrap().signature().unwrap();
    let (signing_key, public_key) = role.keypair().unwrap();
    let signed = sign_bundle(&unsigned, &signing_key, &public_key).unwrap();

    assert_eq!(&signed[..footer_off], &unsigned[..footer_off]);
    let parsed = Bundle::parse(&signed).unwrap();
    assert_eq!(parsed.footer.sig_classical.len(), 64);
    assert_eq!(parsed.footer.sig_pq.len(), PQ_SIGNATURE_LEN);
    assert_eq!(parsed.footer.total_len, signed.len() as u64);
    assert!(parsed.verify_signatures(&public_key).is_ok());

    // The same public key does not authenticate a tampered suite-3 file: flip one
    // byte inside `sig_pq`, which changes no field the parser validates.
    let mut tampered = signed.clone();
    let signature_start = footer_off + 40; // root ‖ the two length fields
    tampered[signature_start + 64 + ML_DSA_65_SIGNATURE_LEN + 1] ^= 0x01;
    assert!(
        Bundle::parse(&tampered)
            .unwrap()
            .verify_signatures(&public_key)
            .is_err()
    );
}

/// The suite-3 role does not silently reduce to two components: a signature carrying
/// only the ML-DSA half is the wrong width and is rejected by the primitive.
#[test]
fn a_two_component_suite_three_signature_is_refused() {
    let f = fixture();
    let role = suite(3).unwrap().signature().unwrap();
    let two_component = HybridSignature {
        classical: f.footer.sig_classical.clone(),
        pq: f.footer.sig_pq[..ML_DSA_65_SIGNATURE_LEN].to_vec(),
    };
    assert_eq!(
        role.verify(&f.footer.sig_input(3), &f.public_key, &two_component)
            .unwrap_err(),
        SuiteError::InvalidLength {
            role: Role::Signature,
            expected: PQ_SIGNATURE_LEN,
            got: ML_DSA_65_SIGNATURE_LEN,
        }
    );
}

/// `SLH_DSA_SIGNATURE_LEN` pins the dependency's parameter set: a bump that changed
/// it would fail here rather than silently moving the §20.3 slot layout.
#[test]
fn slh_dsa_signature_length_is_the_fips_parameter_set() {
    assert_eq!(SLH_DSA_SIGNATURE_LEN, 7856);
    assert_eq!(PQ_SIGNATURE_LEN, 11165);
    let role = suite(3).unwrap().signature().unwrap();
    assert_eq!(role.pq_signature_len(), PQ_SIGNATURE_LEN);
}
