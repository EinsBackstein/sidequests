//! Sealed-progress and transfer tests (ticket 41, spec §18.3, §24).
//!
//! A handoff must be non-repudiable — the current holder signs the transfer — and
//! must not reset a multi-stage challenge, so the earned stages travel sealed to
//! the new holder's key. These tests pin both: the holder signature verifies only
//! against the holder named by the previous record, and the progress blob opens
//! only with the new holder's secret key.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use ctf_format::cbor::Value;
use ctf_format::suite::Signature;
use ctf_format::{
    EntitlementChain, HolderKeys, HybridPublicKey, Timestamp, VERSION_MAJOR, holder_hash,
    open_progress, seal_progress, suite,
};

const SUITE: u16 = 1;
const ROOT: [u8; 32] = [0x11; 32];

fn signature_role() -> &'static dyn Signature {
    suite(SUITE).unwrap().signature().unwrap()
}

/// A hybrid KEM keypair as `(secret, public)`.
fn kem_keypair() -> (Vec<u8>, Vec<u8>) {
    let pair = suite(SUITE).unwrap().kem().unwrap().generate().unwrap();
    (pair.secret_key, pair.public_key)
}

fn signing_keypair() -> (ctf_format::HybridSigningKey, HybridPublicKey) {
    signature_role().keypair().unwrap()
}

#[test]
fn progress_round_trips_to_the_new_holder() {
    let (secret, public) = kem_keypair();
    let plaintext = b"stages:1,2,3";

    let payload = seal_progress(SUITE, VERSION_MAJOR, &public, "bird", "alice", plaintext).unwrap();
    let opened = open_progress(SUITE, VERSION_MAJOR, &secret, "bird", "alice", &payload).unwrap();
    assert_eq!(opened, plaintext);
}

#[test]
fn a_wrong_holder_key_cannot_open_progress() {
    let (_secret, public) = kem_keypair();
    let (other_secret, _other_public) = kem_keypair();

    let payload = seal_progress(SUITE, VERSION_MAJOR, &public, "bird", "alice", b"secret").unwrap();
    assert!(
        open_progress(
            SUITE,
            VERSION_MAJOR,
            &other_secret,
            "bird",
            "alice",
            &payload
        )
        .is_err()
    );
}

#[test]
fn progress_is_bound_to_the_challenge_and_subject() {
    let (secret, public) = kem_keypair();
    let payload = seal_progress(SUITE, VERSION_MAJOR, &public, "bird", "alice", b"secret").unwrap();

    // Same key, same bytes, different AAD: the tag does not verify.
    assert!(open_progress(SUITE, VERSION_MAJOR, &secret, "bird", "bob", &payload).is_err());
    assert!(open_progress(SUITE, VERSION_MAJOR, &secret, "plant", "alice", &payload).is_err());
}

#[test]
fn a_tampered_progress_payload_fails() {
    let (secret, public) = kem_keypair();
    let mut payload =
        seal_progress(SUITE, VERSION_MAJOR, &public, "bird", "alice", b"secret").unwrap();
    // Flip one byte of the ciphertext region, not of the CBOR framing.
    let last = payload.len() - 1;
    payload[last] ^= 0x01;
    assert!(open_progress(SUITE, VERSION_MAJOR, &secret, "bird", "alice", &payload).is_err());
}

#[test]
fn a_payload_with_an_extra_key_is_rejected() {
    let (secret, public) = kem_keypair();
    let payload = seal_progress(SUITE, VERSION_MAJOR, &public, "bird", "alice", b"secret").unwrap();

    // Re-encode the same map with a third key: §24.1 fixes exactly two.
    let value = Value::decode(&payload).unwrap();
    let mut entries = value.as_map().unwrap().to_vec();
    entries.push((Value::Text("extra".into()), Value::Uint(1)));
    let tampered = Value::Map(entries).encode().unwrap();

    assert!(open_progress(SUITE, VERSION_MAJOR, &secret, "bird", "alice", &tampered).is_err());
}

#[test]
fn a_transfer_appends_a_holder_signed_record_and_carries_sealed_progress() {
    let (platform_sk, platform_pk) = signing_keypair();
    let (holder_a_sk, holder_a_pk) = signing_keypair();
    let (_holder_b_sk, holder_b_pk) = signing_keypair();
    let (holder_b_kem_secret, holder_b_kem_public) = kem_keypair();

    let mut chain = EntitlementChain::new();
    chain
        .append_grant(
            "bird",
            "alice",
            holder_hash(&holder_a_pk),
            ROOT,
            SUITE,
            &platform_sk,
            Some(Timestamp::Uint(1_700_000_000)),
        )
        .unwrap();

    let plaintext = b"stages:1,2";
    let payload = seal_progress(
        SUITE,
        VERSION_MAJOR,
        &holder_b_kem_public,
        "bird",
        "alice",
        plaintext,
    )
    .unwrap();
    chain
        .append_transfer(
            "bird",
            "alice",
            holder_hash(&holder_b_pk),
            SUITE,
            &platform_sk,
            &holder_a_sk,
            None,
            Some(payload.clone()),
        )
        .unwrap();

    // E1–E8 with no key.
    chain.validate().unwrap();
    assert_eq!(chain.len(), 2);

    // E9: the holder signature verifies against holder A, the predecessor.
    let mut holders = HolderKeys::new();
    holders.insert(holder_hash(&holder_a_pk), holder_a_pk);
    holders.insert(holder_hash(&holder_b_pk), holder_b_pk);
    chain
        .verify_signatures(SUITE, &platform_pk, &holders)
        .unwrap();

    // The progress survives the handoff, readable by the new holder only.
    let opened = open_progress(
        SUITE,
        VERSION_MAJOR,
        &holder_b_kem_secret,
        "bird",
        "alice",
        &payload,
    )
    .unwrap();
    assert_eq!(opened, plaintext);
}

#[test]
fn a_transfer_signed_by_the_wrong_holder_key_fails_verification() {
    let (platform_sk, platform_pk) = signing_keypair();
    let (_holder_a_sk, holder_a_pk) = signing_keypair();
    let (holder_b_sk, holder_b_pk) = signing_keypair();

    let mut chain = EntitlementChain::new();
    chain
        .append_grant(
            "bird",
            "alice",
            holder_hash(&holder_a_pk),
            ROOT,
            SUITE,
            &platform_sk,
            None,
        )
        .unwrap();
    // Sign with B's key while the chain says A is the current holder: the record
    // verifies structurally, but not against the key the predecessor names.
    chain
        .append_transfer(
            "bird",
            "alice",
            holder_hash(&holder_b_pk),
            SUITE,
            &platform_sk,
            &holder_b_sk,
            None,
            None,
        )
        .unwrap();
    chain.validate().unwrap();

    let mut holders = HolderKeys::new();
    holders.insert(holder_hash(&holder_a_pk), holder_a_pk);
    holders.insert(holder_hash(&holder_b_pk), holder_b_pk);
    assert!(
        chain
            .verify_signatures(SUITE, &platform_pk, &holders)
            .is_err()
    );
}
