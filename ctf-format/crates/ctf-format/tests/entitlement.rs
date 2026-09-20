//! Entitlement chain tests (ticket 39, spec §18, design §9).
//!
//! The chain is append-only and hash-linked, and every structural rule but E9 is a
//! pure function of the bundle's own bytes. These tests pin both halves: E1–E8 are
//! checked with no key at all, and E9 is checked against trusted keys supplied as
//! inputs. Every rejection mutates a known-good fixture by exactly one field.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use ctf_format::cbor::Value;
use ctf_format::suite::{Role, Signature, SuiteError, suite};
use ctf_format::{
    EntitlementChain, EntitlementRecord, HolderKeys, HybridPublicKey, RecordType, Timestamp,
    sig_input,
};

const SUITE: u16 = 1;
const GENESIS_ROOT: [u8; 32] = [0x11; 32];
const HOLDER_A: [u8; 32] = [0xA1; 32];
const HOLDER_B: [u8; 32] = [0xB2; 32];

fn signature_role() -> &'static dyn Signature {
    suite(SUITE).unwrap().signature().unwrap()
}

/// A valid genesis grant + transfer + progress, signed with the platform key and,
/// for the transfer, holder A's key.
fn build_signed_chain() -> (EntitlementChain, HybridPublicKey, HolderKeys) {
    let role = signature_role();
    let (platform_sk, platform_pk) = role.keypair().unwrap();
    let (holder_a_sk, holder_a_pk) = role.keypair().unwrap();
    let (_holder_b_sk, holder_b_pk) = role.keypair().unwrap();

    let mut genesis = EntitlementRecord {
        seq: 0,
        record_type: RecordType::Grant,
        challenge: "bird".into(),
        subject: "alice".into(),
        holder: HOLDER_A,
        prev: [0u8; 32],
        root: Some(GENESIS_ROOT),
        timestamp: Some(Timestamp::Uint(1_700_000_000)),
        payload: None,
        sig_holder: None,
        sig_platform: None,
    };
    let mut transfer = EntitlementRecord {
        seq: 1,
        record_type: RecordType::Transfer,
        challenge: "bird".into(),
        subject: "alice".into(),
        holder: HOLDER_B,
        prev: [0u8; 32],
        root: None,
        timestamp: None,
        payload: None,
        sig_holder: None,
        sig_platform: None,
    };
    let mut progress = EntitlementRecord {
        seq: 2,
        record_type: RecordType::Progress,
        challenge: "bird".into(),
        subject: "alice".into(),
        holder: HOLDER_B,
        prev: [0u8; 32],
        root: None,
        timestamp: Some(Timestamp::Nint(5)),
        payload: Some(vec![1, 2, 3]),
        sig_holder: None,
        sig_platform: None,
    };

    genesis.sign(SUITE, &platform_sk, None).unwrap();
    transfer.prev = genesis.record_id().unwrap();
    transfer
        .sign(SUITE, &platform_sk, Some(&holder_a_sk))
        .unwrap();
    progress.prev = transfer.record_id().unwrap();
    progress.sign(SUITE, &platform_sk, None).unwrap();

    let mut holders = HolderKeys::new();
    holders.insert(HOLDER_A, holder_a_pk);
    holders.insert(HOLDER_B, holder_b_pk);

    (
        EntitlementChain::from_records(vec![genesis, transfer, progress]),
        platform_pk,
        holders,
    )
}

#[test]
fn a_valid_chain_round_trips_and_validates() {
    let (chain, platform_pk, holders) = build_signed_chain();
    chain.validate().unwrap();

    let bytes = chain.encode().unwrap();
    let decoded = EntitlementChain::from_bytes(&bytes).unwrap();
    assert_eq!(decoded, chain);
    assert_eq!(decoded.encode().unwrap(), bytes);
    assert_eq!(decoded.len(), 3);
    assert_eq!(decoded.record_id(0).unwrap(), chain.record_id(0).unwrap());
    assert_eq!(decoded.get(1).unwrap().record_type, RecordType::Transfer);

    decoded
        .verify_signatures(SUITE, &platform_pk, &holders)
        .unwrap();
}

#[test]
fn both_signatures_verify_and_a_wrong_key_fails() {
    let (chain, platform_pk, holders) = build_signed_chain();
    chain
        .verify_signatures(SUITE, &platform_pk, &holders)
        .unwrap();

    let (_sk, wrong_platform) = signature_role().keypair().unwrap();
    let err = chain
        .verify_signatures(SUITE, &wrong_platform, &holders)
        .unwrap_err();
    assert!(matches!(err, SuiteError::VerificationFailed { .. }));

    let (_sk, wrong_holder) = signature_role().keypair().unwrap();
    let mut bad_holders = HolderKeys::new();
    bad_holders.insert(HOLDER_A, wrong_holder);
    let err = chain
        .verify_signatures(SUITE, &platform_pk, &bad_holders)
        .unwrap_err();
    assert_eq!(
        err,
        SuiteError::VerificationFailed {
            component: "classical"
        }
    );
}

#[test]
fn a_transfer_without_the_holders_key_in_the_resolver_fails() {
    let (chain, platform_pk, _holders) = build_signed_chain();
    let err = chain
        .verify_signatures(SUITE, &platform_pk, &HolderKeys::new())
        .unwrap_err();
    assert_eq!(
        err,
        SuiteError::InvalidKey {
            role: Role::Signature
        }
    );
}

#[test]
fn a_tampered_record_fails() {
    // Tampering the last record leaves the chain structurally intact (nothing
    // links to it), so only E9 can catch it.
    let (mut chain, platform_pk, holders) = build_signed_chain();
    chain.records_mut()[2].subject = "mallory".into();
    chain.validate().unwrap();
    let err = chain
        .verify_signatures(SUITE, &platform_pk, &holders)
        .unwrap_err();
    assert!(matches!(err, SuiteError::VerificationFailed { .. }));

    // Tampering a middle record also breaks the link its successor commits to.
    let (mut chain, _pk, _holders) = build_signed_chain();
    chain.records_mut()[1].subject = "mallory".into();
    assert!(chain.validate().is_err());
}

#[test]
fn a_flipped_signature_component_fails() {
    let (mut chain, platform_pk, holders) = build_signed_chain();
    chain.records_mut()[0]
        .sig_platform
        .as_mut()
        .unwrap()
        .classical[0] ^= 0x01;
    assert!(
        chain
            .verify_signatures(SUITE, &platform_pk, &holders)
            .is_err()
    );

    let (mut chain, platform_pk, holders) = build_signed_chain();
    chain.records_mut()[1].sig_holder.as_mut().unwrap().pq[0] ^= 0x01;
    assert!(
        chain
            .verify_signatures(SUITE, &platform_pk, &holders)
            .is_err()
    );
}

#[test]
fn a_broken_prev_link_fails() {
    let (mut chain, _pk, _holders) = build_signed_chain();
    chain.records_mut()[1].prev = [0xEE; 32];
    assert!(chain.validate().is_err());
}

#[test]
fn non_contiguous_seq_fails() {
    let (mut chain, _pk, _holders) = build_signed_chain();
    chain.records_mut()[2].seq = 5;
    assert!(chain.validate().is_err());
}

#[test]
fn a_bad_genesis_fails() {
    // Not a grant.
    let (mut chain, _pk, _holders) = build_signed_chain();
    chain.records_mut()[0].record_type = RecordType::Progress;
    assert!(chain.validate().is_err());

    // Missing root.
    let (mut chain, _pk, _holders) = build_signed_chain();
    chain.records_mut()[0].root = None;
    assert!(chain.validate().is_err());

    // Non-zero prev.
    let (mut chain, _pk, _holders) = build_signed_chain();
    chain.records_mut()[0].prev = [0x01; 32];
    assert!(chain.validate().is_err());
}

#[test]
fn root_on_a_non_genesis_record_fails() {
    let (mut chain, _pk, _holders) = build_signed_chain();
    chain.records_mut()[1].root = Some([0x03; 32]);
    assert!(chain.validate().is_err());
}

#[test]
fn the_genesis_root_must_equal_the_commitment_root() {
    let (chain, _pk, _holders) = build_signed_chain();
    chain.validate_against_root(&GENESIS_ROOT).unwrap();
    assert!(
        chain.validate_against_root(&[0x22; 32]).is_err(),
        "a grant for another bundle version must not validate"
    );
}

#[test]
fn a_transfer_without_a_holder_signature_fails() {
    let (mut chain, _pk, _holders) = build_signed_chain();
    chain.records_mut()[1].sig_holder = None;
    assert!(chain.validate().is_err());
}

#[test]
fn a_non_transfer_carrying_sig_holder_fails() {
    let (mut chain, _pk, _holders) = build_signed_chain();
    let holder_sig = chain.records()[1].sig_holder.clone();
    chain.records_mut()[0].sig_holder = holder_sig;
    assert!(chain.validate().is_err());
}

#[test]
fn a_record_without_a_platform_signature_fails() {
    let (mut chain, _pk, _holders) = build_signed_chain();
    chain.records_mut()[0].sig_platform = None;
    assert!(chain.validate().is_err());
}

#[test]
fn an_empty_chain_fails() {
    assert!(EntitlementChain::new().validate().is_err());
}

/// The transcript is `"ctf/entitlement-sig/v1" ‖ u16_le(suite_id) ‖ u32_le(seq) ‖
/// record_id` (§18.3), and the label is 22 ASCII bytes.
#[test]
fn the_transcript_is_the_specified_construction() {
    let id = [0x5A; 32];
    let transcript = sig_input(7, &id, 1);
    assert_eq!(&transcript[..22], b"ctf/entitlement-sig/v1");
    assert_eq!(&transcript[22..24], &1u16.to_le_bytes());
    assert_eq!(&transcript[24..28], &7u32.to_le_bytes());
    assert_eq!(&transcript[28..], &id);
    assert_eq!(transcript.len(), 60);
}

/// A genesis record map, for the E1/E2 tests that must not be representable through
/// the typed API. `holder_len` lets a caller produce the wrong-length case.
fn genesis_plaintext(seq: u64, holder_len: usize, extra: Option<(&str, Value)>) -> Vec<u8> {
    let mut entries = vec![
        (Value::Text("seq".into()), Value::Uint(seq)),
        (Value::Text("type".into()), Value::Text("grant".into())),
        (Value::Text("challenge".into()), Value::Text("bird".into())),
        (Value::Text("subject".into()), Value::Text("alice".into())),
        (
            Value::Text("holder".into()),
            Value::Bytes(vec![0u8; holder_len]),
        ),
        (Value::Text("prev".into()), Value::Bytes(vec![0u8; 32])),
        (Value::Text("root".into()), Value::Bytes(vec![0u8; 32])),
        (
            Value::Text("sig_platform".into()),
            Value::Map(vec![
                (Value::Text("classical".into()), Value::Bytes(vec![0u8; 64])),
                (Value::Text("pq".into()), Value::Bytes(vec![0u8; 3309])),
            ]),
        ),
    ];
    if let Some((key, value)) = extra {
        entries.push((Value::Text(key.into()), value));
    }
    Value::Array(vec![Value::Map(entries)]).encode().unwrap()
}

#[test]
fn an_unknown_record_key_fails() {
    let bytes = genesis_plaintext(0, 32, Some(("bogus", Value::Uint(1))));
    assert!(EntitlementChain::from_bytes(&bytes).is_err());
}

#[test]
fn a_wrong_length_holder_fails() {
    let bytes = genesis_plaintext(0, 31, None);
    assert!(EntitlementChain::from_bytes(&bytes).is_err());
}

#[test]
fn from_bytes_enforces_the_chain_rules() {
    // A single genesis record whose seq is not 0 violates E3.
    let bytes = genesis_plaintext(1, 32, None);
    assert!(EntitlementChain::from_bytes(&bytes).is_err());
}

#[test]
fn malformed_plaintext_fails() {
    let (chain, _pk, _holders) = build_signed_chain();
    let bytes = chain.encode().unwrap();

    // Trailing bytes after the array.
    let mut trailing = bytes.clone();
    trailing.push(0x00);
    assert!(EntitlementChain::from_bytes(&trailing).is_err());

    // Truncated inside the array.
    assert!(EntitlementChain::from_bytes(&bytes[..bytes.len() - 1]).is_err());

    // Not an array at all.
    let text = Value::Text("nope".into()).encode().unwrap();
    assert!(EntitlementChain::from_bytes(&text).is_err());

    // Non-canonical: `seq` 0 spelled in the two-byte form (`0x18 0x00`), which
    // `Value::decode` rejects before the schema is ever consulted (E1).
    let non_canonical = [0x81, 0xA1, 0x63, b's', b'e', b'q', 0x18, 0x00];
    assert!(EntitlementChain::from_bytes(&non_canonical).is_err());
}

#[test]
fn record_types_round_trip_through_their_names() {
    for name in ["grant", "transfer", "revoke", "progress"] {
        assert_eq!(RecordType::from_name(name).unwrap().name(), name);
    }
    assert!(RecordType::from_name("handoff").is_none());
}
