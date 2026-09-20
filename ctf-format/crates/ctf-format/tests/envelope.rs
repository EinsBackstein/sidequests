//! Key envelope tests (ticket 14, spec §20.1–§20.2, design §7).
//!
//! An envelope is KEM-DEM: the recipient's hybrid public key encapsulates a
//! per-envelope key, and that key AEAD-seals the section's fresh content key. The
//! construction is bound to a named context (`storage`, `seal`, `stage:<n>`,
//! `holder`) three times over — in the KEM transcript, in the AEAD AAD, and in an
//! explicit unwrap check — so both a wrong key and a wrong context are refused.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use ctf_format::cbor::Value;
use ctf_format::envelope::{Envelope, seal};
use ctf_format::suite::{KemKeyPair, suite};

/// The contexts design §7 names, each round-tripped verbatim.
const CONTEXTS: [&str; 4] = ["storage", "seal", "stage:3", "holder"];

fn keypair(suite_id: u16) -> KemKeyPair {
    suite(suite_id).unwrap().kem().unwrap().generate().unwrap()
}

fn content_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = 0x9e;
    key[31] = 0x42;
    key
}

fn round_trip(suite_id: u16, context: &str) -> Envelope {
    let recipient = keypair(suite_id);
    let key = content_key();
    let envelope = seal(&key, &recipient.public_key, suite_id, 0, context).unwrap();
    let recovered = envelope
        .open(&recipient.secret_key, suite_id, 0, context)
        .unwrap();
    assert_eq!(recovered, key, "suite {suite_id}, context {context}");
    assert_eq!(
        envelope.context, context,
        "context must be carried verbatim"
    );
    envelope
}

/// Acceptance 1: the content key survives a full envelope round trip on both
/// implemented suites.
#[test]
fn a_content_key_round_trips_on_suite_1() {
    round_trip(1, "storage");
}

#[test]
fn a_content_key_round_trips_on_suite_2() {
    round_trip(2, "storage");
}

/// Acceptance 2: every context round-trips on both suites and is carried verbatim.
#[test]
fn every_context_round_trips_and_is_carried_verbatim() {
    for suite_id in [1u16, 2] {
        for context in CONTEXTS {
            let envelope = round_trip(suite_id, context);
            assert_eq!(envelope.context, context);
        }
    }
}

/// Acceptance 3: a recipient holding the wrong secret key cannot unwrap. The KEM
/// derives a different `kek`, so the AEAD tag fails.
#[test]
fn a_recipient_without_the_matching_secret_key_cannot_unwrap() {
    for suite_id in [1u16, 2] {
        let intended = keypair(suite_id);
        let other = keypair(suite_id);
        let key = content_key();

        let envelope = seal(&key, &intended.public_key, suite_id, 0, "storage").unwrap();
        let result = envelope.open(&other.secret_key, suite_id, 0, "storage");
        assert!(
            result.is_err(),
            "suite {suite_id}: an unrelated secret key must not unwrap"
        );
    }
}

/// Acceptance 4: a wrong context is refused even with the matching secret key. The
/// explicit check rejects before any key material is used.
#[test]
fn a_wrong_context_is_refused_even_with_a_valid_key() {
    for suite_id in [1u16, 2] {
        let recipient = keypair(suite_id);
        let key = content_key();

        let envelope = seal(&key, &recipient.public_key, suite_id, 0, "storage").unwrap();
        let result = envelope.open(&recipient.secret_key, suite_id, 0, "seal");
        assert!(
            result.is_err(),
            "suite {suite_id}: an envelope sealed to `storage` must not open as `seal`"
        );
    }
}

/// Acceptance 5: encode/decode round-trips through both the `Value` and byte APIs.
#[test]
fn an_envelope_round_trips_through_canonical_cbor() {
    for suite_id in [1u16, 2] {
        for context in CONTEXTS {
            let recipient = keypair(suite_id);
            let key = content_key();
            let envelope = seal(&key, &recipient.public_key, suite_id, 0, context).unwrap();

            let via_value = Envelope::from_cbor(&envelope.to_cbor()).unwrap();
            assert_eq!(via_value, envelope);
            assert_eq!(via_value.context, context);

            let bytes = envelope.to_bytes().unwrap();
            let via_bytes = Envelope::from_bytes(&bytes).unwrap();
            assert_eq!(via_bytes, envelope);

            // Decoding preserves the binding, so the decoded envelope still opens.
            let back = via_bytes
                .open(&recipient.secret_key, suite_id, 0, context)
                .unwrap();
            assert_eq!(back, key);
        }
    }
}

/// A map missing a required key is rejected.
#[test]
fn a_cbor_map_missing_a_key_is_rejected() {
    let envelope = seal(&content_key(), &keypair(1).public_key, 1, 0, "storage").unwrap();

    let Value::Map(mut entries) = envelope.to_cbor() else {
        panic!("envelope must encode as a map");
    };
    entries.retain(|(k, _)| k.as_text() != Some("wrapped"));
    assert!(Envelope::from_cbor(&Value::Map(entries)).is_err());
}

/// An extra key is rejected: the schema is exactly three keys.
#[test]
fn a_cbor_map_with_an_extra_key_is_rejected() {
    let envelope = seal(&content_key(), &keypair(1).public_key, 1, 0, "storage").unwrap();
    let Value::Map(mut entries) = envelope.to_cbor() else {
        panic!("envelope must encode as a map");
    };
    entries.push((Value::Text("extra".into()), Value::Uint(1)));
    assert!(Envelope::from_cbor(&Value::Map(entries)).is_err());
}

/// A field of the wrong type is rejected.
#[test]
fn a_cbor_map_with_a_wrong_typed_field_is_rejected() {
    let envelope = seal(&content_key(), &keypair(1).public_key, 1, 0, "storage").unwrap();
    let Value::Map(mut entries) = envelope.to_cbor() else {
        panic!("envelope must encode as a map");
    };
    for (key, value) in entries.iter_mut() {
        if key.as_text() == Some("ct") {
            *value = Value::Text("not bytes".into());
        }
    }
    assert!(Envelope::from_cbor(&Value::Map(entries)).is_err());
}

/// A non-map outermost value is rejected.
#[test]
fn a_non_map_envelope_is_rejected() {
    assert!(Envelope::from_cbor(&Value::Uint(0)).is_err());
    assert!(Envelope::from_cbor(&Value::Bytes(vec![])).is_err());
    assert!(Envelope::from_bytes(b"").is_err());
}

/// Truncated or trailing bytes are rejected by the canonical decoder.
#[test]
fn corrupted_cbor_bytes_are_rejected() {
    let envelope = seal(&content_key(), &keypair(1).public_key, 1, 0, "storage").unwrap();
    let bytes = envelope.to_bytes().unwrap();

    let truncated = &bytes[..bytes.len() - 1];
    assert!(Envelope::from_bytes(truncated).is_err());

    let mut appended = bytes.clone();
    appended.push(0);
    assert!(Envelope::from_bytes(&appended).is_err());
}
