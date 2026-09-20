//! Cross-implementation primitive vectors (ticket 17).
//!
//! Every suite role — `hash`, `kdf`, `kem`, `aead`, `signature` — is checked
//! against a committed vector whose `expected` value came from a second,
//! independent implementation. Provenance for each role is documented in
//! `spec/vectors/generate.py`, which writes both artifacts together:
//!
//! - `spec/vectors/primitives.json` — human-readable, hex.
//! - `tests/vectors/vectors_data.rs` — the same data as plain Rust, pulled in
//!   below with `include!` (a `tests/vectors/` subdirectory is used because
//!   cargo treats every top-level `tests/*.rs` as its own test target).
//!
//! The test is hermetic: it never invokes openssl and never touches the network.
//! A deliberate one-bit corruption of every vector is checked to fail, and the
//! committed JSON is asserted to contain the committed Rust data.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines
)]

use ctf_format::suite::{HybridPublicKey, HybridSignature, HybridSigningKey, KemContext, suite};

include!("vectors/vectors_data.rs");

/// The `version_major` the committed vectors were built against (spec §12).
const VERSION_MAJOR: u16 = 0;

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn flip_bit(bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[0] ^= 0x01;
    out
}

fn first(role: &str) -> &'static Vector {
    VECTORS
        .iter()
        .find(|v| v.role == role)
        .unwrap_or_else(|| panic!("no vector for role {role}"))
}

#[test]
fn every_role_has_at_least_one_vector() {
    for role in ["hash", "kdf", "kem", "aead", "signature"] {
        assert!(
            VECTORS.iter().any(|v| v.role == role),
            "role {role} has no committed vector"
        );
    }
}

#[test]
fn hash_vectors_match_the_second_implementation() {
    let mut count = 0;
    for v in VECTORS.iter().filter(|v| v.role == "hash") {
        let got = suite(v.suite).unwrap().hash().hash(v.inputs[0]);
        assert_eq!(
            got.as_slice(),
            v.expected,
            "hash vector {} did not reproduce",
            v.name
        );
        count += 1;
    }
    assert!(count >= 3, "expected several hash vectors, got {count}");
}

#[test]
fn kdf_vectors_match_the_second_implementation() {
    for v in VECTORS.iter().filter(|v| v.role == "kdf") {
        let mut out = vec![0u8; v.expected.len()];
        suite(v.suite)
            .unwrap()
            .kdf()
            .unwrap()
            .derive(v.inputs[0], v.inputs[1], v.inputs[2], &mut out)
            .unwrap();
        assert_eq!(out, v.expected, "kdf vector {} did not reproduce", v.name);
    }
}

#[test]
fn aead_vectors_seal_and_open_match_the_second_implementation() {
    for v in VECTORS.iter().filter(|v| v.role == "aead") {
        let aead = suite(v.suite).unwrap().aead().unwrap();
        let sealed = aead
            .seal(v.inputs[0], v.inputs[1], v.inputs[2], v.inputs[3])
            .unwrap();
        assert_eq!(
            sealed, v.expected,
            "aead vector {} sealed differently",
            v.name
        );
        let opened = aead
            .open(v.inputs[0], v.inputs[1], v.inputs[2], v.expected)
            .unwrap();
        assert_eq!(
            opened, v.inputs[3],
            "aead vector {} opened differently",
            v.name
        );
    }
    // Both suites are covered.
    assert!(VECTORS.iter().any(|v| v.role == "aead" && v.suite == 1));
    assert!(VECTORS.iter().any(|v| v.role == "aead" && v.suite == 2));
}

#[test]
fn signature_vectors_verify_the_second_implementation() {
    for v in VECTORS.iter().filter(|v| v.role == "signature") {
        let role = suite(v.suite).unwrap().signature().unwrap();
        let public_key = HybridPublicKey {
            classical: v.inputs[0].to_vec(),
            pq: v.inputs[1].to_vec(),
        };
        let signature = HybridSignature {
            classical: v.inputs[3].to_vec(),
            pq: v.inputs[4].to_vec(),
        };
        role.verify(v.inputs[2], &public_key, &signature)
            .unwrap_or_else(|e| panic!("signature vector {} failed: {e}", v.name));
    }
}

/// The reverse direction for Ed25519, which is deterministic: signing the
/// committed transcript with the committed seed must reproduce the exact
/// signature Python produced. The crate-produced hybrid signature must also
/// verify through the crate's own two-component check.
#[test]
fn a_crate_signature_reproduces_the_second_implementations_ed25519() {
    let v = first("signature");
    let role = suite(v.suite).unwrap().signature().unwrap();
    let signing_key = HybridSigningKey {
        classical: v.inputs[5].to_vec(),
        pq: v.inputs[6].to_vec(),
    };
    let produced = role.sign(v.inputs[2], &signing_key).unwrap();
    assert_eq!(
        produced.classical, v.inputs[3],
        "Ed25519 is deterministic; the crate must reproduce the committed signature"
    );
    let public_key = HybridPublicKey {
        classical: v.inputs[0].to_vec(),
        pq: v.inputs[1].to_vec(),
    };
    role.verify(v.inputs[2], &public_key, &produced)
        .expect("the crate's own signature must verify");
}

#[test]
fn kem_vectors_match_the_second_implementation() {
    for v in VECTORS.iter().filter(|v| v.role == "kem") {
        let context = KemContext {
            suite_id: v.suite,
            version_major: VERSION_MAJOR,
            label: v.inputs[2],
        };
        let key = suite(v.suite)
            .unwrap()
            .kem()
            .unwrap()
            .decapsulate(v.inputs[0], v.inputs[1], &context)
            .unwrap_or_else(|e| panic!("kem vector {} failed: {e}", v.name));
        assert_eq!(
            key.as_slice(),
            v.expected,
            "kem vector {} derived a different content key",
            v.name
        );
    }
}

/// "A deliberate one-bit corruption fails each vector": flip one bit of the
/// authenticated input (or, when the input is empty, of the expected value) and
/// require the crate's check to reject or disagree.
#[test]
fn a_deliberate_one_bit_corruption_fails_every_vector() {
    for v in VECTORS {
        assert!(
            corruption_detected(v),
            "a one-bit flip did not disturb {} vector {}",
            v.role,
            v.name
        );
    }
}

fn corruption_detected(v: &Vector) -> bool {
    match v.role {
        "hash" => {
            let (data, expected) = if v.inputs[0].is_empty() {
                (v.inputs[0].to_vec(), flip_bit(v.expected))
            } else {
                (flip_bit(v.inputs[0]), v.expected.to_vec())
            };
            suite(v.suite).unwrap().hash().hash(&data).as_slice() != expected.as_slice()
        }
        "kdf" => {
            let data = flip_bit(v.inputs[0]);
            let mut out = vec![0u8; v.expected.len()];
            suite(v.suite)
                .unwrap()
                .kdf()
                .unwrap()
                .derive(&data, v.inputs[1], v.inputs[2], &mut out)
                .unwrap();
            out.as_slice() != v.expected
        }
        "aead" => {
            let aead = suite(v.suite).unwrap().aead().unwrap();
            let tampered = flip_bit(v.expected);
            match aead.open(v.inputs[0], v.inputs[1], v.inputs[2], &tampered) {
                Ok(plaintext) => plaintext.as_slice() != v.inputs[3],
                Err(_) => true,
            }
        }
        "signature" => {
            let signature = HybridSignature {
                classical: flip_bit(v.inputs[3]),
                pq: v.inputs[4].to_vec(),
            };
            let public_key = HybridPublicKey {
                classical: v.inputs[0].to_vec(),
                pq: v.inputs[1].to_vec(),
            };
            suite(v.suite)
                .unwrap()
                .signature()
                .unwrap()
                .verify(v.inputs[2], &public_key, &signature)
                .is_err()
        }
        "kem" => {
            let context = KemContext {
                suite_id: v.suite,
                version_major: VERSION_MAJOR,
                label: v.inputs[2],
            };
            let tampered = flip_bit(v.inputs[1]);
            match suite(v.suite).unwrap().kem().unwrap().decapsulate(
                v.inputs[0],
                &tampered,
                &context,
            ) {
                Ok(key) => key.as_slice() != v.expected,
                Err(_) => true,
            }
        }
        other => panic!("unknown role {other}"),
    }
}

/// The two committed artifacts are written by one run of the generator. This
/// asserts the JSON contains every vector the Rust module carries, so a hand
/// edit to either file is caught.
#[test]
fn committed_json_and_rust_data_agree() {
    let json = include_str!("../../../spec/vectors/primitives.json");
    assert!(json.contains("\"generated_by\": \"spec/vectors/generate.py\""));
    for v in VECTORS {
        assert!(json.contains(v.name), "json is missing vector {}", v.name);
        assert!(
            json.contains(&format!("\"role\": \"{}\"", v.role)),
            "json is missing role {}",
            v.role
        );
        if !v.expected.is_empty() {
            assert!(
                json.contains(&to_hex(v.expected)),
                "json is missing expected output of {}",
                v.name
            );
        }
        for input in v.inputs {
            if !input.is_empty() {
                assert!(
                    json.contains(&to_hex(input)),
                    "json is missing an input of {}",
                    v.name
                );
            }
        }
    }
}
