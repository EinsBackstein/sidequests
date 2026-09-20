//! The phase 2 cryptographic constructions, behind the suite traits of
//! [`crate::suite`].
//!
//! Normative: `spec/SPEC.md` §20 (the constructions this module implements).
//! Rationale: design §7. Nothing here moves a byte of the container: each
//! primitive plugs into a trait the suite registry already exposes, and
//! `suite_id` selects which one is used.
//!
//! # Hybrid by construction
//!
//! An attacker must break **both** halves. The classical component comes from
//! audited AWS-LC (`aws-lc-rs`): AES-256-GCM, X25519, Ed25519, HKDF-SHA-256. The
//! post-quantum component comes from the pure-Rust RustCrypto FIPS 203/204
//! implementations, which are independent code and therefore a genuinely separate
//! thing to break. ML-DSA is the least settled primitive in the stack, so it lives
//! behind [`crate::suite::Signature`] where `suite_id` can retire it without a
//! format change (design §7).
//!
//! # Encoding rule
//!
//! Every `‖` in these constructions joins **fixed-width fields only**, except
//! where [`lp`] length-prefixes a variable-length input. Without the prefix,
//! `chal ‖ subject` has two spellings for two different subjects — the ambiguity
//! design §7 exists to close.

pub mod aead;
pub mod hybrid_kem;
pub mod kdf;
pub mod sign;
pub mod stream;

/// `LP(x) = u32_le(len(x)) ‖ x`.
///
/// The length prefix is what makes concatenation injective. A transcript that
/// mixes variable-length fields without it can be steered: `("ab","c")` and
/// `("a","bc")` are the same bytes, so two different inputs derive the same key.
pub fn lp(out: &mut Vec<u8>, x: &[u8]) {
    let len = u32::try_from(x.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(x);
}

/// Fill `out` with bytes from the system CSPRNG.
///
/// Used for fresh content keys (spec §20.2: every encryption draws a fresh
/// `content_key`, which is what removes the need for a `key_epoch` in the
/// nonce) and for X25519 or Ed25519 secret material.
pub(crate) fn random_bytes(
    out: &mut [u8],
    role: crate::suite::Role,
) -> Result<(), crate::suite::SuiteError> {
    aws_lc_rs::rand::fill(out).map_err(|_| crate::suite::SuiteError::Primitive {
        role,
        reason: "system random source failed",
    })
}

/// Truncate `b` to a fixed-width array, mapping the failure to the role that asked.
pub(crate) fn fixed<const N: usize>(
    b: &[u8],
    role: crate::suite::Role,
) -> Result<[u8; N], crate::suite::SuiteError> {
    <[u8; N]>::try_from(b).map_err(|_| crate::suite::SuiteError::InvalidLength {
        role,
        expected: N,
        got: b.len(),
    })
}
