//! Sealed progress payloads (spec §24, design §9).
//!
//! A `progress` record's `payload` carries the stages a subject has already
//! earned, sealed to the **new** holder's hybrid KEM key, so a handoff mid
//! multi-stage challenge does not reset progress. The chain itself treats the
//! payload as opaque; this module is what gives it a shape.
//!
//! # Shape
//!
//! ```text
//! payload = CBOR map {
//!     "envelope": <key envelope §21.3, context "holder", name_id 0>,
//!     "ct":       AEAD.seal(content_key, nonce = 0,
//!                   aad = "ctf/progress/v1" ‖ u16_le(suite_id)
//!                         ‖ LP(challenge) ‖ LP(subject),
//!                   plaintext)
//! }
//! ```
//!
//! The envelope wraps a fresh content key to the holder; the AEAD binds the
//! challenge and subject into the AAD, so a payload cannot be replayed under a
//! different challenge or subject. The all-zero AEAD nonce is safe for the same
//! reason an envelope's is (spec §21.1): the content key is fresh per payload, so
//! no `(key, nonce)` pair ever repeats.
//!
//! A reader without the holder's KEM secret key cannot recover the plaintext
//! (rule P4).

use crate::cbor::Value;
use crate::crypto::lp;
use crate::envelope::Envelope;
use crate::suite::{Role, SuiteError};

/// Domain label for the progress AAD (spec §24.2). 16 ASCII bytes.
pub const PROGRESS_AAD_LABEL: &[u8] = b"ctf/progress/v1";

/// The recipient context a progress payload's envelope is bound to (rule P2).
pub const HOLDER_CONTEXT: &str = "holder";

/// The `name_id` an envelope inside a progress payload carries. A progress payload
/// wraps a content key rather than a section's, and no section has this identity
/// for that purpose.
const PROGRESS_NAME_ID: u16 = 0;

/// A malformed-payload error. Static, so a diagnostic cannot become an oracle.
fn malformed(reason: &'static str) -> SuiteError {
    SuiteError::Primitive {
        role: Role::Aead,
        reason,
    }
}

/// `"ctf/progress/v1" ‖ u16_le(suite_id) ‖ LP(challenge) ‖ LP(subject)`.
fn progress_aad(suite_id: u16, challenge: &str, subject: &str) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(PROGRESS_AAD_LABEL);
    aad.extend_from_slice(&suite_id.to_le_bytes());
    lp(&mut aad, challenge.as_bytes());
    lp(&mut aad, subject.as_bytes());
    aad
}

/// Seal `plaintext` to a new holder's hybrid KEM public key.
///
/// Returns the canonical-CBOR payload bytes a `progress` record carries. The
/// caller places them in [`crate::EntitlementRecord::payload`].
pub fn seal_progress(
    suite_id: u16,
    version_major: u16,
    holder_public_key: &[u8],
    challenge: &str,
    subject: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, SuiteError> {
    let suite = crate::suite::suite(suite_id)?;
    let aead = suite.aead()?;
    let content_key = crate::crypto::stream::fresh_content_key(aead)?;

    let envelope = crate::envelope::seal(
        content_key
            .as_slice()
            .try_into()
            .map_err(|_| malformed("fresh content key is not the frozen 32-byte size"))?,
        holder_public_key,
        suite_id,
        version_major,
        PROGRESS_NAME_ID,
        HOLDER_CONTEXT,
    )?;

    let nonce = vec![0u8; aead.nonce_len()];
    let aad = progress_aad(suite_id, challenge, subject);
    let ct = aead.seal(&content_key, &nonce, &aad, plaintext)?;

    Value::Map(vec![
        (Value::Text("envelope".into()), envelope.to_cbor()),
        (Value::Text("ct".into()), Value::Bytes(ct)),
    ])
    .encode()
    .map_err(|_| malformed("progress payload could not be encoded"))
}

/// Recover the plaintext with the holder's hybrid KEM secret key.
pub fn open_progress(
    suite_id: u16,
    version_major: u16,
    holder_secret_key: &[u8],
    challenge: &str,
    subject: &str,
    payload: &[u8],
) -> Result<Vec<u8>, SuiteError> {
    let value =
        Value::decode(payload).map_err(|_| malformed("progress payload is not canonical CBOR"))?;
    let entries = value
        .as_map()
        .ok_or_else(|| malformed("progress payload is not a CBOR map"))?;
    // Exactly the two keys of §24.1: a payload with any other shape is a different
    // structure, not a progress payload this version understands.
    if entries.len() != 2 {
        return Err(malformed(
            "progress payload does not have exactly `envelope` and `ct`",
        ));
    }
    let envelope_value = value
        .get("envelope")
        .ok_or_else(|| malformed("progress payload is missing `envelope`"))?;
    let ct = value
        .get("ct")
        .and_then(Value::as_bytes)
        .ok_or_else(|| malformed("progress payload is missing `ct` or it is not bytes"))?;
    let envelope = Envelope::from_cbor(envelope_value)?;

    // `open` checks the context before touching key material, so an envelope bound
    // to another context is refused (rule P2).
    let content_key = envelope.open(holder_secret_key, suite_id, version_major, HOLDER_CONTEXT)?;

    let suite = crate::suite::suite(suite_id)?;
    let aead = suite.aead()?;
    let nonce = vec![0u8; aead.nonce_len()];
    let aad = progress_aad(suite_id, challenge, subject);
    aead.open(&content_key, &nonce, &aad, ct)
}
