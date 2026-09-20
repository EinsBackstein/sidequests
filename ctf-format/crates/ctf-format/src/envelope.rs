//! Key envelopes (design §7, spec §20.1–§20.2).
//!
//! A section's `content_key` is a fresh random 32-byte key (spec §20.2). It is
//! delivered to a named recipient by a KEM-DEM construction: the recipient's
//! hybrid KEM public key encapsulates a per-envelope key, and that key seals the
//! `content_key` under the suite's AEAD.
//!
//! ```text
//! (ct, kek) = KEM.encapsulate(recipient_public_key,
//!                 KemContext { suite_id, version_major, label: context })
//! wrapped   = AEAD.seal(kek, nonce = 0, aad, content_key)
//! aad       = "ctf/envelope/v1" ‖ u16_le(suite_id) ‖ LP(context)
//! ```
//!
//! `context` is one of `storage`, `seal`, `stage:<n>`, or `holder` (design §7).
//! It is bound twice: once into the KEM combiner's transcript (so a wrong-context
//! recipient derives a different `kek`) and once into the AEAD AAD, and a third
//! time as an explicit check on unwrap.
//!
//! # Why an all-zero AEAD nonce is safe here
//!
//! GCM and ChaCha20-Poly1305 fail catastrophically on a repeated `(key, nonce)`
//! pair, so a constant nonce looks alarming. It is safe **because each envelope's
//! `kek` is unique**: every [`Kem::encapsulate`](crate::suite::Kem::encapsulate)
//! call draws fresh randomness, so two envelopes never share a key and no pair can
//! repeat. Nonce *uniqueness*, not nonce unpredictability, is the property the
//! AEADs require, and a per-envelope key supplies it even with a zero nonce.
//! Reusing a `kek` for a second seal would break this, which is why an envelope is
//! produced once and never re-sealed under an existing `kek`.
//!
//! # CBOR schema
//!
//! A `keys` section (kind 7) carries envelopes as its plaintext, so an envelope is
//! a canonical-CBOR map (§7.1):
//!
//! | Key | Type | Value |
//! |---|---|---|
//! | `name_id` | uint | The identity of the section whose `content_key` this wraps |
//! | `context` | tstr | The recipient context, carried verbatim |
//! | `ct` | bstr | The hybrid KEM ciphertext |
//! | `wrapped` | bstr | The sealed content key (`content_key ‖ tag`) |
//!
//! Exactly these four keys; a missing, extra, or wrong-typed key is rejected.
//!
//! `name_id` is what lets one `keys` section serve every encrypted section in a
//! bundle: it is the section's own identity (§5.1), the value the STREAM nonce and
//! AAD already bind, so a recipient finds the envelope addressed to the section it
//! holds. It is not itself covered by the envelope AAD, but a mismatched `name_id`
//! still fails safe: the recovered content key is then used to decrypt a different
//! section, whose STREAM AAD binds its own `name_id`, so the tag does not verify.

use crate::cbor::Value;
use crate::suite::{KemContext, Role, SuiteError};

/// Domain label for the envelope AAD (design §7).
const ENVELOPE_AAD_LABEL: &[u8] = b"ctf/envelope/v1";

/// The content-key length. A content key is the frozen 32-byte root size (§12).
const CONTENT_KEY_LEN: usize = 32;

/// Build the AEAD additional authenticated data for an envelope:
/// `"ctf/envelope/v1" ‖ u16_le(suite_id) ‖ LP(context)`.
fn envelope_aad(suite_id: u16, context: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(ENVELOPE_AAD_LABEL.len() + 2 + 4 + context.len());
    aad.extend_from_slice(ENVELOPE_AAD_LABEL);
    aad.extend_from_slice(&suite_id.to_le_bytes());
    crate::crypto::lp(&mut aad, context.as_bytes());
    aad
}

/// A malformed-envelope error. The reason is static and never echoes input bytes.
fn malformed(reason: &'static str) -> SuiteError {
    SuiteError::Primitive {
        role: Role::Kem,
        reason,
    }
}

/// A content key wrapped to one named recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// The identity of the section whose `content_key` this envelope wraps
    /// (spec §5.1). One `keys` section can carry envelopes for many sections.
    pub name_id: u16,
    /// The recipient context: `storage`, `seal`, `stage:<n>`, or `holder`.
    pub context: String,
    /// The hybrid KEM ciphertext for the recipient.
    pub ciphertext: Vec<u8>,
    /// The content key sealed under the KEM-derived key.
    pub wrapped: Vec<u8>,
}

/// Seal a content key to a recipient's hybrid KEM public key.
///
/// The returned envelope is bound to `name_id` (the section whose key it carries)
/// and to `context`; unwrapping requires the exact same context (see
/// [`Envelope::open`]).
pub fn seal(
    content_key: &[u8; 32],
    recipient_public_key: &[u8],
    suite_id: u16,
    version_major: u16,
    name_id: u16,
    context: &str,
) -> Result<Envelope, SuiteError> {
    let suite = crate::suite::suite(suite_id)?;
    let kem = suite.kem()?;
    let aead = suite.aead()?;

    let kem_context = KemContext {
        suite_id,
        version_major,
        label: context.as_bytes(),
    };
    let (ciphertext, kek) = kem.encapsulate(recipient_public_key, &kem_context)?;

    // All-zero nonce, unique per-envelope `kek`; see the module docs.
    let nonce = vec![0u8; aead.nonce_len()];
    let aad = envelope_aad(suite_id, context);
    let wrapped = aead.seal(&kek, &nonce, &aad, content_key)?;

    Ok(Envelope {
        name_id,
        context: context.to_owned(),
        ciphertext,
        wrapped,
    })
}

impl Envelope {
    /// Unwrap the content key with the recipient's hybrid KEM secret key.
    ///
    /// `expected_context` is checked first, before any key material is touched, so
    /// an envelope addressed to another context is refused even when it would open
    /// cryptographically.
    pub fn open(
        &self,
        recipient_secret_key: &[u8],
        suite_id: u16,
        version_major: u16,
        expected_context: &str,
    ) -> Result<[u8; 32], SuiteError> {
        if self.context != expected_context {
            return Err(malformed(
                "envelope context does not match the expected context",
            ));
        }

        let suite = crate::suite::suite(suite_id)?;
        let kem = suite.kem()?;
        let aead = suite.aead()?;

        if self.ciphertext.len() != kem.ciphertext_len() {
            return Err(SuiteError::InvalidLength {
                role: Role::Kem,
                expected: kem.ciphertext_len(),
                got: self.ciphertext.len(),
            });
        }

        // The same context the sender bound: a different label changes the KEM
        // combiner transcript, so decapsulation derives a different `kek`.
        let kem_context = KemContext {
            suite_id,
            version_major,
            label: self.context.as_bytes(),
        };
        let kek = kem.decapsulate(recipient_secret_key, &self.ciphertext, &kem_context)?;

        // All-zero nonce, unique per-envelope `kek`; see the module docs.
        let nonce = vec![0u8; aead.nonce_len()];
        let aad = envelope_aad(suite_id, &self.context);
        let plaintext = aead.open(&kek, &nonce, &aad, &self.wrapped)?;
        crate::crypto::fixed::<CONTENT_KEY_LEN>(&plaintext, Role::Kem)
    }

    /// The envelope as a canonical-CBOR value: a map with `name_id`, `context`,
    /// `ct`, and `wrapped`.
    pub fn to_cbor(&self) -> Value {
        Value::Map(vec![
            (
                Value::Text("name_id".into()),
                Value::Uint(u64::from(self.name_id)),
            ),
            (
                Value::Text("context".into()),
                Value::Text(self.context.clone()),
            ),
            (
                Value::Text("ct".into()),
                Value::Bytes(self.ciphertext.clone()),
            ),
            (
                Value::Text("wrapped".into()),
                Value::Bytes(self.wrapped.clone()),
            ),
        ])
    }

    /// Decode an envelope from a CBOR value.
    ///
    /// Rejects a non-map, a missing key, a wrong-typed field, and any extra or
    /// duplicate key. Reasons are static; input bytes are never echoed.
    pub fn from_cbor(v: &Value) -> Result<Envelope, SuiteError> {
        let entries = v
            .as_map()
            .ok_or_else(|| malformed("envelope is not a CBOR map"))?;

        let mut name_id: Option<u16> = None;
        let mut context: Option<String> = None;
        let mut ciphertext: Option<Vec<u8>> = None;
        let mut wrapped: Option<Vec<u8>> = None;

        for (key, value) in entries {
            let name = key
                .as_text()
                .ok_or_else(|| malformed("envelope map key is not text"))?;
            match name {
                "name_id" => {
                    if name_id.is_some() {
                        return Err(malformed("envelope has a duplicate key"));
                    }
                    let raw = value
                        .as_uint()
                        .ok_or_else(|| malformed("envelope name_id is not an unsigned integer"))?;
                    name_id = Some(u16::try_from(raw).map_err(|_| {
                        malformed("envelope name_id is outside the u16 section identity space")
                    })?);
                }
                "context" => {
                    if context.is_some() {
                        return Err(malformed("envelope has a duplicate key"));
                    }
                    context = Some(
                        value
                            .as_text()
                            .ok_or_else(|| malformed("envelope context is not text"))?
                            .to_owned(),
                    );
                }
                "ct" => {
                    if ciphertext.is_some() {
                        return Err(malformed("envelope has a duplicate key"));
                    }
                    ciphertext = Some(
                        value
                            .as_bytes()
                            .ok_or_else(|| malformed("envelope ct is not bytes"))?
                            .to_vec(),
                    );
                }
                "wrapped" => {
                    if wrapped.is_some() {
                        return Err(malformed("envelope has a duplicate key"));
                    }
                    wrapped = Some(
                        value
                            .as_bytes()
                            .ok_or_else(|| malformed("envelope wrapped is not bytes"))?
                            .to_vec(),
                    );
                }
                _ => return Err(malformed("envelope has an unknown map key")),
            }
        }

        Ok(Envelope {
            name_id: name_id.ok_or_else(|| malformed("envelope is missing name_id"))?,
            context: context.ok_or_else(|| malformed("envelope is missing context"))?,
            ciphertext: ciphertext.ok_or_else(|| malformed("envelope is missing ct"))?,
            wrapped: wrapped.ok_or_else(|| malformed("envelope is missing wrapped"))?,
        })
    }

    /// Canonical-CBOR encoding of the envelope.
    pub fn to_bytes(&self) -> Result<Vec<u8>, SuiteError> {
        self.to_cbor()
            .encode()
            .map_err(|_| malformed("envelope CBOR encoding failed"))
    }

    /// Decode an envelope from canonical-CBOR bytes. A non-canonical encoding is
    /// rejected by the decoder before [`Envelope::from_cbor`] runs.
    pub fn from_bytes(b: &[u8]) -> Result<Envelope, SuiteError> {
        let value = Value::decode(b).map_err(|_| malformed("envelope is not canonical CBOR"))?;
        Self::from_cbor(&value)
    }
}
