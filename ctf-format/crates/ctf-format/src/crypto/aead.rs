//! The two per-message AEADs the registry selects: AES-256-GCM (suite 1) and
//! XChaCha20-Poly1305 (suite 2).
//!
//! Normative: `spec/SPEC.md` §20.2. This is the per-message primitive; the chunked
//! STREAM construction that gives it reorder/truncation resistance is
//! [`crate::crypto::stream`].
//!
//! AES-256-GCM comes from audited AWS-LC, which is also where the AES-NI / ARMv8
//! acceleration lives (design §7). XChaCha20-Poly1305 is not exposed by AWS-LC —
//! its ChaCha is the 12-byte-nonce variant — so suite 2's AEAD is the RustCrypto
//! `chacha20poly1305` implementation, which is independent code.

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use chacha20poly1305::aead::{Aead as _, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::suite::{Aead, Role, SuiteError};

const AES_KEY_LEN: usize = 32;
const AES_NONCE_LEN: usize = 12;
const CHACHA_KEY_LEN: usize = 32;
const CHACHA_NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

fn primitive(message: &'static str) -> SuiteError {
    SuiteError::Primitive {
        role: Role::Aead,
        reason: message,
    }
}

/// AES-256-GCM (suite 1). The default when AES acceleration is present.
#[derive(Debug, Clone, Copy, Default)]
pub struct Aes256Gcm;

impl Aes256Gcm {
    /// Construct the role.
    pub const fn new() -> Self {
        Self
    }
}

fn aes_key(key: &[u8]) -> Result<LessSafeKey, SuiteError> {
    let unbound = UnboundKey::new(&AES_256_GCM, key).map_err(|_| SuiteError::InvalidLength {
        role: Role::Aead,
        expected: AES_KEY_LEN,
        got: key.len(),
    })?;
    Ok(LessSafeKey::new(unbound))
}

impl Aead for Aes256Gcm {
    fn key_len(&self) -> usize {
        AES_KEY_LEN
    }

    fn nonce_len(&self) -> usize {
        AES_NONCE_LEN
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn seal(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, SuiteError> {
        let key = aes_key(key)?;
        let nonce =
            Nonce::try_assume_unique_for_key(nonce).map_err(|_| SuiteError::InvalidLength {
                role: Role::Aead,
                expected: AES_NONCE_LEN,
                got: nonce.len(),
            })?;
        let mut in_out = plaintext.to_vec();
        key.seal_in_place_append_tag(nonce, Aad::from(aad), &mut in_out)
            .map_err(|_| primitive("AES-256-GCM sealing failed"))?;
        Ok(in_out)
    }

    fn open(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SuiteError> {
        let key = aes_key(key)?;
        let nonce =
            Nonce::try_assume_unique_for_key(nonce).map_err(|_| SuiteError::InvalidLength {
                role: Role::Aead,
                expected: AES_NONCE_LEN,
                got: nonce.len(),
            })?;
        let mut in_out = ciphertext.to_vec();
        let plaintext = key
            .open_in_place(nonce, Aad::from(aad), &mut in_out)
            .map_err(|_| primitive("AES-256-GCM authentication failed"))?;
        Ok(plaintext.to_vec())
    }
}

/// XChaCha20-Poly1305 (suite 2). The fallback for hosts without AES acceleration.
#[derive(Debug, Clone, Copy, Default)]
pub struct XChaCha20Poly1305Aead;

impl XChaCha20Poly1305Aead {
    /// Construct the role.
    pub const fn new() -> Self {
        Self
    }
}

fn chacha_key(key: &[u8]) -> Result<XChaCha20Poly1305, SuiteError> {
    XChaCha20Poly1305::new_from_slice(key).map_err(|_| SuiteError::InvalidLength {
        role: Role::Aead,
        expected: CHACHA_KEY_LEN,
        got: key.len(),
    })
}

impl Aead for XChaCha20Poly1305Aead {
    fn key_len(&self) -> usize {
        CHACHA_KEY_LEN
    }

    fn nonce_len(&self) -> usize {
        CHACHA_NONCE_LEN
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn seal(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, SuiteError> {
        let cipher = chacha_key(key)?;
        let nonce = XNonce::try_from(nonce).map_err(|_| SuiteError::InvalidLength {
            role: Role::Aead,
            expected: CHACHA_NONCE_LEN,
            got: nonce.len(),
        })?;
        cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| primitive("XChaCha20-Poly1305 sealing failed"))
    }

    fn open(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SuiteError> {
        let cipher = chacha_key(key)?;
        let nonce = XNonce::try_from(nonce).map_err(|_| SuiteError::InvalidLength {
            role: Role::Aead,
            expected: CHACHA_NONCE_LEN,
            got: nonce.len(),
        })?;
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| primitive("XChaCha20-Poly1305 authentication failed"))
    }
}
