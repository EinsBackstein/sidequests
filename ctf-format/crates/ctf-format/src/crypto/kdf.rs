//! HKDF-SHA-256, the KDF every suite uses (design §7, spec §19).
//!
//! This is the `kdf` role. The hybrid KEM combiner ([`crate::crypto::hybrid_kem`])
//! is built on it: the combiner is HKDF over both shared secrets, so the KDF is
//! not a primitive any suite can omit.

use aws_lc_rs::hkdf::{HKDF_SHA256, KeyType, Salt};

use crate::suite::{Kdf, Role, SuiteError};

/// HKDF-SHA-256 (RFC 5869). The one KDF in the registry.
#[derive(Debug, Clone, Copy, Default)]
pub struct HkdfSha256;

impl HkdfSha256 {
    /// Construct the role.
    pub const fn new() -> Self {
        Self
    }
}

/// The output length an HKDF expansion produces. `aws-lc-rs` wants it as a type
/// implementing [`KeyType`], because the length is a compile-time property in the
/// general case.
struct OutLen(usize);

impl KeyType for OutLen {
    fn len(&self) -> usize {
        self.0
    }
}

impl Kdf for HkdfSha256 {
    fn derive(
        &self,
        ikm: &[u8],
        salt: &[u8],
        info: &[u8],
        out: &mut [u8],
    ) -> Result<(), SuiteError> {
        let salt = Salt::new(HKDF_SHA256, salt);
        let prk = salt.extract(ikm);
        let info = [info];
        let okm = prk
            .expand(&info, OutLen(out.len()))
            .map_err(|_| SuiteError::Primitive {
                role: Role::Kdf,
                reason: "HKDF expand rejected the output length",
            })?;
        okm.fill(out).map_err(|_| SuiteError::Primitive {
            role: Role::Kdf,
            reason: "HKDF output buffer length mismatch",
        })?;
        Ok(())
    }
}
