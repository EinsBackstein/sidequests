//! The hybrid signature: Ed25519 + ML-DSA-65, both over the identical transcript.
//!
//! Normative: `spec/SPEC.md` §20.3. Rationale: design §7. This is ticket 10.
//!
//! The two signatures are stored in separate footer slots ([`crate::footer`]), so
//! no in-slot encoding is needed: the classical slot holds an Ed25519 signature and
//! the post-quantum slot an ML-DSA-65 signature. Both MUST verify, and an unsigned
//! bundle MUST NOT be reported as authentic on any grounds — verification is the
//! only thing that produces [`Authentication`].
//!
//! Ed25519 comes from audited AWS-LC. ML-DSA-65 is the RustCrypto FIPS 204
//! implementation, kept behind [`crate::suite::Signature`] because it is the least
//! settled primitive in the stack (design §7).

use aws_lc_rs::signature::{ED25519, Ed25519KeyPair, KeyPair as _, UnparsedPublicKey};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, Generate, Keypair as _, MlDsa65,
    Signature as MlDsaSignature, SignatureEncoding, Signer as _, SigningKey, Verifier as _,
    VerifyingKey,
};

use crate::crypto::random_bytes;
use crate::suite::{
    HybridPublicKey, HybridSignature, HybridSigningKey, Role, Signature, SuiteError,
};

const ED25519_PUBLIC_KEY_LEN: usize = 32;
const ED25519_SIGNATURE_LEN: usize = 64;
const ML_DSA_65_PUBLIC_KEY_LEN: usize = 1952;
const ML_DSA_65_SIGNATURE_LEN: usize = 3309;

/// Ed25519 + ML-DSA-65 (design §7, spec §19 suites 1 and 2).
#[derive(Debug, Clone, Copy, Default)]
pub struct Ed25519MlDsa65;

impl Ed25519MlDsa65 {
    /// Construct the role.
    pub const fn new() -> Self {
        Self
    }
}

fn key_error() -> SuiteError {
    SuiteError::InvalidKey {
        role: Role::Signature,
    }
}

/// A successful verification of **both** signature components.
///
/// This type is deliberately unconstructable outside this module: the only way to
/// hold one is to have verified a hybrid signature, which is what makes "a reader
/// never reports authenticity on a file it has not signed-checked" a property of the
/// type rather than a comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Authentication(());

impl Authentication {
    /// The one constructor, private to this module. Reachable only through a
    /// successful two-component verification.
    fn verified() -> Self {
        Self(())
    }

    /// Whether a verification has happened. Always `true`; the method exists so a
    /// holder can ask the question without knowing the construction rule.
    pub const fn is_authentic(self) -> bool {
        true
    }
}

/// Verify a bundle footer's hybrid signature over the §8.4 transcript.
///
/// Key distribution is deliberately out of scope (spec §8.2): bundles are authored
/// by a single trusted org whose keys the platform holds out of band, so the trusted
/// public key is a parameter, never inferred from `suite_id`.
///
/// An unsigned footer yields an error: there is nothing to verify, and an unsigned
/// bundle MUST NOT be reported as authentic (spec §13). A failure of either
/// component is a failure of the whole; there is no half-authentic result.
pub fn verify_footer(
    suite_id: u16,
    footer: &crate::footer::Footer,
    public_key: &HybridPublicKey,
) -> Result<Authentication, SuiteError> {
    if footer.sig_classical.is_empty() || footer.sig_pq.is_empty() {
        return Err(SuiteError::Primitive {
            role: Role::Signature,
            reason: "footer is unsigned; there is nothing to authenticate",
        });
    }
    let suite = crate::suite::suite(suite_id)?;
    let role = suite.signature()?;
    let transcript = footer.sig_input(suite_id);
    let signature = HybridSignature {
        classical: footer.sig_classical.clone(),
        pq: footer.sig_pq.clone(),
    };
    role.verify(&transcript, public_key, &signature)?;
    Ok(Authentication::verified())
}

/// Produce both hybrid signatures over the §8.4 transcript.
///
/// The slot lengths are inputs rather than derived from a footer because the
/// transcript binds them (spec §8.4, the `v2` change): a signer must fix the
/// lengths before it can sign the bytes that locate the slots. The caller takes them
/// from the suite ([`Signature::classical_signature_len`] and
/// [`Signature::pq_signature_len`]), never from a file.
pub fn sign_footer(
    suite_id: u16,
    root: &[u8; crate::footer::ROOT_LEN],
    total_len: u64,
    sig_classical_len: u32,
    sig_pq_len: u32,
    signing_key: &HybridSigningKey,
) -> Result<HybridSignature, SuiteError> {
    let suite = crate::suite::suite(suite_id)?;
    let role = suite.signature()?;
    let transcript =
        crate::footer::sig_input(suite_id, sig_classical_len, sig_pq_len, root, total_len);
    role.sign(&transcript, signing_key)
}

impl Signature for Ed25519MlDsa65 {
    fn classical_public_key_len(&self) -> usize {
        ED25519_PUBLIC_KEY_LEN
    }

    fn classical_signature_len(&self) -> usize {
        ED25519_SIGNATURE_LEN
    }

    fn pq_public_key_len(&self) -> usize {
        ML_DSA_65_PUBLIC_KEY_LEN
    }

    fn pq_signature_len(&self) -> usize {
        ML_DSA_65_SIGNATURE_LEN
    }

    fn keypair(&self) -> Result<(HybridSigningKey, HybridPublicKey), SuiteError> {
        let mut seed = [0u8; ED25519_PUBLIC_KEY_LEN];
        random_bytes(&mut seed, Role::Signature)?;
        let classical = Ed25519KeyPair::from_seed_unchecked(&seed).map_err(|_| key_error())?;
        let classical_public = classical.public_key().as_ref().to_vec();

        let pq = SigningKey::<MlDsa65>::generate();
        let pq_public = pq.verifying_key().encode().to_vec();

        Ok((
            HybridSigningKey {
                classical: seed.to_vec(),
                pq: pq.to_seed().to_vec(),
            },
            HybridPublicKey {
                classical: classical_public,
                pq: pq_public,
            },
        ))
    }

    fn sign(
        &self,
        transcript: &[u8],
        signing_key: &HybridSigningKey,
    ) -> Result<HybridSignature, SuiteError> {
        let classical =
            Ed25519KeyPair::from_seed_unchecked(&signing_key.classical).map_err(|_| key_error())?;
        let classical = classical.sign(transcript).as_ref().to_vec();

        let seed = ml_dsa::Seed::try_from(signing_key.pq.as_slice()).map_err(|_| key_error())?;
        let pq = SigningKey::<MlDsa65>::from_seed(&seed);
        let pq = pq.sign(transcript).to_bytes().to_vec();

        Ok(HybridSignature { classical, pq })
    }

    fn verify(
        &self,
        transcript: &[u8],
        public_key: &HybridPublicKey,
        signature: &HybridSignature,
    ) -> Result<(), SuiteError> {
        // Both components must be present and the right width. A half-signed footer
        // is already refused by F4; this is the same rule at the primitive, so a
        // caller holding raw components cannot skip it.
        if signature.classical.len() != self.classical_signature_len() {
            return Err(SuiteError::InvalidLength {
                role: Role::Signature,
                expected: self.classical_signature_len(),
                got: signature.classical.len(),
            });
        }
        if signature.pq.len() != self.pq_signature_len() {
            return Err(SuiteError::InvalidLength {
                role: Role::Signature,
                expected: self.pq_signature_len(),
                got: signature.pq.len(),
            });
        }
        if public_key.classical.len() != self.classical_public_key_len()
            || public_key.pq.len() != self.pq_public_key_len()
        {
            return Err(key_error());
        }

        let classical = UnparsedPublicKey::new(&ED25519, public_key.classical.as_slice());
        classical
            .verify(transcript, &signature.classical)
            .map_err(|_| SuiteError::VerificationFailed {
                component: "classical",
            })?;

        let encoded_key: EncodedVerifyingKey<MlDsa65> =
            <EncodedVerifyingKey<MlDsa65>>::try_from(public_key.pq.as_slice())
                .map_err(|_| key_error())?;
        let pq_key = VerifyingKey::<MlDsa65>::decode(&encoded_key);
        let encoded_sig: EncodedSignature<MlDsa65> =
            <EncodedSignature<MlDsa65>>::try_from(signature.pq.as_slice())
                .map_err(|_| SuiteError::VerificationFailed { component: "pq" })?;
        let pq_sig = MlDsaSignature::<MlDsa65>::decode(&encoded_sig)
            .ok_or(SuiteError::VerificationFailed { component: "pq" })?;
        pq_key
            .verify(transcript, &pq_sig)
            .map_err(|_| SuiteError::VerificationFailed { component: "pq" })?;

        Ok(())
    }
}

impl Ed25519MlDsa65 {
    /// Verify **both** components and, only then, produce an [`Authentication`].
    ///
    /// This is the typed form of ticket 10's acceptance criterion: a caller cannot
    /// obtain an [`Authentication`] except from a successful two-component check, so
    /// "reports a bundle as authentic without checking" is unrepresentable.
    pub fn authenticate(
        &self,
        transcript: &[u8],
        public_key: &HybridPublicKey,
        signature: &HybridSignature,
    ) -> Result<Authentication, SuiteError> {
        self.verify(transcript, public_key, signature)?;
        Ok(Authentication::verified())
    }
}
