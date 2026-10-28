//! The hybrid signature: Ed25519 + ML-DSA-65, plus SLH-DSA for suite 3, all over
//! the identical transcript.
//!
//! Normative: `spec/SPEC.md` §20.3. Rationale: design §7. This is ticket 10, with
//! suite 3's third component added by §20.3.
//!
//! The classical signature occupies the footer's `sig_classical` slot. The
//! post-quantum material occupies `sig_pq`: ML-DSA-65 alone for suites 1 and 2, and
//! `ML-DSA-65 ‖ SLH-DSA-SHA2-128s` for suite 3 (§20.3). Every component MUST verify,
//! and an unsigned bundle MUST NOT be reported as authentic on any grounds —
//! verification is the only thing that produces [`Authentication`].
//!
//! Ed25519 comes from audited AWS-LC. ML-DSA-65 and SLH-DSA are the RustCrypto
//! FIPS 204/205 implementations, kept behind [`crate::suite::Signature`] because they
//! are the least settled primitives in the stack (design §7).

use aws_lc_rs::signature::{ED25519, Ed25519KeyPair, KeyPair as _, UnparsedPublicKey};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, Generate, Keypair as _, MlDsa65,
    Signature as MlDsaSignature, SignatureEncoding, Signer as _, SigningKey, Verifier as _,
    VerifyingKey,
};
use slh_dsa::{
    Sha2_128s, Signature as SlhDsaSignature, SigningKey as SlhDsaSigningKey,
    VerifyingKey as SlhDsaVerifyingKey,
};

use crate::crypto::random_bytes;
use crate::suite::{
    HybridPublicKey, HybridSignature, HybridSigningKey, Role, Signature, SuiteError,
};

const ED25519_PUBLIC_KEY_LEN: usize = 32;
const ED25519_SIGNATURE_LEN: usize = 64;
const ML_DSA_65_PUBLIC_KEY_LEN: usize = 1952;
const ML_DSA_65_SIGNATURE_LEN: usize = 3309;
/// ML-DSA-65's 32-byte key-generation seed. Secret-key layout is this
/// implementation's, not the format's.
const ML_DSA_65_SIGNING_KEY_LEN: usize = 32;
/// A serialized SLH-DSA-SHA2-128s verifying key is `2 × n` for `n = 16` (§20.3).
const SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN: usize = 32;
/// FIPS 205's SLH-DSA-SHA2-128s signature length (§20.3).
const SLH_DSA_SHA2_128S_SIGNATURE_LEN: usize = 7856;
/// A serialized SLH-DSA signing key: `sk_seed ‖ sk_prf ‖ pk_seed ‖ pk_root`, each
/// `n = 16` bytes. Secret-key layout is not part of the container format; it only
/// has to round-trip through [`HybridSigningKey::pq`].
const SLH_DSA_SHA2_128S_SIGNING_KEY_LEN: usize = 64;
/// The seed material SLH-DSA key generation consumes: `sk_seed ‖ sk_prf ‖ pk_seed`.
const SLH_DSA_SHA2_128S_SEED_LEN: usize = 48;

/// Ed25519 + ML-DSA-65 (design §7, spec §19 suites 1 and 2).
#[derive(Debug, Clone, Copy, Default)]
pub struct Ed25519MlDsa65;

impl Ed25519MlDsa65 {
    /// Construct the role.
    pub const fn new() -> Self {
        Self
    }
}

/// Ed25519 + ML-DSA-65 + SLH-DSA-SHA2-128s (spec §19 suite 3, §20.3).
#[derive(Debug, Clone, Copy, Default)]
pub struct Ed25519MlDsa65SlhDsa;

impl Ed25519MlDsa65SlhDsa {
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

fn length_error(expected: usize, got: usize) -> SuiteError {
    SuiteError::InvalidLength {
        role: Role::Signature,
        expected,
        got,
    }
}

/// A successful verification of every signature component.
///
/// This type is deliberately unconstructable outside this module: the only way to
/// hold one is to have verified a hybrid signature, which is what makes "a reader
/// never reports authenticity on a file it has not signed-checked" a property of the
/// type rather than a comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Authentication(());

impl Authentication {
    /// The one constructor, private to this module. Reachable only through a
    /// successful verification of every component.
    fn verified() -> Self {
        Self(())
    }

    /// Whether a verification has happened. Always `true`; the method exists so a
    /// holder can ask the question without knowing the construction rule.
    pub const fn is_authentic(self) -> bool {
        true
    }
}

// The three component primitives, factored so suites 1/2 and suite 3 share one
// code path for each algorithm rather than two that could drift.

fn classical_keypair() -> Result<(Vec<u8>, Vec<u8>), SuiteError> {
    let mut seed = [0u8; ED25519_PUBLIC_KEY_LEN];
    random_bytes(&mut seed, Role::Signature)?;
    let classical = Ed25519KeyPair::from_seed_unchecked(&seed).map_err(|_| key_error())?;
    Ok((seed.to_vec(), classical.public_key().as_ref().to_vec()))
}

fn classical_sign(seed: &[u8], transcript: &[u8]) -> Result<Vec<u8>, SuiteError> {
    let key = Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| key_error())?;
    Ok(key.sign(transcript).as_ref().to_vec())
}

fn classical_verify(
    public_key: &[u8],
    transcript: &[u8],
    signature: &[u8],
) -> Result<(), SuiteError> {
    let key = UnparsedPublicKey::new(&ED25519, public_key);
    key.verify(transcript, signature)
        .map_err(|_| SuiteError::VerificationFailed {
            component: "classical",
        })
}

fn ml_dsa_keypair() -> Result<(Vec<u8>, Vec<u8>), SuiteError> {
    let key = SigningKey::<MlDsa65>::generate();
    Ok((
        key.to_seed().to_vec(),
        key.verifying_key().encode().to_vec(),
    ))
}

fn ml_dsa_sign(seed: &[u8], transcript: &[u8]) -> Result<Vec<u8>, SuiteError> {
    let seed = ml_dsa::Seed::try_from(seed).map_err(|_| key_error())?;
    let key = SigningKey::<MlDsa65>::from_seed(&seed);
    Ok(key.sign(transcript).to_bytes().to_vec())
}

fn ml_dsa_verify(public_key: &[u8], transcript: &[u8], signature: &[u8]) -> Result<(), SuiteError> {
    let encoded_key: EncodedVerifyingKey<MlDsa65> =
        <EncodedVerifyingKey<MlDsa65>>::try_from(public_key).map_err(|_| key_error())?;
    let key = VerifyingKey::<MlDsa65>::decode(&encoded_key);
    let encoded_sig: EncodedSignature<MlDsa65> =
        <EncodedSignature<MlDsa65>>::try_from(signature)
            .map_err(|_| SuiteError::VerificationFailed { component: "pq" })?;
    let sig = MlDsaSignature::<MlDsa65>::decode(&encoded_sig)
        .ok_or(SuiteError::VerificationFailed { component: "pq" })?;
    key.verify(transcript, &sig)
        .map_err(|_| SuiteError::VerificationFailed { component: "pq" })
}

fn slh_dsa_keypair() -> Result<(Vec<u8>, Vec<u8>), SuiteError> {
    // `slh_keygen_internal` is FIPS 205's key generation from explicitly drawn
    // seeds; `SigningKey::new` would draw the same three seeds from an RNG trait we
    // do not otherwise depend on.
    let mut seeds = [0u8; SLH_DSA_SHA2_128S_SEED_LEN];
    random_bytes(&mut seeds, Role::Signature)?;
    let third = SLH_DSA_SHA2_128S_SEED_LEN / 3;
    let (sk_seed, rest) = seeds.split_at(third);
    let (sk_prf, pk_seed) = rest.split_at(third);
    let key = SlhDsaSigningKey::<Sha2_128s>::slh_keygen_internal(sk_seed, sk_prf, pk_seed);
    Ok((
        key.to_bytes().to_vec(),
        key.verifying_key().to_bytes().to_vec(),
    ))
}

fn slh_dsa_sign(signing_key: &[u8], transcript: &[u8]) -> Result<Vec<u8>, SuiteError> {
    let key = SlhDsaSigningKey::<Sha2_128s>::try_from(signing_key).map_err(|_| key_error())?;
    // Deterministic signing (no `sign_with_rng`): the same key and transcript yield
    // the same bytes, so a signer is reproducible.
    Ok(key.sign(transcript).to_bytes().to_vec())
}

fn slh_dsa_verify(
    public_key: &[u8],
    transcript: &[u8],
    signature: &[u8],
) -> Result<(), SuiteError> {
    let key = SlhDsaVerifyingKey::<Sha2_128s>::try_from(public_key).map_err(|_| {
        SuiteError::VerificationFailed {
            component: "slh-dsa",
        }
    })?;
    let sig = SlhDsaSignature::<Sha2_128s>::try_from(signature).map_err(|_| {
        SuiteError::VerificationFailed {
            component: "slh-dsa",
        }
    })?;
    key.verify(transcript, &sig)
        .map_err(|_| SuiteError::VerificationFailed {
            component: "slh-dsa",
        })
}

/// Verify a bundle footer's hybrid signature over the §8.4 transcript.
///
/// Key distribution is deliberately out of scope (spec §8.2): bundles are authored
/// by a single trusted org whose keys the platform holds out of band, so the trusted
/// public key is a parameter, never inferred from `suite_id`.
///
/// An unsigned footer yields an error: there is nothing to verify, and an unsigned
/// bundle MUST NOT be reported as authentic (spec §13). A failure of any component is
/// a failure of the whole; there is no half-authentic result.
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

/// Produce every hybrid signature over the §8.4 transcript.
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
        let (classical_secret, classical_public) = classical_keypair()?;
        let (pq_secret, pq_public) = ml_dsa_keypair()?;
        Ok((
            HybridSigningKey {
                classical: classical_secret,
                pq: pq_secret,
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
        Ok(HybridSignature {
            classical: classical_sign(&signing_key.classical, transcript)?,
            pq: ml_dsa_sign(&signing_key.pq, transcript)?,
        })
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
            return Err(length_error(
                self.classical_signature_len(),
                signature.classical.len(),
            ));
        }
        if signature.pq.len() != self.pq_signature_len() {
            return Err(length_error(self.pq_signature_len(), signature.pq.len()));
        }
        if public_key.classical.len() != self.classical_public_key_len()
            || public_key.pq.len() != self.pq_public_key_len()
        {
            return Err(key_error());
        }

        classical_verify(&public_key.classical, transcript, &signature.classical)?;
        ml_dsa_verify(&public_key.pq, transcript, &signature.pq)
    }
}

impl Signature for Ed25519MlDsa65SlhDsa {
    fn classical_public_key_len(&self) -> usize {
        ED25519_PUBLIC_KEY_LEN
    }

    fn classical_signature_len(&self) -> usize {
        ED25519_SIGNATURE_LEN
    }

    /// `ML-DSA-65 public key ‖ SLH-DSA-SHA2-128s public key` (§20.3).
    fn pq_public_key_len(&self) -> usize {
        ML_DSA_65_PUBLIC_KEY_LEN + SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN
    }

    /// `ML-DSA-65 signature ‖ SLH-DSA-SHA2-128s signature` (§20.3).
    fn pq_signature_len(&self) -> usize {
        ML_DSA_65_SIGNATURE_LEN + SLH_DSA_SHA2_128S_SIGNATURE_LEN
    }

    fn keypair(&self) -> Result<(HybridSigningKey, HybridPublicKey), SuiteError> {
        let (classical_secret, classical_public) = classical_keypair()?;
        let (ml_dsa_secret, ml_dsa_public) = ml_dsa_keypair()?;
        let (slh_dsa_secret, slh_dsa_public) = slh_dsa_keypair()?;

        let mut pq_secret = Vec::with_capacity(ml_dsa_secret.len() + slh_dsa_secret.len());
        pq_secret.extend_from_slice(&ml_dsa_secret);
        pq_secret.extend_from_slice(&slh_dsa_secret);

        let mut pq_public = Vec::with_capacity(ml_dsa_public.len() + slh_dsa_public.len());
        pq_public.extend_from_slice(&ml_dsa_public);
        pq_public.extend_from_slice(&slh_dsa_public);

        Ok((
            HybridSigningKey {
                classical: classical_secret,
                pq: pq_secret,
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
        if signing_key.pq.len() != ML_DSA_65_SIGNING_KEY_LEN + SLH_DSA_SHA2_128S_SIGNING_KEY_LEN {
            return Err(key_error());
        }
        let (ml_dsa_secret, slh_dsa_secret) = signing_key.pq.split_at(ML_DSA_65_SIGNING_KEY_LEN);

        let mut pq = Vec::with_capacity(self.pq_signature_len());
        pq.extend_from_slice(&ml_dsa_sign(ml_dsa_secret, transcript)?);
        pq.extend_from_slice(&slh_dsa_sign(slh_dsa_secret, transcript)?);
        Ok(HybridSignature {
            classical: classical_sign(&signing_key.classical, transcript)?,
            pq,
        })
    }

    fn verify(
        &self,
        transcript: &[u8],
        public_key: &HybridPublicKey,
        signature: &HybridSignature,
    ) -> Result<(), SuiteError> {
        if signature.classical.len() != self.classical_signature_len() {
            return Err(length_error(
                self.classical_signature_len(),
                signature.classical.len(),
            ));
        }
        if signature.pq.len() != self.pq_signature_len() {
            return Err(length_error(self.pq_signature_len(), signature.pq.len()));
        }
        if public_key.classical.len() != self.classical_public_key_len()
            || public_key.pq.len() != self.pq_public_key_len()
        {
            return Err(key_error());
        }

        let (ml_dsa_signature, slh_dsa_signature) = signature.pq.split_at(ML_DSA_65_SIGNATURE_LEN);
        let (ml_dsa_public, slh_dsa_public) = public_key.pq.split_at(ML_DSA_65_PUBLIC_KEY_LEN);

        classical_verify(&public_key.classical, transcript, &signature.classical)?;
        ml_dsa_verify(ml_dsa_public, transcript, ml_dsa_signature)?;
        slh_dsa_verify(slh_dsa_public, transcript, slh_dsa_signature)
    }
}

impl Ed25519MlDsa65 {
    /// Verify **both** components and, only then, produce an [`Authentication`].
    ///
    /// This is the typed form of ticket 10's acceptance criterion: a caller cannot
    /// obtain an [`Authentication`] except from a successful component check, so
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

impl Ed25519MlDsa65SlhDsa {
    /// Verify **all three** components and, only then, produce an [`Authentication`].
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
