//! The hybrid KEM: X25519 + ML-KEM-768, with a transcript-binding combiner.
//!
//! Normative: `spec/SPEC.md` §20.1. Rationale: design §7. This is ticket 11.
//!
//! The combiner MUST be a KDF over **both** shared secrets **and the full
//! transcript** — never XOR, never a bare concatenation of the secrets. Binding the
//! transcript is what stops an attacker who controls one component's ciphertext
//! from steering the derived key.
//!
//! ```text
//! ss = HKDF-SHA-256(
//!        ikm  = ss_x25519 ‖ ss_mlkem,
//!        salt = "ctf/kem/v1" ‖ u16_le(suite_id) ‖ u16_le(version_major),
//!        info = LP(ct_x25519) ‖ LP(ct_mlkem) ‖ LP(pk_x25519) ‖ LP(pk_mlkem)
//!               ‖ LP(context_label) )
//! ```
//!
//! The salt binds `version_major` only, never the minor: binding the full version
//! would silently re-key every bundle on a spec bump that moved no field, so a 0.2
//! tool could not open a 0.1 bundle it had written correctly.

use aws_lc_rs::agreement;
use ml_kem::kem::{Decapsulate, Encapsulate, Kem as MlKem};
use ml_kem::{
    Ciphertext, DecapsulationKey768, EncapsulationKey768, Key, KeyExport, MlKem768,
    Seed as MlKemSeed,
};

use crate::crypto::kdf::HkdfSha256;
use crate::crypto::{fixed, lp, random_bytes};
use crate::footer::ROOT_LEN;
use crate::suite::{Kdf, Kem, KemContext, KemKeyPair, Role, SuiteError};

/// Domain-separates the combiner from every other HKDF use in the format.
const KEM_LABEL: &[u8] = b"ctf/kem/v1";

/// X25519 component sizes. The secret key is the raw 32-byte scalar; the "public
/// key" and the encapsulated form of the classical half are both 32 bytes.
const X25519_LEN: usize = 32;

/// ML-KEM-768 FIPS 203 sizes. The encapsulation key is 1184 bytes and the
/// ciphertext 1088; the decapsulation key is serialized as its 64-byte seed
/// (`d ‖ z`), the compact form the crate prefers.
const MLKEM768_EK_LEN: usize = 1184;
const MLKEM768_DK_LEN: usize = 64;
const MLKEM768_CT_LEN: usize = 1088;

/// X25519 + ML-KEM-768, hybrid (design §7, suite 1 and 2).
#[derive(Debug, Clone, Copy, Default)]
pub struct X25519MlKem768;

impl X25519MlKem768 {
    /// Construct the role.
    pub const fn new() -> Self {
        Self
    }
}

fn x25519_public(secret: &[u8]) -> Result<Vec<u8>, SuiteError> {
    let sk = agreement::PrivateKey::from_private_key(&agreement::X25519, secret)
        .map_err(|_| SuiteError::InvalidKey { role: Role::Kem })?;
    let pk = sk.compute_public_key().map_err(|_| SuiteError::Primitive {
        role: Role::Kem,
        reason: "x25519 public-key computation failed",
    })?;
    Ok(pk.as_ref().to_vec())
}

fn x25519_agree(secret: &[u8], peer: &[u8]) -> Result<[u8; ROOT_LEN], SuiteError> {
    let sk = agreement::PrivateKey::from_private_key(&agreement::X25519, secret)
        .map_err(|_| SuiteError::InvalidKey { role: Role::Kem })?;
    let peer = agreement::UnparsedPublicKey::new(&agreement::X25519, peer);
    agreement::agree(
        &sk,
        peer,
        SuiteError::InvalidKey { role: Role::Kem },
        |ss| fixed::<ROOT_LEN>(ss, Role::Kem),
    )
}

fn mlkem_ek(bytes: &[u8]) -> Result<EncapsulationKey768, SuiteError> {
    let key: Key<EncapsulationKey768> =
        <Key<EncapsulationKey768>>::try_from(bytes).map_err(|_| SuiteError::InvalidLength {
            role: Role::Kem,
            expected: MLKEM768_EK_LEN,
            got: bytes.len(),
        })?;
    EncapsulationKey768::new(&key).map_err(|_| SuiteError::InvalidKey { role: Role::Kem })
}

fn mlkem_dk(bytes: &[u8]) -> Result<DecapsulationKey768, SuiteError> {
    let seed: MlKemSeed = MlKemSeed::try_from(bytes).map_err(|_| SuiteError::InvalidLength {
        role: Role::Kem,
        expected: MLKEM768_DK_LEN,
        got: bytes.len(),
    })?;
    Ok(DecapsulationKey768::from_seed(seed))
}

/// The transcript-binding HKDF combiner of design §7.
#[allow(clippy::too_many_arguments)]
fn combine(
    ss_x25519: &[u8],
    ss_mlkem: &[u8],
    ct_x25519: &[u8],
    ct_mlkem: &[u8],
    pk_x25519: &[u8],
    pk_mlkem: &[u8],
    context: &KemContext<'_>,
) -> Result<[u8; ROOT_LEN], SuiteError> {
    let mut ikm = Vec::with_capacity(ss_x25519.len() + ss_mlkem.len());
    ikm.extend_from_slice(ss_x25519);
    ikm.extend_from_slice(ss_mlkem);

    // Salt binds the label, the suite, and the major version — never the minor.
    let mut salt = Vec::with_capacity(KEM_LABEL.len() + 4);
    salt.extend_from_slice(KEM_LABEL);
    salt.extend_from_slice(&context.suite_id.to_le_bytes());
    salt.extend_from_slice(&context.version_major.to_le_bytes());

    // Every variable-length transcript field is length-prefixed, so no two
    // distinct (ct, pk, label) tuples can produce identical `info` bytes.
    let mut info = Vec::new();
    lp(&mut info, ct_x25519);
    lp(&mut info, ct_mlkem);
    lp(&mut info, pk_x25519);
    lp(&mut info, pk_mlkem);
    lp(&mut info, context.label);

    let mut out = [0u8; ROOT_LEN];
    HkdfSha256::new().derive(&ikm, &salt, &info, &mut out)?;
    Ok(out)
}

impl Kem for X25519MlKem768 {
    fn public_key_len(&self) -> usize {
        X25519_LEN + MLKEM768_EK_LEN
    }

    fn secret_key_len(&self) -> usize {
        X25519_LEN + MLKEM768_DK_LEN
    }

    fn ciphertext_len(&self) -> usize {
        X25519_LEN + MLKEM768_CT_LEN
    }

    fn shared_secret_len(&self) -> usize {
        ROOT_LEN
    }

    fn generate(&self) -> Result<KemKeyPair, SuiteError> {
        let mut x_sk = [0u8; X25519_LEN];
        random_bytes(&mut x_sk, Role::Kem)?;
        let x_pk = x25519_public(&x_sk)?;

        let (dk, ek) = MlKem768::generate_keypair();
        let ek = ek.to_bytes();
        let dk = dk.to_bytes();

        let mut public_key = Vec::with_capacity(X25519_LEN + MLKEM768_EK_LEN);
        public_key.extend_from_slice(&x_pk);
        public_key.extend_from_slice(ek.as_ref());

        let mut secret_key = Vec::with_capacity(X25519_LEN + MLKEM768_DK_LEN);
        secret_key.extend_from_slice(&x_sk);
        secret_key.extend_from_slice(dk.as_ref());

        Ok(KemKeyPair {
            public_key,
            secret_key,
        })
    }

    fn encapsulate(
        &self,
        public_key: &[u8],
        context: &KemContext<'_>,
    ) -> Result<(Vec<u8>, [u8; ROOT_LEN]), SuiteError> {
        if public_key.len() != self.public_key_len() {
            return Err(SuiteError::InvalidLength {
                role: Role::Kem,
                expected: self.public_key_len(),
                got: public_key.len(),
            });
        }
        let pk_x25519 = public_key.get(..X25519_LEN).unwrap_or(&[]);
        let pk_mlkem = public_key.get(X25519_LEN..).unwrap_or(&[]);

        let ek = mlkem_ek(pk_mlkem)?;
        let (ct_mlkem, ss_mlkem) = ek.encapsulate();

        let mut eph = [0u8; X25519_LEN];
        random_bytes(&mut eph, Role::Kem)?;
        let ct_x25519 = x25519_public(&eph)?;
        let ss_x25519 = x25519_agree(&eph, pk_x25519)?;

        let mut ct = Vec::with_capacity(X25519_LEN + MLKEM768_CT_LEN);
        ct.extend_from_slice(&ct_x25519);
        ct.extend_from_slice(ct_mlkem.as_ref());

        let key = combine(
            &ss_x25519,
            ss_mlkem.as_ref(),
            &ct_x25519,
            ct_mlkem.as_ref(),
            pk_x25519,
            pk_mlkem,
            context,
        )?;
        Ok((ct, key))
    }

    fn decapsulate(
        &self,
        secret_key: &[u8],
        ciphertext: &[u8],
        context: &KemContext<'_>,
    ) -> Result<[u8; ROOT_LEN], SuiteError> {
        if secret_key.len() != self.secret_key_len() {
            return Err(SuiteError::InvalidLength {
                role: Role::Kem,
                expected: self.secret_key_len(),
                got: secret_key.len(),
            });
        }
        if ciphertext.len() != self.ciphertext_len() {
            return Err(SuiteError::InvalidLength {
                role: Role::Kem,
                expected: self.ciphertext_len(),
                got: ciphertext.len(),
            });
        }
        let sk_x25519 = secret_key.get(..X25519_LEN).unwrap_or(&[]);
        let dk_mlkem = secret_key.get(X25519_LEN..).unwrap_or(&[]);
        let ct_x25519 = ciphertext.get(..X25519_LEN).unwrap_or(&[]);
        let ct_mlkem_bytes = ciphertext.get(X25519_LEN..).unwrap_or(&[]);

        let ct_mlkem: Ciphertext<MlKem768> = <Ciphertext<MlKem768>>::try_from(ct_mlkem_bytes)
            .map_err(|_| SuiteError::InvalidLength {
                role: Role::Kem,
                expected: MLKEM768_CT_LEN,
                got: ct_mlkem_bytes.len(),
            })?;
        let dk = mlkem_dk(dk_mlkem)?;
        let ss_mlkem = dk.decapsulate(&ct_mlkem);

        let ss_x25519 = x25519_agree(sk_x25519, ct_x25519)?;
        let pk_x25519 = x25519_public(sk_x25519)?;
        let pk_mlkem = dk.encapsulation_key().to_bytes();

        combine(
            &ss_x25519,
            ss_mlkem.as_ref(),
            ct_x25519,
            ct_mlkem.as_ref(),
            &pk_x25519,
            pk_mlkem.as_ref(),
            context,
        )
    }
}
