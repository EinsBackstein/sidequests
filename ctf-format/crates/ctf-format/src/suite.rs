//! The crypto suite registry: `suite_id` → one implementation per primitive role.
//!
//! Normative: `spec/SPEC.md` §19. The design rationale is design §7.
//!
//! # Why the registry exists at all
//!
//! `suite_id` is a header field, and the header is frozen. A primitive that turns
//! out to be broken, or a new one that arrives after the format is in use, cannot
//! move a field or change a structure — it can only be *selected by number*. This
//! module is the one place that maps a number to a set of primitives, so retiring a
//! suite (design §7's ML-DSA warning is the concrete case) touches no byte layout
//! and no record rule.
//!
//! # Failure timing is the acceptance criterion
//!
//! [`Header::parse`](crate::Header::parse) MUST NOT consult this registry: spec
//! §4.3 says a reader MUST NOT reject a file during header parsing merely because
//! `suite_id` is unrecognized. The value is recorded verbatim and looked up at the
//! point a primitive is actually needed, so an unrecognized suite produces "this
//! suite is unknown" where the diagnostic is useful, not a structural error about a
//! header that is in fact perfectly well-formed.
//!
//! # Status
//!
//! All five roles are implemented for suites 1 and 2: BLAKE3 `hash`, HKDF-SHA-256
//! `kdf`, X25519+ML-KEM-768 `kem`, AES-256-GCM / XChaCha20-Poly1305 `aead`, and
//! Ed25519+ML-DSA-65 `signature`. The constructions are normative in spec §20.
//!
//! Suite 3's `signature` adds SLH-DSA, which this build does not implement, so
//! resolving it returns [`SuiteError::NotImplemented`] naming the suite and role
//! rather than silently reducing the hybrid to two of its three components.

use crate::footer::ROOT_LEN;

/// A primitive role a suite provides. One trait per role (spec §19).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Content hashing and the commitment.
    Hash,
    /// Key derivation.
    Kdf,
    /// Key encapsulation.
    Kem,
    /// Authenticated encryption.
    Aead,
    /// Digital signatures.
    Signature,
}

impl Role {
    /// The name this role is reported under.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Hash => "hash",
            Self::Kdf => "kdf",
            Self::Kem => "kem",
            Self::Aead => "aead",
            Self::Signature => "signature",
        }
    }
}

/// Why a suite or one of its primitives could not be resolved, or why a
/// primitive operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuiteError {
    /// No suite in the registry has this id.
    UnknownSuite { id: u16 },
    /// The suite exists, but this build has not implemented the requested role
    /// yet. Reported where the primitive is used, never at header parse.
    NotImplemented { suite: u16, role: Role },
    /// A key, nonce, ciphertext, or signature was not the length its suite
    /// requires. Lengths are suite properties (spec §8.1), never read from the
    /// input, so a mismatch is rejected rather than accepted and padded.
    InvalidLength {
        role: Role,
        expected: usize,
        got: usize,
    },
    /// A public or secret key could not be parsed. The bytes are never echoed: an
    /// error string must not become an oracle for key material.
    InvalidKey { role: Role },
    /// A primitive failed for a reason its suite names. The reason is a static
    /// description, never input bytes.
    Primitive { role: Role, reason: &'static str },
    /// One component of a hybrid signature failed to verify. Both must verify
    /// (design §7, spec §8.4); a bundle carrying one valid half is a downgrade.
    VerificationFailed { component: &'static str },
}

impl core::fmt::Display for SuiteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownSuite { id } => write!(f, "unknown crypto suite {id}"),
            Self::NotImplemented { suite, role } => {
                write!(
                    f,
                    "suite {suite} {} role is not implemented yet",
                    role.name()
                )
            }
            Self::InvalidLength {
                role,
                expected,
                got,
            } => write!(
                f,
                "{} input is {got} bytes, suite requires {expected}",
                role.name()
            ),
            Self::InvalidKey { role } => write!(f, "invalid {} key", role.name()),
            Self::Primitive { role, reason } => {
                write!(f, "{} primitive failed: {reason}", role.name())
            }
            Self::VerificationFailed { component } => {
                write!(f, "hybrid signature {component} component did not verify")
            }
        }
    }
}

impl core::error::Error for SuiteError {}

/// The context a KEM operation is bound to (design §7).
///
/// The hybrid combiner's salt is `"ctf/kem/v1" ‖ u16_le(suite_id) ‖
/// u16_le(version_major)` and its `info` transcript ends with the length-prefixed
/// `label`. `version_major` only is bound, never `version_minor`: binding the minor
/// would silently re-key every bundle on a spec bump that moved no field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KemContext<'a> {
    /// The header's `suite_id`.
    pub suite_id: u16,
    /// The header's `version_major`. Never the minor.
    pub version_major: u16,
    /// One of `storage`, `seal`, `stage:N`, or `holder` (design §7).
    pub label: &'a [u8],
}

/// A hybrid KEM keypair. The public key and secret key are both the concatenation
/// of a classical and a post-quantum component, in that order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KemKeyPair {
    /// X25519 public key ‖ ML-KEM-768 encapsulation key.
    pub public_key: Vec<u8>,
    /// X25519 secret key ‖ ML-KEM-768 decapsulation key.
    pub secret_key: Vec<u8>,
}

/// A hybrid public key, split into its two components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridPublicKey {
    /// The classical (Ed25519) component.
    pub classical: Vec<u8>,
    /// The post-quantum (ML-DSA-65) component.
    pub pq: Vec<u8>,
}

/// A hybrid signing key, split into its two components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridSigningKey {
    /// The classical (Ed25519) component.
    pub classical: Vec<u8>,
    /// The post-quantum (ML-DSA-65) component.
    pub pq: Vec<u8>,
}

/// A hybrid signature. Both components cover the identical transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridSignature {
    /// The classical (Ed25519) component.
    pub classical: Vec<u8>,
    /// The post-quantum (ML-DSA-65) component.
    pub pq: Vec<u8>,
}

/// A hashing primitive. Every suite provides one; the `root` field is 32 bytes in
/// the frozen layout, so the digest size is fixed (spec §12).
pub trait Hash: core::fmt::Debug + Send + Sync {
    /// Hash `data` to 32 bytes.
    fn hash(&self, data: &[u8]) -> [u8; ROOT_LEN];
}

/// HKDF-SHA-256, the KDF every suite uses (design §7).
pub trait Kdf: core::fmt::Debug + Send + Sync {
    /// Derive `out.len()` bytes from `ikm`, with the given salt and info.
    fn derive(
        &self,
        ikm: &[u8],
        salt: &[u8],
        info: &[u8],
        out: &mut [u8],
    ) -> Result<(), SuiteError>;
}

/// The hybrid KEM of design §7: X25519 + ML-KEM-768, with a transcript-binding
/// HKDF combiner (ticket 11). Both shared secrets and the full transcript of both
/// ciphertexts and both public keys enter the derivation, so steering one component
/// cannot steer the resulting key.
pub trait Kem: core::fmt::Debug + Send + Sync {
    /// Length of a hybrid public key (X25519 ‖ ML-KEM-768 encapsulation key).
    fn public_key_len(&self) -> usize;
    /// Length of a hybrid secret key (X25519 ‖ ML-KEM-768 decapsulation key).
    fn secret_key_len(&self) -> usize;
    /// Length of a hybrid ciphertext (X25519 ephemeral public key ‖ ML-KEM-768
    /// ciphertext).
    fn ciphertext_len(&self) -> usize;
    /// Length of the derived content key. The combiner always produces 32 bytes,
    /// which is the frozen `root`/content-key size (spec §12).
    fn shared_secret_len(&self) -> usize;

    /// Generate a fresh hybrid keypair.
    fn generate(&self) -> Result<KemKeyPair, SuiteError>;

    /// Encapsulate to `public_key`, returning the hybrid ciphertext and the derived
    /// content key.
    fn encapsulate(
        &self,
        public_key: &[u8],
        context: &KemContext<'_>,
    ) -> Result<(Vec<u8>, [u8; ROOT_LEN]), SuiteError>;

    /// Decapsulate `ciphertext` under `secret_key`, deriving the same content key
    /// the sender computed.
    fn decapsulate(
        &self,
        secret_key: &[u8],
        ciphertext: &[u8],
        context: &KemContext<'_>,
    ) -> Result<[u8; ROOT_LEN], SuiteError>;
}

/// The AEAD. The chunked STREAM construction of ticket 12 builds on this
/// per-message primitive: the STREAM layer derives the nonce and AAD and calls
/// [`Aead::seal`] or [`Aead::open`] once per chunk.
pub trait Aead: core::fmt::Debug + Send + Sync {
    /// Length of a content key.
    fn key_len(&self) -> usize;
    /// Length of a nonce.
    fn nonce_len(&self) -> usize;
    /// Length of the authentication tag appended to each ciphertext.
    fn tag_len(&self) -> usize;

    /// Seal `plaintext`, returning `ciphertext ‖ tag`.
    fn seal(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, SuiteError>;

    /// Open `ciphertext ‖ tag`, returning the plaintext. A tag mismatch is a hard
    /// failure: no plaintext is returned.
    fn open(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SuiteError>;
}

/// The hybrid signature: Ed25519 + ML-DSA-65 (spec §19, suite 1). Both components
/// MUST verify over the identical transcript (design §7, spec §8.4); a bundle that
/// carries one of the pair is a downgrade and is refused by F4 before it reaches a
/// verifier.
pub trait Signature: core::fmt::Debug + Send + Sync {
    /// Length of the classical public key.
    fn classical_public_key_len(&self) -> usize;
    /// Length of the classical signature.
    fn classical_signature_len(&self) -> usize;
    /// Length of the post-quantum public key.
    fn pq_public_key_len(&self) -> usize;
    /// Length of the post-quantum signature.
    fn pq_signature_len(&self) -> usize;

    /// Generate a fresh hybrid signing key and its public key.
    fn keypair(&self) -> Result<(HybridSigningKey, HybridPublicKey), SuiteError>;

    /// Produce both signatures over `transcript`.
    fn sign(
        &self,
        transcript: &[u8],
        signing_key: &HybridSigningKey,
    ) -> Result<HybridSignature, SuiteError>;

    /// Verify **both** components over `transcript`. Returns an error naming the
    /// first component that failed; a caller must treat any error as "not
    /// authentic".
    fn verify(
        &self,
        transcript: &[u8],
        public_key: &HybridPublicKey,
        signature: &HybridSignature,
    ) -> Result<(), SuiteError>;
}

/// The BLAKE3 hash role, implemented.
#[derive(Debug, Clone, Copy, Default)]
pub struct Blake3;

impl Hash for Blake3 {
    fn hash(&self, data: &[u8]) -> [u8; ROOT_LEN] {
        *blake3::hash(data).as_bytes()
    }
}

static BLAKE3: Blake3 = Blake3;

// The phase 2 primitives (tickets 10–12). Each is a zero-sized role implementation;
// `suite_id` selects which one a file uses, and the registry below is the only place
// that mapping lives.
use crate::crypto::aead::{Aes256Gcm, XChaCha20Poly1305Aead};
use crate::crypto::hybrid_kem::X25519MlKem768;
use crate::crypto::kdf::HkdfSha256;
use crate::crypto::sign::Ed25519MlDsa65;

static HKDF_SHA256_ROLE: HkdfSha256 = HkdfSha256;
static X25519_MLKEM768_ROLE: X25519MlKem768 = X25519MlKem768;
static AES_256_GCM_ROLE: Aes256Gcm = Aes256Gcm;
static XCHACHA20_POLY1305_ROLE: XChaCha20Poly1305Aead = XChaCha20Poly1305Aead;
static ED25519_MLDSA65_ROLE: Ed25519MlDsa65 = Ed25519MlDsa65;

/// The hash algorithm a suite selects. Every suite uses BLAKE3 today; the enum
/// exists so a future suite can select another without a new field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashId {
    /// BLAKE3 (spec §12).
    Blake3,
}

/// The key-derivation algorithm a suite selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfId {
    /// HKDF-SHA-256 (design §7).
    HkdfSha256,
}

/// The KEM a suite selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemId {
    /// X25519 + ML-KEM-768, hybrid (design §7).
    X25519MlKem768,
}

/// The AEAD a suite selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadId {
    /// AES-256-GCM, for hosts with AES acceleration.
    Aes256Gcm,
    /// XChaCha20-Poly1305, for hosts without.
    XChaCha20Poly1305,
}

/// The signature set a suite selects. Both components MUST verify (design §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureId {
    /// Ed25519 + ML-DSA-65.
    Ed25519MlDsa65,
    /// Ed25519 + ML-DSA-65 + SLH-DSA, for the archive suite.
    Ed25519MlDsa65SlhDsa,
}

/// One crypto suite: the algorithm each primitive role selects, plus the
/// implementation of any role this build has finished.
pub struct Suite {
    /// The on-disk `suite_id`.
    pub id: u16,
    /// Human name for diagnostics only; never written to a file.
    pub name: &'static str,
    hash_id: HashId,
    kdf_id: KdfId,
    kem_id: KemId,
    aead_id: AeadId,
    signature_id: SignatureId,
    hash: &'static dyn Hash,
    kdf: Option<&'static dyn Kdf>,
    kem: Option<&'static dyn Kem>,
    aead: Option<&'static dyn Aead>,
    signature: Option<&'static dyn Signature>,
}

impl core::fmt::Debug for Suite {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Suite")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("hash_id", &self.hash_id)
            .field("kdf_id", &self.kdf_id)
            .field("kem_id", &self.kem_id)
            .field("aead_id", &self.aead_id)
            .field("signature_id", &self.signature_id)
            .field("hash", &true)
            .field("kdf", &self.kdf.is_some())
            .field("kem", &self.kem.is_some())
            .field("aead", &self.aead.is_some())
            .field("signature", &self.signature.is_some())
            .finish()
    }
}

impl Suite {
    /// The hash algorithm this suite selects.
    pub fn hash_id(&self) -> HashId {
        self.hash_id
    }
    /// The KDF this suite selects.
    pub fn kdf_id(&self) -> KdfId {
        self.kdf_id
    }
    /// The KEM this suite selects.
    pub fn kem_id(&self) -> KemId {
        self.kem_id
    }
    /// The AEAD this suite selects.
    pub fn aead_id(&self) -> AeadId {
        self.aead_id
    }
    /// The signature set this suite selects.
    pub fn signature_id(&self) -> SignatureId {
        self.signature_id
    }

    /// The hash role. Present for every suite.
    pub fn hash(&self) -> &'static dyn Hash {
        self.hash
    }

    /// The KDF role, or [`SuiteError::NotImplemented`] until ticket 15 lands.
    pub fn kdf(&self) -> Result<&'static dyn Kdf, SuiteError> {
        self.kdf.ok_or(SuiteError::NotImplemented {
            suite: self.id,
            role: Role::Kdf,
        })
    }

    /// The KEM role, or [`SuiteError::NotImplemented`] until ticket 14 lands.
    pub fn kem(&self) -> Result<&'static dyn Kem, SuiteError> {
        self.kem.ok_or(SuiteError::NotImplemented {
            suite: self.id,
            role: Role::Kem,
        })
    }

    /// The AEAD role, or [`SuiteError::NotImplemented`] until ticket 12 lands.
    pub fn aead(&self) -> Result<&'static dyn Aead, SuiteError> {
        self.aead.ok_or(SuiteError::NotImplemented {
            suite: self.id,
            role: Role::Aead,
        })
    }

    /// The signature role, or [`SuiteError::NotImplemented`] until ticket 10 lands.
    pub fn signature(&self) -> Result<&'static dyn Signature, SuiteError> {
        self.signature.ok_or(SuiteError::NotImplemented {
            suite: self.id,
            role: Role::Signature,
        })
    }
}

/// The default suite (design §7, suite 1): X25519+ML-KEM-768, AES-256-GCM,
/// BLAKE3, HKDF-SHA-256, Ed25519+ML-DSA-65.
static SUITE_1: Suite = Suite {
    id: 1,
    name: "hybrid-aes",
    hash_id: HashId::Blake3,
    kdf_id: KdfId::HkdfSha256,
    kem_id: KemId::X25519MlKem768,
    aead_id: AeadId::Aes256Gcm,
    signature_id: SignatureId::Ed25519MlDsa65,
    hash: &BLAKE3,
    kdf: Some(&HKDF_SHA256_ROLE),
    kem: Some(&X25519_MLKEM768_ROLE),
    aead: Some(&AES_256_GCM_ROLE),
    signature: Some(&ED25519_MLDSA65_ROLE),
};

/// Suite 2: identical to suite 1 with XChaCha20-Poly1305 for hosts without AES
/// acceleration.
static SUITE_2: Suite = Suite {
    id: 2,
    name: "hybrid-chacha",
    hash_id: HashId::Blake3,
    kdf_id: KdfId::HkdfSha256,
    kem_id: KemId::X25519MlKem768,
    aead_id: AeadId::XChaCha20Poly1305,
    signature_id: SignatureId::Ed25519MlDsa65,
    hash: &BLAKE3,
    kdf: Some(&HKDF_SHA256_ROLE),
    kem: Some(&X25519_MLKEM768_ROLE),
    aead: Some(&XCHACHA20_POLY1305_ROLE),
    signature: Some(&ED25519_MLDSA65_ROLE),
};

/// Suite 3: suite 1 plus SLH-DSA, for the long-term archive copy.
///
/// The signature role is deliberately absent: SLH-DSA is not in this build, and a
/// suite with one unimplemented component of a *hybrid* signature is not a working
/// signature role. Resolving it reports `NotImplemented` naming the suite, which is
/// the accurate diagnostic — a suite is not silently reduced to Ed25519+ML-DSA.
static SUITE_3: Suite = Suite {
    id: 3,
    name: "hybrid-archive",
    hash_id: HashId::Blake3,
    kdf_id: KdfId::HkdfSha256,
    kem_id: KemId::X25519MlKem768,
    aead_id: AeadId::Aes256Gcm,
    signature_id: SignatureId::Ed25519MlDsa65SlhDsa,
    hash: &BLAKE3,
    kdf: Some(&HKDF_SHA256_ROLE),
    kem: Some(&X25519_MLKEM768_ROLE),
    aead: Some(&AES_256_GCM_ROLE),
    signature: None,
};

/// Every suite this build knows.
static REGISTRY: [&Suite; 3] = [&SUITE_1, &SUITE_2, &SUITE_3];

/// Resolve a `suite_id` to its suite.
///
/// **Never call this during header parsing.** The registry is consulted where a
/// primitive is first needed (spec §4.3, §19), so an unknown id yields a diagnostic
/// about the suite rather than a misleading structural error.
pub fn suite(id: u16) -> Result<&'static Suite, SuiteError> {
    REGISTRY
        .iter()
        .copied()
        .find(|s| s.id == id)
        .ok_or(SuiteError::UnknownSuite { id })
}
