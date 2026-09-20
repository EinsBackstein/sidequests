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
//! Only the *hash* role is implemented today: BLAKE3 is the one primitive the
//! container already depends on. The remaining roles are declared here so the
//! dispatch surface is fixed, and resolving one returns
//! [`SuiteError::NotImplemented`] rather than panicking. Tickets 10–17 fill them in
//! behind these traits; none of them needs to move a field to do it.

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

/// Why a suite or one of its primitives could not be resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuiteError {
    /// No suite in the registry has this id.
    UnknownSuite { id: u16 },
    /// The suite exists, but this build has not implemented the requested role
    /// yet. Reported where the primitive is used, never at header parse.
    NotImplemented { suite: u16, role: Role },
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
        }
    }
}

impl core::error::Error for SuiteError {}

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

/// The hybrid KEM of design §7. Implemented by ticket 14 on top of ticket 11's
/// transcript-binding combiner.
pub trait Kem: core::fmt::Debug + Send + Sync {
    /// Length of an encapsulation key.
    fn public_key_len(&self) -> usize;
    /// Length of a ciphertext this KEM produces.
    fn ciphertext_len(&self) -> usize;
}

/// The AEAD. The chunked STREAM construction is ticket 12's job; this trait is the
/// per-message primitive it builds on.
pub trait Aead: core::fmt::Debug + Send + Sync {
    /// Length of a content key.
    fn key_len(&self) -> usize;
    /// Length of a nonce.
    fn nonce_len(&self) -> usize;
}

/// The hybrid signature. Both components MUST verify (design §7).
pub trait Signature: core::fmt::Debug + Send + Sync {
    /// Length of a signing key.
    fn public_key_len(&self) -> usize;
    /// Length of a signature this suite produces.
    fn signature_len(&self) -> usize;
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
    kdf: None,
    kem: None,
    aead: None,
    signature: None,
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
    kdf: None,
    kem: None,
    aead: None,
    signature: None,
};

/// Suite 3: suite 1 plus SLH-DSA, for the long-term archive copy.
static SUITE_3: Suite = Suite {
    id: 3,
    name: "hybrid-archive",
    hash_id: HashId::Blake3,
    kdf_id: KdfId::HkdfSha256,
    kem_id: KemId::X25519MlKem768,
    aead_id: AeadId::Aes256Gcm,
    signature_id: SignatureId::Ed25519MlDsa65SlhDsa,
    hash: &BLAKE3,
    kdf: None,
    kem: None,
    aead: None,
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
