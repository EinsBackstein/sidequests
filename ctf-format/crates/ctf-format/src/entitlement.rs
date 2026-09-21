//! Entitlement records: an append-only, hash-chained, hybrid-signed log.
//!
//! Normative: `spec/SPEC.md` §18. Rationale: design §9. This is ticket 39.
//!
//! An `entitlement` section (kind `6`, spec §5.2) carries the log inside the
//! bundle rather than in a platform database. That placement is the whole point:
//! on-site CTFs run air-gapped forensics workstations off USB media, so the chain
//! has to validate with no platform reachable and stay auditable even if the
//! platform's database is later found to be wrong. Everything except signature
//! verification (E9) is therefore a pure function of the bundle's own bytes.
//!
//! # Plaintext (E1)
//!
//! The plaintext is one canonical CBOR **array** of record maps, decoded under the
//! same rules as the manifest ([`crate::cbor`], spec §7.1), with no bytes after the
//! array. Canonical encoding is enforced on decode, so a record id — a hash of the
//! record's canonical bytes — cannot be steered by a second spelling of the same
//! record.
//!
//! # The chain (E3, E5, E6, E7)
//!
//! `seq` is the authoritative ordering and MUST be exactly `0, 1, …, count−1` in
//! array order. Each record's `prev` is the **record id** of its predecessor, and
//! the genesis record's `prev` is 32 zero bytes. The genesis record MUST be a
//! `grant` carrying `root`, the bundle's commitment root (spec §8.3); that binding
//! is what stops a grant for challenge version 3 being replayed as one for version
//! 4. No later record may carry `root`.
//!
//! `timestamp` is **advisory only** and MUST NOT be used for ordering or
//! validation: clocks drift and clients lie, and the field exists for human audit
//! display.
//!
//! # Signatures (E9)
//!
//! Both signatures cover the identical transcript
//!
//! ```text
//! sig_input = "ctf/entitlement-sig/v1" ‖ u16_le(suite_id) ‖ u32_le(seq) ‖ record_id
//! ```
//!
//! and both components of the suite's hybrid signature MUST verify
//! ([`crate::suite::Signature`], spec §19). The label differs from §8.4's, so a
//! footer signature can never be replayed as an entitlement signature even though
//! the two share keys (design §9). `sig_holder` is required only for `transfer`,
//! which is what makes a handoff non-repudiable: the current holder cannot later
//! claim another player took the challenge.
//!
//! Key distribution is out of scope (spec §14): E9 takes trusted keys as **inputs**
//! — the platform public key always, and for a `transfer` the public key of the
//! holder named by the previous record. [`HolderKeys`] is the small resolver that
//! supplies the latter. [`EntitlementChain::validate`] never touches a key and
//! never reaches the network; [`EntitlementChain::verify_signatures`] is the
//! separate, explicit step that does.
//!
//! # Authentication is a separate step
//!
//! [`EntitlementChain::validate`] establishes structure and the genesis binding —
//! E1–E8 — with no key and no network. It does **not** establish authenticity:
//! that is [`EntitlementChain::verify_signatures`], which needs trusted keys the
//! bundle does not carry (§14). A caller MUST NOT report a chain as authenticated
//! until E9 has run with keys it trusts (spec §18.4).

use crate::cbor::Value;
use crate::footer::ROOT_LEN;
use crate::suite::{HybridPublicKey, HybridSignature, HybridSigningKey, Role, SuiteError, suite};
use crate::{Error, Result};

/// Domain-separated label for a record id. ASCII, no terminator, no length prefix:
/// it is the BLAKE3 prefix. 25 bytes (spec §18.2).
pub const RECORD_LABEL: &[u8] = b"ctf/entitlement/record/v1";

/// Domain-separated label for the signature transcript. ASCII, no terminator, no
/// length prefix. The label differs from §8.4's, which is what blocks a footer
/// signature being replayed against an entitlement record (design §9).
pub const SIG_LABEL: &[u8] = b"ctf/entitlement-sig/v1";

/// Domain label for the holder public-key hash (spec §34.1). 18 ASCII bytes.
pub const HOLDER_HASH_LABEL: &[u8] = b"ctf/holder-hash/v1";

/// The holder public-key hash (spec §34.1).
///
/// `BLAKE3("ctf/holder-hash/v1" ‖ pk_classical ‖ pk_pq)` over the holder's hybrid
/// **signature** public key. The spec fixes the construction so a verifier can
/// resolve a record's 32-byte `holder` field to a trusted key; the KEM key a §24
/// progress envelope uses is a separate input (§34.2).
pub fn holder_hash(public_key: &HybridPublicKey) -> [u8; ROOT_LEN] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(HOLDER_HASH_LABEL);
    hasher.update(&public_key.classical);
    hasher.update(&public_key.pq);
    *hasher.finalize().as_bytes()
}

/// The four record types (§18.1). A `type` that is not one of these names is E4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordType {
    /// The genesis record: binds a subject to a holder for a bundle version.
    Grant,
    /// A holder change. Requires the current holder's signature (§18.3).
    Transfer,
    /// Revocation of a subject's entitlement.
    Revoke,
    /// An advisory progress marker, e.g. a sealed stage blob.
    Progress,
}

impl RecordType {
    /// The wire name, exactly as it appears in the `type` field.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Grant => "grant",
            Self::Transfer => "transfer",
            Self::Revoke => "revoke",
            Self::Progress => "progress",
        }
    }

    /// Parse a wire name. `None` for anything outside the four names (E4).
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "grant" => Some(Self::Grant),
            "transfer" => Some(Self::Transfer),
            "revoke" => Some(Self::Revoke),
            "progress" => Some(Self::Progress),
            _ => None,
        }
    }
}

/// An advisory integer timestamp (§18.1): a CBOR unsigned or negative integer,
/// kept in the encoded form so the whole range survives.
///
/// `Nint(n)` is the negative integer `-1 - n`, CBOR major type 1's own
/// representation. The type is deliberately never compared or ordered by this
/// module: `timestamp` MUST NOT drive ordering or validation (§18.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Timestamp {
    /// Non-negative, CBOR major type 0.
    Uint(u64),
    /// `-1 - n`, CBOR major type 1.
    Nint(u64),
}

impl Timestamp {
    /// Read a `timestamp` value. `None` when it is neither a uint nor a nint (E2).
    pub fn from_value(value: &Value) -> Option<Self> {
        match value {
            Value::Uint(n) => Some(Self::Uint(*n)),
            Value::Nint(n) => Some(Self::Nint(*n)),
            _ => None,
        }
    }

    /// The CBOR value this timestamp encodes to.
    pub fn to_value(self) -> Value {
        match self {
            Self::Uint(n) => Value::Uint(n),
            Self::Nint(n) => Value::Nint(n),
        }
    }
}

/// One entitlement record (§18.1).
///
/// The 32-byte fields are fixed-size arrays rather than `Vec<u8>` so a wrong length
/// is unrepresentable through the typed API (E2); [`EntitlementRecord::check`] then
/// covers the rules the type system cannot, namely `sig_platform` presence and the
/// `transfer`/`sig_holder` pairing (E8).
///
/// `sig_platform` is `Option` because a record exists unsigned between construction
/// and [`EntitlementRecord::sign`]; a chain that still carries an unsigned record
/// fails [`EntitlementChain::validate`] rather than encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntitlementRecord {
    /// Sequence number; the authoritative ordering (E3).
    pub seq: u32,
    /// `grant`, `transfer`, `revoke`, or `progress` (E4).
    pub record_type: RecordType,
    /// Challenge `id` the record is about.
    pub challenge: String,
    /// Subject the record binds.
    pub subject: String,
    /// Holder public-key hash (design §9), 32 bytes.
    pub holder: [u8; ROOT_LEN],
    /// Record id of the previous record; 32 zero bytes at genesis (E7, E5).
    pub prev: [u8; ROOT_LEN],
    /// Commitment root (§8.3) the genesis grant was issued for; genesis only (E5, E6).
    pub root: Option<[u8; ROOT_LEN]>,
    /// Platform-issued, advisory only. Never used for ordering (§18.2).
    pub timestamp: Option<Timestamp>,
    /// Opaque bytes, e.g. a `progress` blob sealed to the new holder.
    pub payload: Option<Vec<u8>>,
    /// Current holder's hybrid signature; required for `transfer` (E8).
    pub sig_holder: Option<HybridSignature>,
    /// Platform's hybrid signature; always required (E8).
    pub sig_platform: Option<HybridSignature>,
}

/// The field names a record map may carry. Anything else is E2's "unknown key".
const RECORD_KEYS: &[&str] = &[
    "seq",
    "type",
    "challenge",
    "subject",
    "holder",
    "prev",
    "root",
    "timestamp",
    "payload",
    "sig_holder",
    "sig_platform",
];

/// The keys a signature map may carry, and must carry (§18.1).
const SIGNATURE_KEYS: &[&str] = &["classical", "pq"];

/// A structural failure with a static description. The text is never
/// attacker-controlled, so a `Display` cannot become an oracle.
fn bad(what: &'static str) -> Error {
    Error::Inconsistent { what }
}

/// The canonical map entries of one record. `include_signatures` is `false` for
/// the record-id preimage (§18.2 removes both `sig_*` keys) and `true` for the wire
/// encoding.
fn record_entries(record: &EntitlementRecord, include_signatures: bool) -> Vec<(Value, Value)> {
    let mut entries = Vec::with_capacity(RECORD_KEYS.len());
    entries.push((
        Value::Text("seq".to_owned()),
        Value::Uint(u64::from(record.seq)),
    ));
    entries.push((
        Value::Text("type".to_owned()),
        Value::Text(record.record_type.name().to_owned()),
    ));
    entries.push((
        Value::Text("challenge".to_owned()),
        Value::Text(record.challenge.clone()),
    ));
    entries.push((
        Value::Text("subject".to_owned()),
        Value::Text(record.subject.clone()),
    ));
    entries.push((
        Value::Text("holder".to_owned()),
        Value::Bytes(record.holder.to_vec()),
    ));
    entries.push((
        Value::Text("prev".to_owned()),
        Value::Bytes(record.prev.to_vec()),
    ));
    if let Some(root) = record.root {
        entries.push((Value::Text("root".to_owned()), Value::Bytes(root.to_vec())));
    }
    if let Some(timestamp) = record.timestamp {
        entries.push((Value::Text("timestamp".to_owned()), timestamp.to_value()));
    }
    if let Some(payload) = &record.payload {
        entries.push((
            Value::Text("payload".to_owned()),
            Value::Bytes(payload.clone()),
        ));
    }
    if include_signatures {
        if let Some(sig) = &record.sig_holder {
            entries.push((Value::Text("sig_holder".to_owned()), signature_value(sig)));
        }
        if let Some(sig) = &record.sig_platform {
            entries.push((Value::Text("sig_platform".to_owned()), signature_value(sig)));
        }
    }
    entries
}

/// A signature map: exactly `classical` and `pq`, each a byte string (§18.1).
fn signature_value(signature: &HybridSignature) -> Value {
    Value::Map(vec![
        (
            Value::Text("classical".to_owned()),
            Value::Bytes(signature.classical.clone()),
        ),
        (
            Value::Text("pq".to_owned()),
            Value::Bytes(signature.pq.clone()),
        ),
    ])
}

/// A 32-byte byte string, or E2.
fn fixed_32(value: &Value, what: &'static str) -> Result<[u8; ROOT_LEN]> {
    let bytes = value.as_bytes().ok_or(bad(what))?;
    <[u8; ROOT_LEN]>::try_from(bytes).map_err(|_| bad(what))
}

/// Parse a signature map (§18.1). Rejects unknown keys, missing keys, and non-byte
/// string components (E2).
fn parse_signature(value: &Value) -> Result<HybridSignature> {
    let entries = value
        .as_map()
        .ok_or(bad("entitlement signature is not a CBOR map"))?;
    for (key, _) in entries {
        let key = key
            .as_text()
            .ok_or(bad("entitlement signature map key is not text"))?;
        if !SIGNATURE_KEYS.contains(&key) {
            return Err(bad("entitlement signature map has an unknown key"));
        }
    }
    let classical = value
        .get("classical")
        .and_then(Value::as_bytes)
        .ok_or(bad(
            "entitlement signature map is missing `classical` or it is not a byte string",
        ))?
        .to_vec();
    let pq = value
        .get("pq")
        .and_then(Value::as_bytes)
        .ok_or(bad(
            "entitlement signature map is missing `pq` or it is not a byte string",
        ))?
        .to_vec();
    Ok(HybridSignature { classical, pq })
}

impl EntitlementRecord {
    /// Parse one record map (E2, E4, E8).
    ///
    /// Unknown keys are rejected rather than carried: unlike the manifest, an
    /// entitlement record has no `crit` mechanism, and every field here is covered
    /// by a hash chain or a signature, so a carried key would be bytes no rule
    /// authenticates.
    pub fn from_value(value: &Value) -> Result<Self> {
        let entries = value
            .as_map()
            .ok_or(bad("entitlement record is not a CBOR map"))?;
        for (key, _) in entries {
            let key = key
                .as_text()
                .ok_or(bad("entitlement record key is not text"))?;
            if !RECORD_KEYS.contains(&key) {
                return Err(bad("entitlement record has an unknown key"));
            }
        }

        let seq = value
            .get("seq")
            .and_then(Value::as_uint)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or(bad(
                "entitlement record is missing `seq` or it is not a uint",
            ))?;
        let record_type = value
            .get("type")
            .and_then(Value::as_text)
            .and_then(RecordType::from_name)
            .ok_or(bad(
                "entitlement record `type` is not one of grant, transfer, revoke, progress",
            ))?;
        let challenge = value
            .get("challenge")
            .and_then(Value::as_text)
            .ok_or(bad(
                "entitlement record is missing `challenge` or it is not text",
            ))?
            .to_owned();
        let subject = value
            .get("subject")
            .and_then(Value::as_text)
            .ok_or(bad(
                "entitlement record is missing `subject` or it is not text",
            ))?
            .to_owned();
        let holder = value
            .get("holder")
            .ok_or(bad("entitlement record is missing `holder`"))
            .and_then(|v| fixed_32(v, "entitlement record `holder` is not exactly 32 bytes"))?;
        let prev = value
            .get("prev")
            .ok_or(bad("entitlement record is missing `prev`"))
            .and_then(|v| fixed_32(v, "entitlement record `prev` is not exactly 32 bytes"))?;
        let root = match value.get("root") {
            Some(v) => Some(fixed_32(
                v,
                "entitlement record `root` is not exactly 32 bytes",
            )?),
            None => None,
        };
        let timestamp = match value.get("timestamp") {
            Some(v) => Some(
                Timestamp::from_value(v)
                    .ok_or(bad("entitlement record `timestamp` is not an integer"))?,
            ),
            None => None,
        };
        let payload = match value.get("payload") {
            Some(v) => Some(
                v.as_bytes()
                    .ok_or(bad("entitlement record `payload` is not a byte string"))?
                    .to_vec(),
            ),
            None => None,
        };
        let sig_holder = match value.get("sig_holder") {
            Some(v) => Some(parse_signature(v)?),
            None => None,
        };
        let sig_platform = match value.get("sig_platform") {
            Some(v) => Some(parse_signature(v)?),
            None => None,
        };

        let record = Self {
            seq,
            record_type,
            challenge,
            subject,
            holder,
            prev,
            root,
            timestamp,
            payload,
            sig_holder,
            sig_platform,
        };
        record.check()?;
        Ok(record)
    }

    /// The E2/E4/E8 rules the type system does not already enforce.
    ///
    /// `seq` is a `u32`, `record_type` an enum, and the 32-byte fields fixed-size
    /// arrays, so E2's type and length rules cannot be violated by a constructed
    /// record. What remains is the pairing rule E8: `sig_platform` is always
    /// required, and `sig_holder` is required for `transfer` and forbidden
    /// otherwise. The last clause is what keeps an unauthenticated signature map
    /// off a non-transfer record, where no rule would cover it.
    pub fn check(&self) -> Result<()> {
        if self.sig_platform.is_none() {
            return Err(bad("entitlement record is missing `sig_platform`"));
        }
        if self.record_type == RecordType::Transfer {
            if self.sig_holder.is_none() {
                return Err(bad("transfer record is missing `sig_holder`"));
            }
        } else if self.sig_holder.is_some() {
            return Err(bad("non-transfer record carries `sig_holder`"));
        }
        Ok(())
    }

    /// The record id of §18.2:
    /// `BLAKE3("ctf/entitlement/record/v1" ‖ cbor)`, where `cbor` is the canonical
    /// encoding of the record map with both `sig_*` keys removed.
    ///
    /// The signature keys are removed so that signing does not change the id, which
    /// is what lets the id appear inside the very transcript both signatures cover.
    pub fn record_id(&self) -> Result<[u8; ROOT_LEN]> {
        let cbor = Value::Map(record_entries(self, false)).encode()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(RECORD_LABEL);
        hasher.update(&cbor);
        Ok(*hasher.finalize().as_bytes())
    }

    /// Produce both signatures over the §18.3 transcript (E9's production half).
    ///
    /// The platform signature is always produced; for a `transfer` the current
    /// holder's signing key is required and its signature is stored in
    /// `sig_holder`. A non-transfer record's `sig_holder` is cleared, so signing
    /// cannot leave an unauthenticated signature map behind (E8).
    ///
    /// `record_id` is computed first, because it is part of the transcript and does
    /// not itself depend on either signature.
    pub fn sign(
        &mut self,
        suite_id: u16,
        platform_key: &HybridSigningKey,
        holder_key: Option<&HybridSigningKey>,
    ) -> Result<()> {
        let role = suite(suite_id)?.signature()?;
        let transcript = sig_input(self.seq, &self.record_id()?, suite_id);
        self.sig_platform = Some(role.sign(&transcript, platform_key)?);
        match self.record_type {
            RecordType::Transfer => {
                let holder_key = holder_key.ok_or(SuiteError::Primitive {
                    role: Role::Signature,
                    reason: "transfer requires the current holder's signing key",
                })?;
                self.sig_holder = Some(role.sign(&transcript, holder_key)?);
            }
            _ => self.sig_holder = None,
        }
        Ok(())
    }
}

/// `"ctf/entitlement-sig/v1" ‖ u16_le(suite_id) ‖ u32_le(seq) ‖ record_id`.
///
/// Every element after the label is fixed width, so the concatenation is
/// unambiguous without length prefixes (design §7's `LP` rule applies only to
/// variable-width elements). The transcript is `22 + 2 + 4 + 32 = 60` bytes.
///
/// `suite_id` is inside the transcript so a signature cannot be replayed under a
/// downgraded suite, and `seq` and `record_id` bind the signature to one position
/// in one chain.
pub fn sig_input(seq: u32, record_id: &[u8; ROOT_LEN], suite_id: u16) -> Vec<u8> {
    let mut v = Vec::with_capacity(SIG_LABEL.len() + 2 + 4 + ROOT_LEN);
    v.extend_from_slice(SIG_LABEL);
    v.extend_from_slice(&suite_id.to_le_bytes());
    v.extend_from_slice(&seq.to_le_bytes());
    v.extend_from_slice(record_id);
    v
}

/// Trusted holder public keys, keyed by the 32-byte `holder` hash a record names.
///
/// Key distribution is out of scope (spec §14): this is the verifier's input, never
/// a bundle field. A `transfer` record is verified against the key of the holder
/// named by its **predecessor**, so the resolver answers "who was the current
/// holder when this record was signed", not "who signs this record".
#[derive(Debug, Clone, Default)]
pub struct HolderKeys {
    entries: Vec<([u8; ROOT_LEN], HybridPublicKey)>,
}

impl HolderKeys {
    /// An empty resolver. Every `transfer` will fail to find its holder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a holder's public key under its 32-byte holder hash.
    pub fn insert(&mut self, holder: [u8; ROOT_LEN], key: HybridPublicKey) {
        self.entries.push((holder, key));
    }

    /// Build a resolver from `(holder_hash, public_key)` pairs.
    pub fn from_pairs(pairs: impl IntoIterator<Item = ([u8; ROOT_LEN], HybridPublicKey)>) -> Self {
        Self {
            entries: pairs.into_iter().collect(),
        }
    }

    /// The trusted key for `holder`, or `None` if the verifier does not hold one.
    pub fn get(&self, holder: &[u8; ROOT_LEN]) -> Option<&HybridPublicKey> {
        self.entries
            .iter()
            .find(|(h, _)| h == holder)
            .map(|(_, key)| key)
    }
}

/// A whole entitlement chain: an ordered `Vec` of records (§18.2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EntitlementChain {
    records: Vec<EntitlementRecord>,
}

impl EntitlementChain {
    /// An empty chain. It does not validate: a chain without a genesis grant has
    /// nothing binding the bundle's commitment root (§18.2, E5).
    pub fn new() -> Self {
        Self::default()
    }

    /// Wrap already-built records. [`EntitlementChain::validate`] is the check.
    pub fn from_records(records: Vec<EntitlementRecord>) -> Self {
        Self { records }
    }

    /// The records in array order.
    pub fn records(&self) -> &[EntitlementRecord] {
        &self.records
    }

    /// The records mutably, for building or inspecting a chain before validation.
    pub fn records_mut(&mut self) -> &mut [EntitlementRecord] {
        &mut self.records
    }

    /// Consume the chain and return its records.
    pub fn into_records(self) -> Vec<EntitlementRecord> {
        self.records
    }

    /// Number of records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the chain is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// The record at `n`, or `None` when `n` is out of range.
    pub fn get(&self, n: usize) -> Option<&EntitlementRecord> {
        self.records.get(n)
    }

    /// Append a record. The caller is responsible for its `seq` and `prev`.
    pub fn push(&mut self, record: EntitlementRecord) {
        self.records.push(record);
    }

    /// Append the genesis `grant`, binding `subject` to `holder` for the bundle
    /// whose commitment root is `commitment_root` (E5, §18.2).
    ///
    /// Builds `seq = 0` and the zero `prev` itself, so the genesis binding cannot
    /// be constructed wrong. The chain MUST be empty: a second genesis is not a
    /// grant, and a grant that is not at `seq = 0` is E5.
    #[allow(clippy::too_many_arguments)]
    pub fn append_grant(
        &mut self,
        challenge: &str,
        subject: &str,
        holder: [u8; ROOT_LEN],
        commitment_root: [u8; ROOT_LEN],
        suite_id: u16,
        platform_key: &HybridSigningKey,
        timestamp: Option<Timestamp>,
    ) -> Result<()> {
        if !self.records.is_empty() {
            return Err(bad("a genesis grant must be the first record (E5)"));
        }
        let mut record = EntitlementRecord {
            seq: 0,
            record_type: RecordType::Grant,
            challenge: challenge.to_owned(),
            subject: subject.to_owned(),
            holder,
            prev: [0u8; ROOT_LEN],
            root: Some(commitment_root),
            timestamp,
            payload: None,
            sig_holder: None,
            sig_platform: None,
        };
        record.sign(suite_id, platform_key, None)?;
        self.records.push(record);
        Ok(())
    }

    /// Append a signed `transfer` handing the subject to `new_holder` (E8, §18.3).
    ///
    /// Builds `seq` and `prev` from the chain, so the hash link cannot be wrong,
    /// and signs with the platform key always and with `current_holder_key` — the
    /// holder named by the previous record — for the holder signature that makes
    /// the handoff non-repudiable. `payload` is where a sealed progress blob goes
    /// ([`crate::seal_progress`]). The chain MUST already have a genesis: a transfer
    /// cannot be first, because there is no current holder to sign it.
    #[allow(clippy::too_many_arguments)]
    pub fn append_transfer(
        &mut self,
        challenge: &str,
        subject: &str,
        new_holder: [u8; ROOT_LEN],
        suite_id: u16,
        platform_key: &HybridSigningKey,
        current_holder_key: &HybridSigningKey,
        timestamp: Option<Timestamp>,
        payload: Option<Vec<u8>>,
    ) -> Result<()> {
        let last = self.records.last().ok_or(bad(
            "a transfer needs a genesis grant to name the current holder (E5)",
        ))?;
        let prev = last.record_id()?;
        let seq = u32::try_from(self.records.len())
            .map_err(|_| bad("entitlement chain is longer than the seq space (E3)"))?;
        let mut record = EntitlementRecord {
            seq,
            record_type: RecordType::Transfer,
            challenge: challenge.to_owned(),
            subject: subject.to_owned(),
            holder: new_holder,
            prev,
            root: None,
            timestamp,
            payload,
            sig_holder: None,
            sig_platform: None,
        };
        record.sign(suite_id, platform_key, Some(current_holder_key))?;
        self.records.push(record);
        Ok(())
    }

    /// The record id of record `n` (§18.2), or E2 when `n` is out of range.
    pub fn record_id(&self, n: usize) -> Result<[u8; ROOT_LEN]> {
        self.records
            .get(n)
            .ok_or(bad("entitlement record index is out of range"))?
            .record_id()
    }

    /// E1–E8: every structural rule that needs no key and no network.
    ///
    /// E1 (canonical CBOR array, no trailing bytes) is enforced by
    /// [`EntitlementChain::from_bytes`]; `validate` re-checks it for a chain built
    /// in memory only insofar as the records' field rules (E2, E4, E8) are
    /// concerned. The remaining rules — contiguity (E3), the genesis binding (E5),
    /// the no-`root`-after-genesis rule (E6), and the hash links (E7) — are checked
    /// here for both paths.
    pub fn validate(&self) -> Result<()> {
        if self.records.is_empty() {
            return Err(bad(
                "entitlement chain is empty; a genesis grant is required (E5)",
            ));
        }
        for (n, record) in self.records.iter().enumerate() {
            record.check()?;
            let expected = u32::try_from(n)
                .map_err(|_| bad("entitlement chain is longer than the seq space (E3)"))?;
            if record.seq != expected {
                return Err(bad(
                    "entitlement seq values are not contiguous in array order (E3)",
                ));
            }
            if n == 0 {
                if record.record_type != RecordType::Grant {
                    return Err(bad("genesis record is not a grant (E5)"));
                }
                if record.root.is_none() {
                    return Err(bad("genesis record does not carry `root` (E5)"));
                }
                if record.prev != [0u8; ROOT_LEN] {
                    return Err(bad("genesis record has a non-zero `prev` (E5)"));
                }
            } else {
                if record.root.is_some() {
                    return Err(bad("non-genesis record carries `root` (E6)"));
                }
                let prev_id = self
                    .records
                    .get(n - 1)
                    .ok_or(bad("entitlement record has no predecessor (E7)"))?
                    .record_id()?;
                if record.prev != prev_id {
                    return Err(bad("`prev` does not equal the predecessor record id (E7)"));
                }
            }
        }
        Ok(())
    }

    /// Decode and fully validate a chain's plaintext: the canonical CBOR array
    /// (E1), every record's fields (E2, E4, E8), and the chain rules (E3, E5–E7).
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let value = Value::decode(b)?;
        let items = value
            .as_array()
            .ok_or(bad("entitlement plaintext is not a CBOR array (E1)"))?;
        let mut records = Vec::with_capacity(items.len());
        for item in items {
            records.push(EntitlementRecord::from_value(item)?);
        }
        let chain = Self { records };
        chain.validate()?;
        Ok(chain)
    }

    /// Validate, and additionally require the genesis grant's `root` to equal the
    /// bundle's commitment root (§8.3).
    ///
    /// [`EntitlementChain::validate`] can only check that `root` is *present*,
    /// because a chain does not carry the bundle's commitment root. This is the
    /// check that closes the replay window §18.2 describes: a grant issued for one
    /// bundle version must not validate against another.
    pub fn validate_against_root(&self, commitment_root: &[u8; ROOT_LEN]) -> Result<()> {
        self.validate()?;
        let genesis = self
            .records
            .first()
            .ok_or(bad("entitlement chain has no genesis grant (E5)"))?;
        if genesis.root.as_ref() != Some(commitment_root) {
            return Err(bad(
                "genesis record `root` does not equal the bundle commitment root (E5)",
            ));
        }
        Ok(())
    }

    /// Encode canonically after validating, so the writer refuses to emit a chain
    /// its own reader would reject.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut items = Vec::with_capacity(self.records.len());
        for record in &self.records {
            items.push(Value::Map(record_entries(record, true)));
        }
        Value::Array(items).encode()
    }

    /// Alias for [`EntitlementChain::encode`].
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.encode()
    }

    /// Sign record `n` (E9's production half). See [`EntitlementRecord::sign`].
    ///
    /// The chain must already have `prev` links in place: the predecessor's record
    /// id is part of this record's map and therefore of the transcript.
    pub fn sign_record(
        &mut self,
        n: usize,
        suite_id: u16,
        platform_key: &HybridSigningKey,
        holder_key: Option<&HybridSigningKey>,
    ) -> Result<()> {
        self.records
            .get_mut(n)
            .ok_or(bad("entitlement record index is out of range"))?
            .sign(suite_id, platform_key, holder_key)
    }

    /// E9: verify every signature in the chain against trusted keys.
    ///
    /// The platform public key is always required. For each `transfer`, the
    /// current holder is the one named by the previous record, and its public key
    /// is resolved through `holders`. A failure of either component of either
    /// signature is a failure of the whole chain — there is no half-authentic
    /// result (spec §20.3).
    ///
    /// This is deliberately separate from [`EntitlementChain::validate`]: E9 needs
    /// keys the bundle does not carry, while E1–E8 need nothing at all.
    pub fn verify_signatures(
        &self,
        suite_id: u16,
        platform_key: &HybridPublicKey,
        holders: &HolderKeys,
    ) -> core::result::Result<(), SuiteError> {
        let role = suite(suite_id)?.signature()?;
        for (n, record) in self.records.iter().enumerate() {
            let record_id = record.record_id().map_err(|_| SuiteError::Primitive {
                role: Role::Signature,
                reason: "entitlement record could not be encoded for verification",
            })?;
            let transcript = sig_input(record.seq, &record_id, suite_id);
            let sig_platform = record.sig_platform.as_ref().ok_or(SuiteError::Primitive {
                role: Role::Signature,
                reason: "entitlement record has no platform signature",
            })?;
            role.verify(&transcript, platform_key, sig_platform)?;

            if record.record_type == RecordType::Transfer {
                let predecessor = n.checked_sub(1).and_then(|i| self.records.get(i)).ok_or(
                    SuiteError::Primitive {
                        role: Role::Signature,
                        reason: "transfer record has no predecessor to name the current holder",
                    },
                )?;
                let holder_key =
                    holders
                        .get(&predecessor.holder)
                        .ok_or(SuiteError::InvalidKey {
                            role: Role::Signature,
                        })?;
                let sig_holder = record.sig_holder.as_ref().ok_or(SuiteError::Primitive {
                    role: Role::Signature,
                    reason: "transfer record has no holder signature",
                })?;
                role.verify(&transcript, holder_key, sig_holder)?;
            }
        }
        Ok(())
    }
}
