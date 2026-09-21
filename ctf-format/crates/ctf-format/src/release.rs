//! Sealed release interop (ticket 66).
//!
//! Normative: `spec/SPEC.md` §27. A `solver`, `writeup`, or `progress` section is
//! `SEALED`: its plaintext needs a key the platform does not hold while the event
//! runs (design §4). At event end the **offline seal key** is brought back and the
//! sections are released, producing assets organizers can serve and archive.
//!
//! # What this does and does not protect
//!
//! The seal key is a hybrid KEM secret key held offline (HSM, split key, or an
//! organizer's laptop) — **not resident on the platform during the event**. This
//! module runs wherever that key is, decrypts the sections the bundle declares
//! releasable, and emits an audit record. It does not protect against a platform
//! that holds the seal key anyway: if the key is online, Pillar 3 is policy, not
//! cryptography (design §4). Stated here rather than implied.
//!
//! # Auditability
//!
//! [`ReleaseReport`] records the bundle's commitment root and every released
//! section's `name_id`, name, size, and root. It contains no plaintext, so it can be
//! published or archived without leaking a writeup or solver.

use serde::Serialize;

use crate::bundle::Bundle;
use crate::cbor::Value;
use crate::footer::ROOT_LEN;
use crate::{Error, Result, SectionFlags};

/// One section released by [`release_at_event_end`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReleasedMember {
    /// The section's cryptographic identity.
    pub name_id: u16,
    /// The section's name.
    pub name: String,
    /// Plaintext size.
    pub size: u64,
    /// `BLAKE3` root of the released plaintext, hex-encoded.
    pub root: String,
}

/// What a release produced, without any plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReleaseReport {
    /// The bundle's commitment root, hex-encoded; binds the release to one bundle.
    pub bundle_root: String,
    /// The challenge `id`.
    pub challenge_id: String,
    /// The challenge `version`.
    pub version: u64,
    /// The release mode the declaration named, or `"all"` when there was none.
    pub release: String,
    /// The sections that were released.
    pub members: Vec<ReleasedMember>,
}

impl ReleaseReport {
    /// The report as pretty JSON, for the operator's audit log.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|_| Error::Inconsistent {
            what: "could not serialize the release report",
        })
    }
}

/// One released section's plaintext, kept out of the JSON report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleasedAsset {
    /// The audit record for this member.
    pub member: ReleasedMember,
    /// The decrypted plaintext.
    pub bytes: Vec<u8>,
}

/// The result of a release: an auditable report plus the recovered assets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    /// The audit record.
    pub report: ReleaseReport,
    /// The recovered plaintexts, one per released member.
    pub assets: Vec<ReleasedAsset>,
}

/// The `sealed` declaration: release mode and member names (spec §7.6).
struct SealedDeclaration {
    release: String,
    members: Option<Vec<String>>,
}

fn sealed_declaration(bundle: &Bundle<'_>) -> Option<SealedDeclaration> {
    let sealed = bundle.manifest.declaration("sealed")?;
    let release = sealed
        .get("release")
        .and_then(Value::as_text)
        .unwrap_or("manual")
        .to_owned();
    let members = sealed.get("members").and_then(Value::as_array).map(|a| {
        a.iter()
            .filter_map(Value::as_text)
            .map(str::to_owned)
            .collect()
    });
    Some(SealedDeclaration { release, members })
}

/// Release the sections a bundle declares for `event_end`, using the offline seal key.
///
/// Only sections the declaration names are released; a bundle with no `sealed`
/// declaration releases every sealed section. A declaration whose release mode is not
/// `event_end` is refused, so a `manual` or `stage:<id>` release cannot be triggered
/// early by running the wrong command.
///
/// `seal_secret_key` is the hybrid KEM secret key of the `seal` recipient. Every
/// released plaintext is verified against its section root before it is returned
/// ([`Bundle::decrypt_section_bytes`]), so a wrong key fails rather than yielding
/// garbage.
pub fn release_at_event_end(bundle: &Bundle<'_>, seal_secret_key: &[u8]) -> Result<Release> {
    let declaration = sealed_declaration(bundle);
    let release = declaration
        .as_ref()
        .map(|d| d.release.clone())
        .unwrap_or_else(|| "all".to_owned());
    if let Some(d) = &declaration
        && d.release != "event_end"
    {
        return Err(Error::Inconsistent {
            what: "the bundle's sealed declaration is not an event-end release",
        });
    }
    let wanted: Option<Vec<String>> = declaration.and_then(|d| d.members);

    let mut members = Vec::new();
    let mut assets = Vec::new();
    for record in &bundle.sections {
        if !record.flags.contains(SectionFlags::SEALED) {
            continue;
        }
        let name = bundle
            .manifest
            .name_of(record.name_id)
            .unwrap_or_default()
            .to_owned();
        if let Some(wanted) = &wanted
            && !wanted.iter().any(|m| m == &name)
        {
            continue;
        }
        let content_key = bundle.section_content_key(record, seal_secret_key, "seal")?;
        let plaintext = bundle.decrypt_section_bytes(record, &content_key)?;
        let member = ReleasedMember {
            name_id: record.name_id,
            name,
            size: record.len_plain,
            root: hex(&record.root),
        };
        members.push(member.clone());
        assets.push(ReleasedAsset {
            member,
            bytes: plaintext,
        });
    }

    let report = ReleaseReport {
        bundle_root: hex(&bundle.footer.root),
        challenge_id: bundle.manifest.id().to_owned(),
        version: bundle.manifest.version(),
        release,
        members,
    };
    Ok(Release { report, assets })
}

/// Lowercase hex.
fn hex(bytes: &[u8; ROOT_LEN]) -> String {
    let mut out = String::with_capacity(ROOT_LEN * 2);
    for b in bytes {
        out.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
    }
    out
}
