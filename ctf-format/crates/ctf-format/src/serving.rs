//! The static artifact serving manifest (ticket 65).
//!
//! Normative: `spec/SPEC.md` §28. A platform serving a challenge's player-visible
//! artifacts needs each artifact's name, size, and BLAKE3 root so it can verify
//! bytes as it hands them out, without re-deriving the commitment or trusting a
//! client-supplied list. This module projects those three facts (plus the section's
//! path and, for an external payload, its mirrors) out of an already-parsed bundle.
//!
//! # The serving rule is two independent checks
//!
//! Only sections flagged `PLAYER_VISIBLE` appear, **and** a `SEALED` section never
//! does (design §10). The container already makes the pair unrepresentable (R5), so
//! the second check is belt and braces — but it is the check that matters if the
//! first is ever relaxed, and a serving manifest is exactly the artifact a leak
//! would flow through.
//!
//! # Bytes are not served before their root verifies
//!
//! The manifest carries the expected `root` so a fetcher can check a payload it
//! received out of band ([`ServedArtifact::verify`]), and [`serve`] returns inline
//! bytes only through [`Bundle::section_bytes`], which hashes them against the
//! section root first. There is no path here that returns unverified bytes.

use std::borrow::Cow;

use crate::bundle::Bundle;
use crate::cbor::Value;
use crate::{Error, Result, SectionFlags};

/// One player-visible artifact the platform may serve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServedArtifact {
    /// The section's cryptographic identity (spec §5.1).
    pub name_id: u16,
    /// The flat name from the manifest's name table.
    pub name: String,
    /// The relative extraction path, when the manifest declares one (§7.2).
    pub path: Option<String>,
    /// Plaintext size, the record's `len_plain`.
    pub size: u64,
    /// `BLAKE3` root of the plaintext, the record's `root`.
    pub root: [u8; 32],
    /// Whether the bytes live outside the bundle.
    pub external: bool,
    /// For an external artifact, where the payload can be fetched.
    pub mirrors: Vec<String>,
}

impl ServedArtifact {
    /// Verify a fetched payload against this artifact's `size` and `root`.
    ///
    /// Both are checked: BLAKE3 over a prefix is a perfectly good hash *of that
    /// prefix*, so a truncated payload is caught by the length check and by nothing
    /// else (spec §9.4).
    pub fn verify(&self, bytes: &[u8]) -> bool {
        bytes.len() as u64 == self.size && blake3::hash(bytes).as_bytes() == &self.root
    }

    /// The artifact as a canonical-CBOR map.
    fn to_cbor(&self) -> Value {
        let mut entries = vec![
            (
                Value::Text("name_id".into()),
                Value::Uint(u64::from(self.name_id)),
            ),
            (Value::Text("name".into()), Value::Text(self.name.clone())),
            (Value::Text("size".into()), Value::Uint(self.size)),
            (Value::Text("root".into()), Value::Bytes(self.root.to_vec())),
            (Value::Text("external".into()), Value::Bool(self.external)),
        ];
        if let Some(path) = &self.path {
            entries.push((Value::Text("path".into()), Value::Text(path.clone())));
        }
        if !self.mirrors.is_empty() {
            entries.push((
                Value::Text("mirrors".into()),
                Value::Array(
                    self.mirrors
                        .iter()
                        .map(|m| Value::Text(m.clone()))
                        .collect(),
                ),
            ));
        }
        Value::Map(entries)
    }
}

/// Everything a platform needs to serve a bundle's player-visible artifacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServingManifest {
    /// The manifest `id`.
    pub challenge_id: String,
    /// The manifest `version`.
    pub version: u64,
    /// The player-visible, non-sealed artifacts, in section-table order.
    pub artifacts: Vec<ServedArtifact>,
}

impl ServingManifest {
    /// Project a parsed bundle's serving surface.
    pub fn from_bundle(bundle: &Bundle<'_>) -> Self {
        let artifacts = bundle
            .sections
            .iter()
            .filter(|r| r.flags.contains(SectionFlags::PLAYER_VISIBLE) && !r.flags.sealed())
            .map(|r| {
                let external = r.flags.contains(SectionFlags::EXTERNAL);
                ServedArtifact {
                    name_id: r.name_id,
                    name: bundle
                        .manifest
                        .name_of(r.name_id)
                        .unwrap_or_default()
                        .to_owned(),
                    path: bundle.manifest.path_of(r.name_id).map(str::to_owned),
                    size: r.len_plain,
                    root: r.root,
                    external,
                    mirrors: if external {
                        bundle
                            .manifest
                            .external(r.name_id)
                            .map(|e| e.mirrors.iter().map(|m| (*m).to_owned()).collect())
                            .unwrap_or_default()
                    } else {
                        Vec::new()
                    },
                }
            })
            .collect();
        Self {
            challenge_id: bundle.manifest.id().to_owned(),
            version: bundle.manifest.version(),
            artifacts,
        }
    }

    /// The serving manifest as a canonical-CBOR value.
    pub fn to_cbor(&self) -> Value {
        Value::Map(vec![
            (
                Value::Text("challenge_id".into()),
                Value::Text(self.challenge_id.clone()),
            ),
            (Value::Text("version".into()), Value::Uint(self.version)),
            (
                Value::Text("artifacts".into()),
                Value::Array(self.artifacts.iter().map(ServedArtifact::to_cbor).collect()),
            ),
        ])
    }

    /// The canonical-CBOR encoding of [`ServingManifest::to_cbor`].
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.to_cbor().encode()
    }

    /// The artifact with this `name_id`, if it is servable.
    pub fn artifact(&self, name_id: u16) -> Option<&ServedArtifact> {
        self.artifacts.iter().find(|a| a.name_id == name_id)
    }
}

/// Return a servable section's inline plaintext, verified against its root.
///
/// Refuses a section that is not player-visible, is sealed, or is external — an
/// external payload's bytes are not in the file and are fetched and checked with
/// [`ServedArtifact::verify`] instead. The bytes come back through
/// [`Bundle::section_bytes`], so they are hashed against the section root before
/// the caller sees them (spec §10).
pub fn serve<'a>(bundle: &Bundle<'a>, name_id: u16) -> Result<Cow<'a, [u8]>> {
    let record = bundle.section(name_id).ok_or(Error::Inconsistent {
        what: "no section with that name_id",
    })?;
    if !record.flags.contains(SectionFlags::PLAYER_VISIBLE) {
        return Err(Error::Inconsistent {
            what: "section is not player-visible",
        });
    }
    if record.flags.sealed() {
        return Err(Error::Inconsistent {
            what: "a SEALED section is never served",
        });
    }
    if record.flags.contains(SectionFlags::EXTERNAL) {
        return Err(Error::Inconsistent {
            what: "an EXTERNAL section's bytes are not in the file",
        });
    }
    bundle.section_bytes(record)
}
