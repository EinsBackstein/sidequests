//! `ctf pack`: compile an authoring document into a `.ctf` bundle.
//!
//! Normative: `spec/SPEC.md` §7 (the manifest the YAML compiles to) and design §10
//! (the authoring surface). This is ticket 35.
//!
//! # What this does, and what it deliberately does not
//!
//! It turns a validated [`ChallengeDoc`] into the required manifest keys, the
//! name table, and the declaration keys of §7.6, then writes a bundle with a single
//! manifest section. That is the minimum viable challenge — an OSINT challenge with
//! no artifacts — and the shape R6 is measured against.
//!
//! It does **not** run a generator, fetch external payloads, or encrypt anything:
//! those need phase 3 and 4. A challenge that declares `generate` packs with its
//! declaration intact and its output names reserved in the name table, ready for
//! the artifacts a later pass will add. The bundle is **unsigned**; signing is
//! [`crate::bundle::sign_bundle`].
//!
//! # The name table is synthesized, and its order is stable
//!
//! `names[name_id]` is a section's identity, so the order in which names are
//! assigned is format-relevant. `pack` assigns, in order: `manifest` first (so the
//! manifest is always `name_id` 0), then the generator module, its declared outputs
//! in declaration order, the sealed members, and the solver. A name repeated across
//! those places is assigned once, at its first occurrence. Every name passes
//! `check_name`, so a path-shaped or control-character name is refused here — at
//! authoring time, with the offending key named — rather than by the manifest
//! decoder with no context.

use core::fmt;

use crate::Error;
use crate::authoring::{ChallengeDoc, ValidationIssue};
use crate::bundle::{SectionSpec, write_bundle};
use crate::descriptor::PlatformDescriptor;
use crate::manifest::{Manifest, check_name};
use crate::policy::PolicyIssue;
use crate::section::{SectionFlags, SectionKind};

/// The suite a packed bundle declares when the caller does not choose one.
/// Suite 1 is the design's default (design §7).
pub const DEFAULT_SUITE_ID: u16 = 1;

/// Why a pack failed.
///
/// Authoring input is the author's own file, so unlike [`Error`] these diagnostics
/// may name the offending key (spec §7.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackError {
    /// The document failed schema or policy validation. The issues name the keys.
    Invalid(Vec<ValidationIssue>),
    /// The document packed, but the platform policy pass rejected the descriptor.
    /// These name the manifest keys the platform reads.
    Policy(Vec<PolicyIssue>),
    /// The document validated but could not be compiled into a bundle.
    Format(Error),
}

impl fmt::Display for PackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(issues) => {
                write!(f, "authoring document is invalid:")?;
                for issue in issues {
                    write!(f, "\n  {issue}")?;
                }
                Ok(())
            }
            Self::Policy(issues) => {
                write!(f, "the bundle fails the platform policy check:")?;
                for issue in issues {
                    write!(f, "\n  {issue}")?;
                }
                Ok(())
            }
            Self::Format(e) => write!(f, "{e}"),
        }
    }
}

impl core::error::Error for PackError {}

impl From<Error> for PackError {
    fn from(e: Error) -> Self {
        Self::Format(e)
    }
}

/// One name table entry and the authoring key it came from, so a shape error can
/// name that key.
struct NameSource {
    name: String,
    key: &'static str,
}

/// The names `pack` will assign, in `name_id` order, with their source keys.
fn name_sources(doc: &ChallengeDoc) -> Vec<NameSource> {
    let mut out: Vec<NameSource> = vec![NameSource {
        name: "manifest".to_owned(),
        key: "manifest",
    }];
    fn push(out: &mut Vec<NameSource>, name: &str, key: &'static str) {
        if !name.is_empty() && !out.iter().any(|s| s.name == name) {
            out.push(NameSource {
                name: name.to_owned(),
                key,
            });
        }
    }
    if let Some(g) = &doc.generate {
        if let Some(wasm) = &g.wasm {
            push(&mut out, wasm, "generate.wasm");
        }
        for o in &g.outputs {
            // `validate` already checks output names; the key is repeated here so a
            // name shared with another key is still reported once.
            push(&mut out, &o.name, "generate.outputs");
        }
    }
    if let Some(s) = &doc.sealed {
        for m in &s.members {
            push(&mut out, m, "sealed.members");
        }
    }
    if let Some(v) = &doc.verify {
        push(&mut out, &v.solver, "verify.solver");
    }
    out
}

/// The name table for a document, in `name_id` order.
///
/// Every entry has passed `check_name`; [`pack`] returns
/// [`PackError::Invalid`] naming the source key when one has not.
pub fn names_for(doc: &ChallengeDoc) -> Vec<String> {
    name_sources(doc).into_iter().map(|s| s.name).collect()
}

/// Build the manifest a document compiles to.
pub fn manifest_for(doc: &ChallengeDoc) -> core::result::Result<Manifest, PackError> {
    let sources = name_sources(doc);
    let mut issues = Vec::new();
    for s in &sources {
        if let Some(reason) = check_name(&s.name) {
            issues.push(ValidationIssue::new(s.key, reason));
        }
    }
    if !issues.is_empty() {
        return Err(PackError::Invalid(issues));
    }
    let names: Vec<&str> = sources.iter().map(|s| s.name.as_str()).collect();

    // The output-to-name-table mapping (spec §7.6, ticket 25). A generator output
    // becomes a section, and a section's identity is its `name_id` into `names`, so
    // an output with no name entry could never be addressed. `name_sources` already
    // reserves every output name; this check makes the invariant explicit rather
    // than incidental, so a future change to name assignment cannot silently drop
    // one.
    if let Some(g) = &doc.generate {
        for (i, output) in g.outputs.iter().enumerate() {
            if !names.contains(&output.name.as_str()) {
                issues.push(ValidationIssue::new(
                    format!("generate.outputs[{i}].name"),
                    "has no entry in the manifest name table",
                ));
            }
        }
    }
    if !issues.is_empty() {
        return Err(PackError::Invalid(issues));
    }

    Manifest::build(&doc.id, &doc.name, &names, doc.manifest_entries()).map_err(PackError::Format)
}

/// Compile an authoring document into an unsigned bundle.
///
/// Refuses a document that fails validation ([`ChallengeDoc::validate`]) before a
/// byte is packed, and refuses a name that violates the manifest's shape rules,
/// naming the authoring key it came from. The writer parses its own output before
/// returning, so a bundle this function produces is one a conforming reader
/// accepts. A warning-severity issue (a third-party origin in the description) does
/// not block packing; [`ChallengeDoc::warnings`] reports it separately.
pub fn pack(doc: &ChallengeDoc) -> core::result::Result<Vec<u8>, PackError> {
    pack_with_suite(doc, DEFAULT_SUITE_ID)
}

/// [`pack`] with an explicit `suite_id`.
pub fn pack_with_suite(
    doc: &ChallengeDoc,
    suite_id: u16,
) -> core::result::Result<Vec<u8>, PackError> {
    pack_with_descriptor(doc, suite_id).map(|(bytes, _)| bytes)
}

/// [`pack`] returning the platform ingest descriptor alongside the bundle (ticket 60).
///
/// The descriptor is projected from the manifest that was just packed, so it cannot
/// disagree with the bundle's committed bytes. It is validated against the
/// platform's constraints before the bundle is returned, so a descriptor the
/// platform would reject fails the pack rather than surfacing at ingest.
pub fn pack_with_descriptor(
    doc: &ChallengeDoc,
    suite_id: u16,
) -> core::result::Result<(Vec<u8>, PlatformDescriptor), PackError> {
    let errors = doc.errors();
    if !errors.is_empty() {
        return Err(PackError::Invalid(errors));
    }
    let manifest = manifest_for(doc)?;
    let descriptor = PlatformDescriptor::from_manifest(&manifest, doc.platform_namespace());
    let issues = descriptor.validate();
    if !issues.is_empty() {
        return Err(PackError::Policy(issues));
    }
    let bytes = manifest.encode().map_err(PackError::Format)?;
    let section = SectionSpec::inline(SectionKind::Manifest, 0, SectionFlags::empty(), &bytes);
    let file = write_bundle(suite_id, &[section]).map_err(PackError::Format)?;
    Ok((file, descriptor))
}

/// The platform ingest descriptor for a document, without packing it (ticket 60).
pub fn descriptor_for(doc: &ChallengeDoc) -> core::result::Result<PlatformDescriptor, PackError> {
    let errors = doc.errors();
    if !errors.is_empty() {
        return Err(PackError::Invalid(errors));
    }
    let manifest = manifest_for(doc)?;
    let descriptor = PlatformDescriptor::from_manifest(&manifest, doc.platform_namespace());
    let issues = descriptor.validate();
    if !issues.is_empty() {
        return Err(PackError::Policy(issues));
    }
    Ok(descriptor)
}
