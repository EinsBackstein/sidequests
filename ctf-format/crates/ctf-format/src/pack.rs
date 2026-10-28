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
//! manifest is always `name_id` 0), then the author's inline `artifacts` in
//! declaration order, the generator module, its declared outputs in declaration
//! order, the sealed members, the solver, and finally the `external` entries. A
//! name repeated across those places is assigned once, at its first occurrence.
//! Every name passes `check_name`, so a path-shaped or control-character name is
//! refused here — at authoring time, with the offending key named — rather than by
//! the manifest decoder with no context.
//!
//! # External payloads are declared, never read
//!
//! An `external` entry compiles into one `artifact` section carrying the
//! `EXTERNAL` flag and a `Payload::External` record, plus an `external` manifest
//! entry keyed by that section's `name_id` (spec §5.7, §7.4). `pack` never opens a
//! file for one: the record's `root` and `len_plain` are the commitment, and the
//! mirrors in the manifest say where a player can fetch the bytes. The writer's own
//! parse-back then applies M20/M21, so a `size` or `root` that disagrees with the
//! record is refused before `pack` returns.
//!
//! # Paths, and why the key is omitted when it says nothing
//!
//! An `artifacts` entry may declare `path` (spec §7.2). `pack` compiles those into
//! the manifest's `paths` map, keyed by the section's `name_id`, and lists `paths`
//! in `crit` because a reader that ignores the tree would unpack the challenge
//! flat (§7.2 asks a writer that relies on the tree to do so). A path equal to the
//! section's flat name is *not* emitted: the fallback already places it there, so
//! an entry would be a second spelling of one fact. A document with no declared
//! path therefore has no `paths` key and packs byte-for-byte as it did before the
//! key existed.

use core::fmt;
use std::path::Path;

use crate::Error;
use crate::authoring::{ChallengeDoc, ValidationIssue};
use crate::bundle::{Payload, SectionSpec, write_bundle};
use crate::cbor::Value;
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
    key: String,
}

/// The names `pack` will assign, in `name_id` order, with their source keys.
fn name_sources(doc: &ChallengeDoc) -> Vec<NameSource> {
    let mut out: Vec<NameSource> = vec![NameSource {
        name: "manifest".to_owned(),
        key: "manifest".to_owned(),
    }];
    fn push(out: &mut Vec<NameSource>, name: &str, key: &str) {
        if !name.is_empty() && !out.iter().any(|s| s.name == name) {
            out.push(NameSource {
                name: name.to_owned(),
                key: key.to_owned(),
            });
        }
    }
    // Before the declarations: an inline artifact is a real section today, while a
    // generator output is only a reserved name. Putting artifacts first keeps
    // `name_id` assignment stable for documents that do not declare any.
    for (i, a) in doc.artifacts.iter().enumerate() {
        push(&mut out, &a.name, &format!("artifacts[{i}].name"));
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
    // External names go last so a document that declares none keeps the exact
    // `name_id` assignment — and therefore the byte-identical manifest — it had
    // before the key existed.
    for (i, external) in doc.external.iter().enumerate() {
        push(&mut out, &external.name, &format!("external[{i}].name"));
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
    let mut issues = doc.artifact_issues();
    issues.extend(doc.external_issues());
    for s in &sources {
        if let Some(reason) = check_name(&s.name) {
            issues.push(ValidationIssue::new(s.key.clone(), reason));
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

    let mut extra = doc.manifest_entries();
    let external = external_entries(doc, &names)?;
    if !external.is_empty() {
        // §7.4: `size` and `root` are copies for a fetcher; the record is
        // authoritative, and the writer's parse-back applies M21. Mirrors are the
        // only place a player learns where the payload lives.
        extra.push((
            text("external"),
            Value::Map(
                external
                    .into_iter()
                    .map(|entry| {
                        (
                            Value::Uint(u64::from(entry.name_id)),
                            Value::Map(vec![
                                (text("size"), Value::Uint(entry.size)),
                                (text("root"), Value::Bytes(entry.root.to_vec())),
                                (
                                    text("mirrors"),
                                    Value::Array(
                                        entry.mirrors.into_iter().map(Value::Text).collect(),
                                    ),
                                ),
                            ]),
                        )
                    })
                    .collect(),
            ),
        ));
    }
    let paths = path_entries(doc, &names)?;
    if !paths.is_empty() {
        extra.push((
            text("paths"),
            Value::Map(
                paths
                    .into_iter()
                    .map(|(name_id, path)| (Value::Uint(u64::from(name_id)), Value::Text(path)))
                    .collect(),
            ),
        ));
        // §7.2: a writer that relies on the tree SHOULD list `paths` in `crit`, so a
        // reader that would ignore it refuses the file instead of unpacking flat.
        extra.push((text("crit"), Value::Array(vec![text("paths")])));
    }

    Manifest::build(&doc.id, &doc.name, &names, extra).map_err(PackError::Format)
}

/// The `paths` entries a document declares, as `(name_id, path)`.
///
/// A path equal to the artifact's flat name is skipped: `names` already places the
/// section there, so the entry would carry no information and would change a
/// manifest only to restate it. The result is empty for a document that declares no
/// non-trivial path, which is what keeps existing bundles byte-identical.
fn path_entries(
    doc: &ChallengeDoc,
    names: &[&str],
) -> core::result::Result<Vec<(u16, String)>, PackError> {
    let mut out = Vec::new();
    for (i, artifact) in doc.artifacts.iter().enumerate() {
        let Some(path) = artifact.path.as_deref() else {
            continue;
        };
        if path == artifact.name {
            continue;
        }
        let name_id = names
            .iter()
            .position(|n| *n == artifact.name)
            .and_then(|index| u16::try_from(index).ok())
            .ok_or_else(|| {
                PackError::Invalid(vec![ValidationIssue::new(
                    format!("artifacts[{i}].name"),
                    "has no entry in the manifest name table",
                )])
            })?;
        out.push((name_id, path.to_owned()));
    }
    Ok(out)
}

/// One compiled `external` entry, bound to the section identity it will carry.
struct ExternalEntry {
    name_id: u16,
    size: u64,
    root: [u8; 32],
    mirrors: Vec<String>,
}

/// The `external` entries a document declares.
///
/// Empty when the document declares none, which is what keeps the manifest key —
/// and every byte of the bundle — absent for a document written before the key
/// existed. A collision is refused by [`ChallengeDoc::external_issues`] before this
/// runs, so failing to find a `name_id` here means the name table was built by
/// something other than [`names_for`].
fn external_entries(
    doc: &ChallengeDoc,
    names: &[&str],
) -> core::result::Result<Vec<ExternalEntry>, PackError> {
    let mut out = Vec::with_capacity(doc.external.len());
    for (i, external) in doc.external.iter().enumerate() {
        let name_id = names
            .iter()
            .position(|n| *n == external.name)
            .and_then(|index| u16::try_from(index).ok())
            .ok_or_else(|| {
                PackError::Invalid(vec![ValidationIssue::new(
                    format!("external[{i}].name"),
                    "has no entry in the manifest name table",
                )])
            })?;
        out.push(ExternalEntry {
            name_id,
            size: external.size,
            root: external.root,
            mirrors: external.mirrors.clone(),
        });
    }
    Ok(out)
}

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

/// Compile an authoring document into an unsigned bundle.
///
/// Refuses a document that fails validation ([`ChallengeDoc::validate`]) before a
/// byte is packed, and refuses a name that violates the manifest's shape rules,
/// naming the authoring key it came from. The writer parses its own output before
/// returning, so a bundle this function produces is one a conforming reader
/// accepts. A warning-severity issue (a third-party origin in the description) does
/// not block packing; [`ChallengeDoc::warnings`] reports it separately.
///
/// An artifact's `source` is resolved against the current directory. A caller that
/// has the authoring document's path — `ctf pack` does — should use
/// [`pack_with_root`] so a relative `source` means next to the document.
pub fn pack(doc: &ChallengeDoc) -> core::result::Result<Vec<u8>, PackError> {
    pack_with_suite(doc, DEFAULT_SUITE_ID)
}

/// [`pack`] with an explicit `suite_id`.
pub fn pack_with_suite(
    doc: &ChallengeDoc,
    suite_id: u16,
) -> core::result::Result<Vec<u8>, PackError> {
    pack_with_root(doc, suite_id, Path::new("."))
}

/// [`pack_with_suite`], resolving relative artifact `source` paths against `root`.
///
/// `root` is the directory holding the authoring document, so `source: assets/main.c`
/// names a file beside it rather than one beside the operator's shell. An absolute
/// `source` is used as written.
pub fn pack_with_root(
    doc: &ChallengeDoc,
    suite_id: u16,
    root: &Path,
) -> core::result::Result<Vec<u8>, PackError> {
    pack_with_descriptor_root(doc, suite_id, root).map(|(bytes, _)| bytes)
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
    pack_with_descriptor_root(doc, suite_id, Path::new("."))
}

/// [`pack_with_descriptor`], resolving relative artifact `source` paths against
/// `root`. See [`pack_with_root`].
pub fn pack_with_descriptor_root(
    doc: &ChallengeDoc,
    suite_id: u16,
    root: &Path,
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

    // Read every payload before writing a byte, so a missing file is a clean
    // authoring error naming the key rather than a half-written `--out`.
    let mut payloads: Vec<Vec<u8>> = Vec::with_capacity(doc.artifacts.len());
    let mut read_issues = Vec::new();
    for (i, artifact) in doc.artifacts.iter().enumerate() {
        let source = root.join(&artifact.source);
        match std::fs::read(&source) {
            Ok(bytes) => payloads.push(bytes),
            Err(e) => read_issues.push(ValidationIssue::new(
                format!("artifacts[{i}].source"),
                format!("could not read `{}`: {e}", artifact.source),
            )),
        }
    }
    if !read_issues.is_empty() {
        return Err(PackError::Invalid(read_issues));
    }

    let bytes = manifest.encode().map_err(PackError::Format)?;
    let mut sections = Vec::with_capacity(1 + payloads.len());
    sections.push(SectionSpec::inline(
        SectionKind::Manifest,
        0,
        SectionFlags::empty(),
        &bytes,
    ));
    let names = manifest.names();
    for (artifact, payload) in doc.artifacts.iter().zip(&payloads) {
        let name_id = names
            .iter()
            .position(|n| *n == artifact.name)
            .and_then(|index| u16::try_from(index).ok())
            .ok_or(PackError::Format(Error::Inconsistent {
                what: "an artifact has no name-table entry after a successful manifest build",
            }))?;
        // A static artifact is material for the player, so it is player-visible.
        // `validate` refuses sealing one, because that is the R5 contradiction.
        sections.push(SectionSpec::inline(
            SectionKind::Artifact,
            name_id,
            SectionFlags(SectionFlags::PLAYER_VISIBLE),
            payload,
        ));
    }
    // External payloads are declared, never read: no `std::fs` call belongs in this
    // loop. The record commits to the author's `root`/`size`, the manifest carries
    // the mirrors, and the payload stays wherever the author hosts it (design §2).
    for (i, external) in doc.external.iter().enumerate() {
        let name_id = names
            .iter()
            .position(|n| *n == external.name)
            .and_then(|index| u16::try_from(index).ok())
            .ok_or_else(|| {
                PackError::Invalid(vec![ValidationIssue::new(
                    format!("external[{i}].name"),
                    "has no entry in the manifest name table",
                )])
            })?;
        sections.push(SectionSpec {
            kind: SectionKind::Artifact,
            name_id,
            // The bytes are for the player, served from a mirror; `EXTERNAL` says
            // they are not in this file (spec §5.3, §5.7).
            flags: SectionFlags(SectionFlags::EXTERNAL | SectionFlags::PLAYER_VISIBLE),
            chunk_size: 0,
            // R22: an EXTERNAL record carries no codec. `size` is already the
            // plaintext length the author declared.
            comp: crate::Compression::None,
            payload: Payload::External {
                len_plain: external.size,
                root: external.root,
            },
            chunk_index: None,
            encryption: None,
        });
    }
    let file = write_bundle(suite_id, &sections).map_err(PackError::Format)?;
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
