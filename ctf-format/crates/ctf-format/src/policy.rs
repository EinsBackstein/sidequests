//! Platform policy: rules the container does not own but a packer and an ingest
//! pipeline must enforce.
//!
//! Normative: `spec/SPEC.md` §7.6 (`runtime`), §7.7 (the `platform` overlay), and
//! §29 (the platform policy checks). These are deliberately **not** container
//! rules: §7.6 says a reader carries the declaration keys without acting on them,
//! so a `runtime` with a tag is still a readable bundle. The policy checks here are
//! what `ctf pack` runs at authoring time and what an ingest step runs at read
//! time, and they are exported so both call the same code rather than re-deriving
//! the rule.
//!
//! Two rules live here:
//!
//! - **Digest pinning** (ticket 61). A runtime image is a digest, never a tag, so
//!   the bytes the platform boots are the bytes the author signed. The image is an
//!   ordinary manifest key and is therefore inside the commitment root and the
//!   author's signature; this check is what keeps a tag — a mutable reference —
//!   from being committed to at all.
//! - **Third-party origins and the referrer policy** (ticket 68). A challenge
//!   frontend that loads an external asset sends the capability URL in its
//!   `Referer` header, handing a third party access. The format cannot rewrite a
//!   frontend, so the policy is: default to `no-referrer`, and warn at authoring
//!   time about any absolute URL in the description. A challenge that vendors its
//!   assets references them relatively and produces no warning.

use core::fmt;

use crate::cbor::Value;
use crate::manifest::Manifest;

/// The referrer policy a packed bundle defaults to (ticket 68).
///
/// `no-referrer` is the only value this version emits. It is a constant rather
/// than an authoring choice on purpose: a challenge author who wants a different
/// policy has to justify it, and the default cannot be forgotten.
pub const DEFAULT_REFERRER_POLICY: &str = "no-referrer";

/// The `runtime.image` field name, for diagnostics.
pub const RUNTIME_IMAGE_KEY: &str = "runtime.image";

/// Why an image reference is not digest-pinned (ticket 61).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageRefError {
    /// The reference is empty.
    Empty,
    /// There is no `@sha256:` digest at all — the reference is a bare name or a
    /// tag.
    MissingDigest,
    /// The name portion carries a tag (`repo:tag@sha256:…`). The tag is ignored by
    /// a digest-pinned pull, but the AC says a tag is rejected, and a tag next to a
    /// digest is a claim about two different images.
    Tagged,
    /// The digest is not `sha256:` followed by exactly 64 lowercase hex digits.
    BadDigest,
}

impl fmt::Display for ImageRefError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "image reference is empty",
            Self::MissingDigest => {
                "image reference is not digest-pinned: it must end with `@sha256:<64 hex>`"
            }
            Self::Tagged => {
                "image reference carries a tag; a digest-pinned image must not also name a tag"
            }
            Self::BadDigest => "image digest must be `sha256:` followed by 64 lowercase hex digits",
        })
    }
}

impl core::error::Error for ImageRefError {}

/// Check that `image` is a digest-pinned reference, e.g.
/// `ghcr.io/ctf/baby-rop@sha256:<64 hex>`.
///
/// A tag is rejected. This is the one place the rule is expressed, so `ctf pack`
/// (authoring time) and an ingest policy pass (read time) cannot drift.
pub fn check_image_ref(image: &str) -> Result<(), ImageRefError> {
    if image.is_empty() {
        return Err(ImageRefError::Empty);
    }
    let Some(at) = image.rfind('@') else {
        return Err(ImageRefError::MissingDigest);
    };
    let (name, digest) = image.split_at(at);
    let digest = digest.strip_prefix('@').unwrap_or(digest);
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err(ImageRefError::MissingDigest);
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ImageRefError::BadDigest);
    }
    if name.is_empty() {
        return Err(ImageRefError::Empty);
    }
    // A registry host may carry a port (`localhost:5000/foo`), so only the last
    // path segment is checked for a tag: that is the part a tag attaches to.
    let last_segment = name.rsplit('/').next().unwrap_or(name);
    if last_segment.contains(':') {
        return Err(ImageRefError::Tagged);
    }
    Ok(())
}

/// One policy finding, named by the manifest or authoring key it concerns.
///
/// The message is a sentence an author can act on, and the key is a dotted path so
/// a tool can point at the exact line. Unlike a container [`crate::Error`], a
/// policy issue is about author intent, not a hostile byte stream, so it may name
/// the key (spec §7.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyIssue {
    key: String,
    message: String,
}

impl PolicyIssue {
    /// Build an issue for `key`.
    pub fn new(key: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            message: message.into(),
        }
    }

    /// The dotted key the issue concerns.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// What is wrong with it.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for PolicyIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "`{}`: {}", self.key, self.message)
    }
}

impl core::error::Error for PolicyIssue {}

/// Distinct absolute `http(s)` origins referenced by free-form `text`.
///
/// A relative reference (`assets/logo.png`) yields nothing, which is what makes
/// "vendor your assets and the warning goes away" true rather than aspirational.
/// The scan is deliberately shallow — it is a warning, not a URL parser — and it
/// stops an origin at the first `/`, `?`, `#`, whitespace, or closing delimiter.
pub fn third_party_origins(text: &str) -> Vec<String> {
    let mut origins: Vec<String> = Vec::new();
    let bytes = text.as_bytes();
    let mut at = 0usize;
    while at < bytes.len() {
        let rest = &text[at..];
        let Some(rel) = find_scheme(rest) else {
            break;
        };
        let start = at + rel;
        let after_scheme = start
            + if rest[rel..].starts_with("https://") {
                "https://".len()
            } else {
                "http://".len()
            };
        let mut end = after_scheme;
        while let Some(&c) = bytes.get(end) {
            if c.is_ascii_whitespace()
                || matches!(
                    c,
                    b'/' | b'?' | b'#' | b')' | b'"' | b'\'' | b'>' | b']' | b'*'
                )
            {
                break;
            }
            end += 1;
        }
        if end > after_scheme {
            let origin = &text[start..end];
            if !origins.iter().any(|o| o == origin) {
                origins.push(origin.to_owned());
            }
        }
        at = end.max(start + 1);
    }
    origins
}

/// Byte offset of the next `http://` or `https://` in `s`.
fn find_scheme(s: &str) -> Option<usize> {
    let https = s.find("https://");
    let http = s.find("http://");
    match (https, http) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

/// The runtime image from a manifest, if the author declared one.
pub fn runtime_image(manifest: &Manifest) -> Option<&str> {
    manifest
        .declaration("runtime")
        .and_then(|r| r.get("image"))
        .and_then(Value::as_text)
}

/// Run every policy check a packed or ingested bundle must pass (tickets 61, 68).
///
/// Returns an empty vector when the manifest is acceptable. The caller decides
/// whether an issue blocks (a bad image digest does) or warns (a third-party
/// origin does); [`PolicyIssue`] does not carry a severity because the same issue
/// is a hard failure at authoring time and a warning at read time.
pub fn check_manifest(manifest: &Manifest) -> Vec<PolicyIssue> {
    let mut issues = Vec::new();
    if let Some(image) = runtime_image(manifest)
        && let Err(e) = check_image_ref(image)
    {
        issues.push(PolicyIssue::new(RUNTIME_IMAGE_KEY, e.to_string()));
    }
    if let Some(description) = manifest.description() {
        for origin in third_party_origins(description) {
            issues.push(PolicyIssue::new(
                "description",
                format!(
                    "references the third-party origin `{origin}`; a frontend that loads it can \
                     leak the capability URL in its Referer header. Vendor the asset, or rely on \
                     the default `{DEFAULT_REFERRER_POLICY}` policy and remove the absolute URL"
                ),
            ));
        }
    }
    issues
}
