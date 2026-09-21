//! The platform ingest descriptor (ticket 60).
//!
//! Normative: `spec/SPEC.md` §29. A bundle is self-describing, but the platform's
//! challenge and runtime records are not the manifest's shape. `ctf pack` therefore
//! emits a descriptor alongside the bundle — a plain JSON object the ingest pipeline
//! can consume without hand-written statements — and the same function builds one
//! from any parsed manifest, so a reader does not have to re-derive it.
//!
//! The descriptor is **derived data**, never a second source of truth. Every field
//! comes from the manifest (which the commitment root and the author's signature
//! cover) or from the namespaced `platform` overlay (§7.7). A descriptor that
//! disagrees with the bundle is a bug in whatever produced it, which is why this
//! module only ever projects the manifest and never accepts a field from a caller.
//!
//! # Platform-owned fields
//!
//! `level`, `storage_size`, and `read_only` are not format concepts, so they travel
//! in the `platform` overlay under the platform's namespace (§7.7). The overlay is
//! opaque to the container; this module reads it only to project it into the
//! descriptor, and a bundle with no overlay simply leaves those fields absent.

use core::fmt;

use serde::Serialize;

use crate::cbor::Value;
use crate::manifest::Manifest;
use crate::policy::{self, PolicyIssue};

/// The reference platform's overlay namespace.
///
/// A namespace is a reversed domain naming its owner (spec §7.7). The descriptor
/// reader can be pointed at another namespace; this is the one `ctf pack` writes
/// and the one the reference platform reads.
pub const DEFAULT_PLATFORM_NAMESPACE: &str = "org.flagfrenzy";

/// Resource limits, projected from `runtime.resources` (spec §7.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Resources {
    /// CPU quota, e.g. `"0.5"`.
    pub cpu: String,
    /// Memory limit, e.g. `"256Mi"`.
    pub memory: String,
    /// PID limit.
    pub pids: u64,
}

/// The readiness probe, projected from `runtime.readiness` (spec §7.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Readiness {
    /// TCP port that must accept a connection.
    pub tcp: u16,
    /// Probe timeout, e.g. `"30s"`.
    pub timeout: String,
}

/// The platform's challenge and runtime record for one bundle.
///
/// Field names are the descriptor's own JSON names, chosen to read directly as the
/// platform's columns. Absent fields are omitted rather than emitted as `null`, so
/// a consumer can distinguish "the author declared nothing" from "the author
/// declared an empty value".
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlatformDescriptor {
    /// The manifest `id`; the platform's challenge key (spec §7.2).
    pub slug: String,
    /// The manifest `name`.
    pub name: String,
    /// The manifest `category`, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// The manifest `version`; `0` when never re-packed.
    pub version: u64,
    /// Track level, from the platform overlay.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<i64>,
    /// The digest-pinned runtime image, from `runtime.image`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// The first exposed container port, from `runtime.ports[0].container`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Resource limits, from `runtime.resources`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<Resources>,
    /// Forensics-scale payload size, from the platform overlay.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_size: Option<u64>,
    /// Whether the instance root filesystem is read-only, from the overlay.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,
    /// Instance lifetime, from `runtime.ttl`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
    /// The readiness probe, from `runtime.readiness`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readiness: Option<Readiness>,
    /// The referrer policy the platform serves the challenge under (ticket 68).
    /// Always [`policy::DEFAULT_REFERRER_POLICY`].
    pub referrer_policy: String,
}

impl PlatformDescriptor {
    /// Project a parsed manifest into the platform's record shape.
    ///
    /// Reads only the manifest and its overlay; never a caller-supplied field, so
    /// the descriptor cannot disagree with the committed bytes.
    pub fn from_manifest(manifest: &Manifest, namespace: &str) -> Self {
        let runtime = manifest.declaration("runtime");
        let overlay = manifest
            .value()
            .get("platform")
            .and_then(Value::as_map)
            .and_then(|entries| {
                entries
                    .iter()
                    .find(|(k, _)| k.as_text() == Some(namespace))
                    .map(|(_, v)| v)
            });

        Self {
            slug: manifest.id().to_owned(),
            name: manifest.name().to_owned(),
            category: manifest.category().map(str::to_owned),
            version: manifest.version(),
            level: overlay.and_then(|o| o.get("level")).and_then(value_as_i64),
            image: runtime
                .and_then(|r| r.get("image"))
                .and_then(Value::as_text)
                .map(str::to_owned),
            port: runtime
                .and_then(|r| r.get("ports"))
                .and_then(Value::as_array)
                .and_then(|ports| ports.first())
                .and_then(|p| p.get("container"))
                .and_then(Value::as_uint)
                .and_then(|n| u16::try_from(n).ok()),
            resources: runtime.and_then(resources_of),
            storage_size: overlay
                .and_then(|o| o.get("storage_size"))
                .and_then(Value::as_uint),
            read_only: overlay
                .and_then(|o| o.get("read_only"))
                .and_then(|v| match v {
                    Value::Bool(b) => Some(*b),
                    _ => None,
                }),
            ttl: runtime
                .and_then(|r| r.get("ttl"))
                .and_then(Value::as_text)
                .map(str::to_owned),
            readiness: runtime.and_then(readiness_of),
            referrer_policy: policy::DEFAULT_REFERRER_POLICY.to_owned(),
        }
    }

    /// Check the descriptor against the platform's constraints.
    ///
    /// These are the constraints the platform's columns impose: a slug in the
    /// challenge-id shape, a port in range, a non-negative level, non-empty
    /// resource and timeout strings. Returns an empty vector when the descriptor is
    /// acceptable.
    pub fn validate(&self) -> Vec<PolicyIssue> {
        let mut issues = Vec::new();
        if let Err(e) = crate::manifest::check_id(&self.slug) {
            issues.push(PolicyIssue::new("slug", e.to_string()));
        }
        if let Some(image) = &self.image
            && let Err(e) = policy::check_image_ref(image)
        {
            issues.push(PolicyIssue::new(policy::RUNTIME_IMAGE_KEY, e.to_string()));
        }
        if let Some(port) = self.port
            && port == 0
        {
            issues.push(PolicyIssue::new("port", "must be between 1 and 65535"));
        }
        if let Some(level) = self.level
            && level < 0
        {
            issues.push(PolicyIssue::new("level", "must not be negative"));
        }
        if let Some(resources) = &self.resources {
            if resources.cpu.is_empty() {
                issues.push(PolicyIssue::new("resources.cpu", "must not be empty"));
            }
            if resources.memory.is_empty() {
                issues.push(PolicyIssue::new("resources.memory", "must not be empty"));
            }
            if resources.pids == 0 {
                issues.push(PolicyIssue::new("resources.pids", "must be at least 1"));
            }
        }
        if let Some(ttl) = &self.ttl
            && ttl.is_empty()
        {
            issues.push(PolicyIssue::new("ttl", "must not be empty"));
        }
        if let Some(readiness) = &self.readiness {
            if readiness.tcp == 0 {
                issues.push(PolicyIssue::new(
                    "readiness.tcp",
                    "must be between 1 and 65535",
                ));
            }
            if readiness.timeout.is_empty() {
                issues.push(PolicyIssue::new("readiness.timeout", "must not be empty"));
            }
        }
        issues
    }

    /// Serialize as pretty JSON, the form the ingest pipeline consumes.
    pub fn to_json(&self) -> Result<String, DescriptorError> {
        serde_json::to_string_pretty(self).map_err(|e| DescriptorError::Json(e.to_string()))
    }
}

/// A descriptor could not be serialized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DescriptorError {
    /// The JSON serializer failed. In practice this cannot happen for this shape.
    Json(String),
}

impl fmt::Display for DescriptorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(e) => write!(f, "could not serialize the ingest descriptor: {e}"),
        }
    }
}

impl core::error::Error for DescriptorError {}

/// Read `runtime.resources` into the descriptor's shape.
fn resources_of(runtime: &Value) -> Option<Resources> {
    let r = runtime.get("resources")?;
    Some(Resources {
        cpu: r.get("cpu").and_then(Value::as_text)?.to_owned(),
        memory: r.get("memory").and_then(Value::as_text)?.to_owned(),
        pids: r.get("pids").and_then(Value::as_uint)?,
    })
}

/// Read `runtime.readiness` into the descriptor's shape.
fn readiness_of(runtime: &Value) -> Option<Readiness> {
    let r = runtime.get("readiness")?;
    Some(Readiness {
        tcp: u16::try_from(r.get("tcp").and_then(Value::as_uint)?).ok()?,
        timeout: r.get("timeout").and_then(Value::as_text)?.to_owned(),
    })
}

/// A CBOR integer as `i64`, if it fits.
fn value_as_i64(v: &Value) -> Option<i64> {
    match v {
        Value::Uint(n) => i64::try_from(*n).ok(),
        // CBOR major type 1: the value is `-1 - n`. Computed in `i128` so
        // `-1 - i64::MAX` (i64::MIN) does not overflow on the way.
        Value::Nint(n) => i64::try_from(-1i128 - i128::from(*n)).ok(),
        _ => None,
    }
}
