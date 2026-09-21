//! The bundle as an OCI artifact (ticket 63).
//!
//! Normative: `spec/SPEC.md` §30. A `.ctf` is a single file, and registries are how
//! the platform distributes immutable, replicated, content-addressed artifacts. This
//! module wraps a bundle as an **OCI image** — an OCI image layout (OCI Image Spec
//! v1.1) with the bundle as its single layer — so `oras`/`docker`/a registry client
//! can push and pull it without knowing anything about the format beyond the media
//! type.
//!
//! # What round-trips
//!
//! [`export`] writes a local OCI image layout and [`import`] reads the bundle back
//! **byte-for-byte**: the layer's blob is the bundle, unmodified, so the registry
//! digest (`sha256` of the bundle) is the bundle's identity. There is no
//! re-serialization step that could change a byte.
//!
//! # Why the digest is `sha256`
//!
//! OCI mandates `sha256` for content addresses, while the format's own commitment
//! is BLAKE3. The two are independent and both are checked: the registry proves the
//! bundle it delivered is the one that was pushed, and the bundle's own footer proves
//! its contents are the author's. The OCI digest is a transport address, never a
//! substitute for the commitment.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::json;

use crate::bundle::Bundle;

/// Media type of the bundle layer blob.
pub const BUNDLE_MEDIA_TYPE: &str = "application/vnd.ctf.bundle.v1";

/// Media type of the (empty) image config blob.
pub const CONFIG_MEDIA_TYPE: &str = "application/vnd.ctf.bundle.config.v1+json";

/// Media type of the OCI image manifest.
pub const IMAGE_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";

/// Media type of the OCI image index.
pub const INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";

/// The OCI image layout version this writer emits.
pub const LAYOUT_VERSION: &str = "1.0.0";

/// The filename of the layout marker.
pub const LAYOUT_MARKER: &str = "oci-layout";

/// Why an OCI export or import failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OciError {
    /// A filesystem operation failed.
    Io(String),
    /// The bytes are not a valid bundle, so no annotations can be derived.
    Format(crate::Error),
    /// A JSON document could not be written or read.
    Json(String),
    /// The directory is not an OCI image layout.
    NotALayout,
    /// The layout carries no layer with [`BUNDLE_MEDIA_TYPE`].
    NoBundleLayer,
}

impl core::fmt::Display for OciError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "oci layout i/o: {e}"),
            Self::Format(e) => write!(f, "{e}"),
            Self::Json(e) => write!(f, "oci layout json: {e}"),
            Self::NotALayout => f.write_str("directory is not an OCI image layout"),
            Self::NoBundleLayer => f.write_str("OCI layout has no .ctf bundle layer"),
        }
    }
}

impl core::error::Error for OciError {}

impl From<crate::Error> for OciError {
    fn from(e: crate::Error) -> Self {
        Self::Format(e)
    }
}

/// Where an exported layout was written and the digest of the bundle it carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciLayout {
    /// The layout directory.
    pub root: PathBuf,
    /// `sha256:<hex>` of the bundle bytes — the registry content address.
    pub bundle_digest: String,
    /// The digest of the generated image manifest.
    pub manifest_digest: String,
}

/// `sha256:<64 lowercase hex>` of `bytes`, the OCI content address.
pub fn digest_sha256(bytes: &[u8]) -> String {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes);
    format!("sha256:{}", hex(digest.as_ref()))
}

/// Export `bundle_bytes` as an OCI image layout rooted at `dir`.
///
/// Parses the bundle to annotate the manifest with the challenge id and version; a
/// bundle that does not parse is refused rather than wrapped, so a layout always
/// describes a real challenge.
pub fn export(bundle_bytes: &[u8], dir: &Path) -> Result<OciLayout, OciError> {
    let parsed = Bundle::parse(bundle_bytes)?;
    let title = parsed.manifest.id().to_owned();
    let version = parsed.manifest.version().to_string();

    let bundle_digest = digest_sha256(bundle_bytes);
    let config_bytes = b"{}";
    let config_digest = digest_sha256(config_bytes);

    let manifest = json!({
        "schemaVersion": 2,
        "mediaType": IMAGE_MANIFEST_MEDIA_TYPE,
        "config": {
            "mediaType": CONFIG_MEDIA_TYPE,
            "digest": config_digest,
            "size": config_bytes.len(),
        },
        "layers": [{
            "mediaType": BUNDLE_MEDIA_TYPE,
            "digest": bundle_digest,
            "size": bundle_bytes.len(),
            "annotations": { "org.opencontainers.image.title": title },
        }],
        "annotations": {
            "org.opencontainers.image.title": title,
            "org.opencontainers.image.version": version,
        },
    });
    let manifest_bytes =
        serde_json::to_vec_pretty(&manifest).map_err(|e| OciError::Json(e.to_string()))?;
    let manifest_digest = digest_sha256(&manifest_bytes);

    let index = json!({
        "schemaVersion": 2,
        "mediaType": INDEX_MEDIA_TYPE,
        "manifests": [{
            "mediaType": IMAGE_MANIFEST_MEDIA_TYPE,
            "digest": manifest_digest,
            "size": manifest_bytes.len(),
            "annotations": {
                "org.opencontainers.image.ref.name": format!("{title}:{version}"),
            },
        }],
    });
    let index_bytes =
        serde_json::to_vec_pretty(&index).map_err(|e| OciError::Json(e.to_string()))?;

    let blobs = dir.join("blobs").join("sha256");
    fs::create_dir_all(&blobs).map_err(io)?;
    fs::write(
        dir.join(LAYOUT_MARKER),
        format!("{{\"imageLayoutVersion\":\"{LAYOUT_VERSION}\"}}"),
    )
    .map_err(io)?;
    fs::write(dir.join("index.json"), &index_bytes).map_err(io)?;
    write_blob(&blobs, &bundle_digest, bundle_bytes)?;
    write_blob(&blobs, &config_digest, config_bytes)?;
    write_blob(&blobs, &manifest_digest, &manifest_bytes)?;

    Ok(OciLayout {
        root: dir.to_path_buf(),
        bundle_digest,
        manifest_digest,
    })
}

/// Read the bundle out of an OCI image layout.
///
/// Follows `index.json` → the first image manifest → the first layer with
/// [`BUNDLE_MEDIA_TYPE`], and returns that blob's bytes unchanged.
pub fn import(dir: &Path) -> Result<Vec<u8>, OciError> {
    if !dir.join(LAYOUT_MARKER).is_file() {
        return Err(OciError::NotALayout);
    }
    let index: serde_json::Value = read_json(&dir.join("index.json"))?;
    let manifests = index
        .get("manifests")
        .and_then(serde_json::Value::as_array)
        .ok_or(OciError::NotALayout)?;
    let manifest_digest = manifests
        .first()
        .and_then(|m| m.get("digest"))
        .and_then(serde_json::Value::as_str)
        .ok_or(OciError::NotALayout)?;
    let manifest: serde_json::Value = read_json(&blob_path(dir, manifest_digest)?)?;
    let layers = manifest
        .get("layers")
        .and_then(serde_json::Value::as_array)
        .ok_or(OciError::NoBundleLayer)?;
    let layer = layers
        .iter()
        .find(|l| l.get("mediaType").and_then(serde_json::Value::as_str) == Some(BUNDLE_MEDIA_TYPE))
        .ok_or(OciError::NoBundleLayer)?;
    let digest = layer
        .get("digest")
        .and_then(serde_json::Value::as_str)
        .ok_or(OciError::NoBundleLayer)?;
    let bytes = fs::read(blob_path(dir, digest)?).map_err(io)?;
    if digest_sha256(&bytes) != digest {
        return Err(OciError::Json(
            "bundle blob does not match its content address".to_owned(),
        ));
    }
    Ok(bytes)
}

/// The blob path for a `sha256:<hex>` digest.
fn blob_path(dir: &Path, digest: &str) -> Result<PathBuf, OciError> {
    let hex = digest.strip_prefix("sha256:").ok_or(OciError::NotALayout)?;
    Ok(dir.join("blobs").join("sha256").join(hex))
}

/// Write a blob, creating nothing (the caller created the directory).
fn write_blob(dir: &Path, digest: &str, bytes: &[u8]) -> Result<(), OciError> {
    let hex = digest.strip_prefix("sha256:").ok_or(OciError::NotALayout)?;
    fs::write(dir.join(hex), bytes).map_err(io)
}

/// Read and parse a JSON file.
fn read_json(path: &Path) -> Result<serde_json::Value, OciError> {
    let bytes = fs::read(path).map_err(io)?;
    serde_json::from_slice(&bytes).map_err(|e| OciError::Json(e.to_string()))
}

fn io(e: std::io::Error) -> OciError {
    OciError::Io(e.to_string())
}

/// Lowercase hex.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
    }
    out
}
