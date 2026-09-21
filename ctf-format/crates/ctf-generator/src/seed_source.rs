//! Seed and flag injection (spec §26, ticket 62).
//!
//! The platform starts a challenge container with the **per-subject seed** and the
//! **derived flag** injected, so a generator-based challenge starts reproducibly
//! inside the platform. This module is the documented mechanism: the environment
//! variables and mount paths, and the rule that a container with no injected value
//! fails rather than guessing.
//!
//! | Value | Environment | Mount |
//! |---|---|---|
//! | 32-byte seed, lowercase hex | `CTF_SEED` | `/ctf/seed` |
//! | derived flag (text) | `CTF_FLAG` | `/ctf/flag` |
//! | generated artifact directory | — | `/ctf/data` |
//!
//! The seed is the generator's only input (`ctf_generate(seed)`, spec §23.2); the
//! host reads it here and writes it into guest memory. The flag is what the
//! challenge service compares a player's submission to; the generator computes it
//! too, and [`crate::seed_source::check_flag`] refuses a mismatch so a challenge
//! whose generator disagrees with the platform's oracle cannot start.

use std::path::{Path, PathBuf};

/// Environment variable carrying the 32-byte seed as 64 lowercase hex digits.
pub const SEED_ENV: &str = "CTF_SEED";
/// Environment variable carrying the derived flag text.
pub const FLAG_ENV: &str = "CTF_FLAG";
/// Mount path of the seed file (raw 32 bytes, or 64 hex digits).
pub const SEED_PATH: &str = "/ctf/seed";
/// Mount path of the flag file (flag text).
pub const FLAG_PATH: &str = "/ctf/flag";
/// Mount path of the generated artifact directory.
pub const DATA_PATH: &str = "/ctf/data";

/// Why a seed or flag could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeedError {
    /// No seed was injected. A container MUST fail rather than guess one.
    Missing,
    /// The injected value was not the expected shape.
    BadValue(&'static str),
    /// A filesystem read failed.
    Io(String),
}

impl core::fmt::Display for SeedError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Missing => f.write_str("no seed was injected (spec §26)"),
            Self::BadValue(what) => write!(f, "injected seed is malformed: {what}"),
            Self::Io(e) => write!(f, "could not read the injected seed: {e}"),
        }
    }
}

impl core::error::Error for SeedError {}

/// The seed from `CTF_SEED`, as 64 lowercase hex digits.
pub fn seed_from_env() -> Result<[u8; 32], SeedError> {
    let value = std::env::var(SEED_ENV).map_err(|_| SeedError::Missing)?;
    parse_seed(value.trim())
}

/// The seed from a file: either 32 raw bytes, or 64 hex digits.
pub fn seed_from_file(path: &Path) -> Result<[u8; 32], SeedError> {
    let bytes = std::fs::read(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            SeedError::Missing
        } else {
            SeedError::Io(e.to_string())
        }
    })?;
    if bytes.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        return Ok(out);
    }
    let text = core::str::from_utf8(&bytes).map_err(|_| SeedError::BadValue("not UTF-8"))?;
    parse_seed(text.trim())
}

/// Resolve the seed from the environment, falling back to `SEED_PATH`.
///
/// The environment wins so a container orchestrator can inject without a mount;
/// the file is the documented fallback. Absent both, this is [`SeedError::Missing`]
/// — never a default seed.
pub fn resolve_seed() -> Result<[u8; 32], SeedError> {
    match seed_from_env() {
        Ok(seed) => Ok(seed),
        Err(SeedError::Missing) => seed_from_file(Path::new(SEED_PATH)),
        Err(e) => Err(e),
    }
}

/// The derived flag from `CTF_FLAG`, falling back to `FLAG_PATH`.
pub fn resolve_flag() -> Result<String, SeedError> {
    if let Ok(flag) = std::env::var(FLAG_ENV) {
        return Ok(flag);
    }
    match std::fs::read_to_string(FLAG_PATH) {
        Ok(flag) => Ok(flag.trim_end_matches(['\n', '\r']).to_owned()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(SeedError::Io(e.to_string())),
    }
}

/// Refuse a generator whose flag disagrees with the injected flag.
///
/// A challenge whose generator and platform oracle disagree would hand out
/// artifacts that do not solve; failing at start is better than failing for the
/// first player. An empty injected flag means none was provided, so nothing is
/// checked.
pub fn check_flag(generated: &str, injected: &str) -> Result<(), SeedError> {
    if injected.is_empty() || generated == injected {
        Ok(())
    } else {
        Err(SeedError::BadValue(
            "the generator's flag does not match the injected CTF_FLAG",
        ))
    }
}

/// Parse 64 lowercase hex digits into 32 bytes.
pub fn parse_seed(text: &str) -> Result<[u8; 32], SeedError> {
    if text.len() != 64 {
        return Err(SeedError::BadValue("expected 64 hex digits"));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = nibble(text.as_bytes().get(i * 2).copied())?;
        let lo = nibble(text.as_bytes().get(i * 2 + 1).copied())?;
        *byte = (hi << 4) | lo;
    }
    Ok(out)
}

fn nibble(c: Option<u8>) -> Result<u8, SeedError> {
    match c {
        Some(d @ b'0'..=b'9') => Ok(d - b'0'),
        Some(d @ b'a'..=b'f') => Ok(d - b'a' + 10),
        _ => Err(SeedError::BadValue("expected lowercase hex")),
    }
}

/// The default artifact directory, exposed so a caller need not hard-code it.
pub fn data_path() -> PathBuf {
    PathBuf::from(DATA_PATH)
}
