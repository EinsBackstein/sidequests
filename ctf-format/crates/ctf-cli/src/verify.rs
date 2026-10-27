//! `ctf verify`: one stable, machine-readable ingest verification artifact
//! (ticket 64, spec §25.6.1).
//!
//! The command answers two questions separately, because conflating them is how a
//! tool reports success it did not earn:
//!
//! 1. **Is the bundle intact?** `Bundle::parse` (§10 steps 1–8) plus
//!    `verify_inline_sections` (§5, §9.4). A parse error or a root mismatch is a
//!    rejection. A section whose bytes are present but which this build cannot read
//!    — an encrypted section, with no key as an input — is counted in
//!    `sections.unverifiable` and disclosed, never silently counted as verified.
//!    An `EXTERNAL` section's bytes are absent by design and are reported, never
//!    rejected.
//! 2. **Did the offline gate pass?** Only when the caller supplies the authoring
//!    document and the event secret, so the §25.5 gate can run. `passed` requires
//!    both answers: intact *and* gate `passed`.
//!
//! # What this artifact does not say
//!
//! It never says a bundle is authentic. `signing` is `unsigned` or `present`, and
//! `present` means present — the signatures were not verified, because no trusted
//! key is an input to this command (§8.2, §34, §10 step 9). Intact is not
//! authentic, and an artifact that blurred the two would be worse than no artifact.
//!
//! # Why the JSON is hand-written
//!
//! The key order is part of the artifact's stability contract: the same bundle
//! bytes and the same inputs must produce byte-identical JSON, so a job can gate on
//! a digest of the artifact. No timestamps, no paths, no flag values, and no secret
//! appear here. A fixed writer is what makes that order explicit rather than a
//! property of a serializer's current version.

use ctf_format::Signing;
use ctf_generator::{GateStatus, VerificationRecord};

/// The artifact's schema id.
pub const SCHEMA: &str = "ctf/ingest-verification/v1";

/// The whole-file digest algorithm. Named in the artifact so a consumer never has
/// to guess what a bare hex string means.
pub const DIGEST_ALGORITHM: &str = "blake3";

/// The overall ingest verdict. Exactly one of four.
///
/// `Rejected` and `Failed` are failures; `Unverified` is honest incompleteness, not
/// success. Only `Passed` may exit 0 (spec §25.6.1, §25.7 S8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Intact, and the offline gate recovered the derived flag.
    Passed,
    /// Intact, but the gate ran and failed (or could not complete a stage).
    Failed,
    /// Intact, but no gate was requested or the gate is `unverified`.
    Unverified,
    /// The commitment or integrity checks failed: the bytes are not this bundle.
    Rejected,
}

impl Status {
    /// The artifact's spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Unverified => "unverified",
            Self::Rejected => "rejected",
        }
    }

    /// The process exit code for this verdict.
    ///
    /// `1` is this CLI's general failure code, so a rejected or failed bundle is
    /// indistinguishable from a usage error to a caller that only checks zero.
    /// `2` keeps its existing meaning — intact, but not a pass — so a script that
    /// already branches on 2 for `inspect --verify`'s unsigned case keeps working.
    pub fn exit_code(self) -> u8 {
        match self {
            Self::Passed => 0,
            Self::Failed | Self::Rejected => 1,
            Self::Unverified => 2,
        }
    }
}

/// What the section pass established (spec §10 step 4 and §9.4).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SectionCounts {
    /// Inline sections hashed and matched against their `root`.
    pub verified: usize,
    /// `EXTERNAL` sections, whose bytes are elsewhere by design.
    pub external: usize,
    /// Inline sections whose bytes are present and which this build cannot check.
    ///
    /// Disclosed, never a rejection on its own: an encrypted section's plaintext
    /// cannot be hashed without a key, which is not an input to this command. A
    /// consumer that requires every inline byte checked must also require this
    /// count to be zero (spec §25.6.1).
    pub unverifiable: usize,
    /// Sections carrying a chunk index. C1–C7 are on-use rules (§10), so this pass
    /// does not evaluate them; the count discloses how many were outside it.
    pub chunk_indices: usize,
    /// `name_id` of every inline section whose plaintext did not hash to its root.
    pub mismatches: Vec<u16>,
}

/// One ingest verification result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    /// BLAKE3 of the whole bundle file, lowercase hex.
    pub bundle_digest: String,
    /// The bundle file's length in bytes.
    pub bundle_size: u64,
    /// The footer's commitment root (§8.3), when the file parsed far enough to
    /// carry one.
    pub commitment_root: Option<[u8; 32]>,
    /// Whether the commitment and inline-section checks passed.
    pub intact: bool,
    /// The section pass's counts.
    pub sections: SectionCounts,
    /// `None` when the bundle did not parse, so this build cannot say.
    pub signing: Option<Signing>,
    /// The §25.6 verification record, or `None` when the gate did not run: no gate
    /// was requested, or the bundle was rejected before the gate could run.
    pub gate: Option<VerificationRecord>,
    /// The overall verdict.
    pub status: Status,
    /// A deterministic sentence naming the outcome.
    pub reason: String,
}

impl Artifact {
    /// An artifact for a file that has not been checked yet.
    pub fn new(bundle_digest: String, bundle_size: u64) -> Self {
        Self {
            bundle_digest,
            bundle_size,
            commitment_root: None,
            intact: false,
            sections: SectionCounts::default(),
            signing: None,
            gate: None,
            status: Status::Unverified,
            reason: String::new(),
        }
    }

    /// Mark the artifact rejected, keeping whatever was learned before the failure.
    pub fn reject(&mut self, reason: String) {
        self.intact = false;
        self.status = Status::Rejected;
        self.reason = reason;
    }

    /// Serialize as the `ctf/ingest-verification/v1` artifact.
    ///
    /// Key order is fixed and there is nothing time-, path-, or run-dependent, so
    /// the same inputs produce the same bytes on every machine.
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        out.push_str("{\n");
        out.push_str(&format!("  \"schema\": \"{SCHEMA}\",\n"));
        out.push_str(&format!(
            "  \"bundle_digest_algorithm\": \"{DIGEST_ALGORITHM}\",\n"
        ));
        out.push_str(&format!(
            "  \"bundle_digest\": \"{}\",\n",
            self.bundle_digest
        ));
        out.push_str(&format!("  \"bundle_size\": {},\n", self.bundle_size));
        out.push_str(&format!(
            "  \"commitment_root\": {},\n",
            optional_hex(self.commitment_root.as_ref())
        ));
        out.push_str(&format!("  \"intact\": {},\n", self.intact));
        out.push_str("  \"sections\": {\n");
        out.push_str(&format!("    \"verified\": {},\n", self.sections.verified));
        out.push_str(&format!("    \"external\": {},\n", self.sections.external));
        out.push_str(&format!(
            "    \"unverifiable\": {},\n",
            self.sections.unverifiable
        ));
        out.push_str(&format!(
            "    \"chunk_indices\": {},\n",
            self.sections.chunk_indices
        ));
        out.push_str(&format!(
            "    \"mismatches\": [{}]\n",
            self.sections
                .mismatches
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ));
        out.push_str("  },\n");
        out.push_str(&format!(
            "  \"signing\": {},\n",
            self.signing.map_or_else(
                || "null".to_owned(),
                |s| format!(
                    "\"{}\"",
                    match s {
                        Signing::Unsigned => "unsigned",
                        Signing::Present => "present",
                    }
                )
            )
        ));
        out.push_str("  \"gate\": ");
        match &self.gate {
            None => out.push_str("null,\n"),
            Some(record) => {
                out.push('\n');
                out.push_str(&record_json(record));
                out.push_str(",\n");
            }
        }
        out.push_str(&format!("  \"status\": \"{}\",\n", self.status.as_str()));
        out.push_str(&format!("  \"reason\": {}\n", json_string(&self.reason)));
        out.push_str("}\n");
        out
    }
}

/// Map the gate's tri-state onto the artifact's four states.
impl From<GateStatus> for Status {
    fn from(status: GateStatus) -> Self {
        match status {
            GateStatus::Passed => Self::Passed,
            GateStatus::Failed => Self::Failed,
            GateStatus::Unverified => Self::Unverified,
        }
    }
}

/// The §25.6 verification record as a nested object, indented for the `gate` key.
///
/// The record is the one `ctf run` persists, field for field, so the two commands
/// cannot disagree about what a gate result contains. The field order follows
/// [`VerificationRecord::to_json`].
fn record_json(record: &VerificationRecord) -> String {
    let root = optional_hex(record.generator_root.as_ref());
    let cross = record
        .cross_engine
        .map_or_else(|| "null".to_owned(), |b| b.to_string());
    let runs = record
        .runs
        .map_or_else(|| "null".to_owned(), |n| n.to_string());
    format!(
        "    {{\n      \"schema\": \"ctf/verification/v1\",\n      \"challenge\": {},\n      \
         \"version\": {},\n      \"subject\": {},\n      \"status\": \"{}\",\n      \
         \"reason\": {},\n      \"generator_root\": {},\n      \"cross_engine\": {},\n      \
         \"runs\": {}\n    }}",
        json_string(&record.challenge),
        record.version,
        json_string(&record.subject),
        record.status,
        json_string(&record.reason),
        root,
        cross,
        runs,
    )
}

/// Lowercase hex, or the JSON literal `null`.
fn optional_hex(bytes: Option<&[u8; 32]>) -> String {
    bytes.map_or_else(|| "null".to_owned(), |b| format!("\"{}\"", hex(b)))
}

/// Lowercase hex. Local to this module so the artifact does not depend on a
/// formatting helper elsewhere.
fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// A JSON string literal, with control characters escaped so attacker-controlled
/// text from a manifest or an error message cannot break the artifact.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

    use super::*;

    fn sample() -> Artifact {
        let mut a = Artifact::new("aa".repeat(32), 4344);
        a.commitment_root = Some([0x11; 32]);
        a.intact = true;
        a.sections = SectionCounts {
            verified: 2,
            external: 1,
            unverifiable: 0,
            chunk_indices: 1,
            mismatches: vec![],
        };
        a.signing = Some(Signing::Unsigned);
        a.status = Status::Unverified;
        a.reason = "no gate requested".to_owned();
        a
    }

    #[test]
    fn the_artifact_is_stable_and_ordered() {
        let first = sample().to_json();
        let second = sample().to_json();
        assert_eq!(first, second, "same inputs must produce the same bytes");
        let schema = first.find("\"schema\"").expect("schema key");
        let digest = first.find("\"bundle_digest\"").expect("digest key");
        let status = first.find("\"status\"").expect("status key");
        assert!(
            schema < digest && digest < status,
            "fixed key order:\n{first}"
        );
        assert!(!first.contains("timestamp"), "{first}");
    }

    #[test]
    fn strings_with_quotes_and_newlines_stay_one_json_value() {
        let mut a = sample();
        a.reason = "a \"quoted\" reason\nwith a newline".to_owned();
        let json = a.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(
            parsed.get("reason").and_then(|v| v.as_str()),
            Some("a \"quoted\" reason\nwith a newline")
        );
    }

    #[test]
    fn statuses_carry_the_documented_exit_codes() {
        assert_eq!(Status::Passed.exit_code(), 0);
        assert_eq!(Status::Failed.exit_code(), 1);
        assert_eq!(Status::Rejected.exit_code(), 1);
        assert_eq!(Status::Unverified.exit_code(), 2);
    }

    #[test]
    fn an_unparsed_bundle_reports_nulls_not_guesses() {
        let mut a = Artifact::new("bb".repeat(32), 10);
        a.reject("the bundle did not parse".to_owned());
        let json = a.to_json();
        assert!(json.contains("\"commitment_root\": null"), "{json}");
        assert!(json.contains("\"signing\": null"), "{json}");
        assert!(json.contains("\"intact\": false"), "{json}");
        assert!(json.contains("\"status\": \"rejected\""), "{json}");
    }
}
