//! Row shapes and small pure helpers shared by the DB layer, the state machine,
//! and the renderer.
//!
//! Nothing here touches a database. `db.rs` produces these values, `ui.rs` reads
//! them, and `app.rs` only moves them around. That split is what lets the headless
//! renderer tests run without Postgres, and what keeps a column name from leaking
//! into a drawing routine.

use serde_json::Value;

/// The four ingest verdicts. `Rejected` is a parse or integrity failure; the other
/// three are the §25.6 tri-state, widened by the one verdict that has no bundle row
/// to attach to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Passed,
    Unverified,
    Failed,
    Rejected,
}

impl Status {
    /// The spelling stored in `verification.status` and shown in the TUI.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Unverified => "unverified",
            Self::Failed => "failed",
            Self::Rejected => "rejected",
        }
    }

    /// Parse a `verification.status` value. An unknown value is `None` rather than
    /// an invented state: a row this build cannot name is shown as its raw text by
    /// the caller, never silently treated as a pass.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "passed" => Some(Self::Passed),
            "unverified" => Some(Self::Unverified),
            "failed" => Some(Self::Failed),
            "rejected" => Some(Self::Rejected),
            _ => None,
        }
    }
}

impl From<ctf_generator::GateStatus> for Status {
    fn from(status: ctf_generator::GateStatus) -> Self {
        match status {
            ctf_generator::GateStatus::Passed => Self::Passed,
            ctf_generator::GateStatus::Failed => Self::Failed,
            ctf_generator::GateStatus::Unverified => Self::Unverified,
        }
    }
}

/// The four phases of an ingest, in the order they run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Validate,
    Verify,
    Gate,
    Store,
}

impl Stage {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Validate => "validate",
            Self::Verify => "verify",
            Self::Gate => "gate",
            Self::Store => "store",
        }
    }

    /// Every stage, for a static four-step header.
    pub const ALL: [Self; 4] = [Self::Validate, Self::Verify, Self::Gate, Self::Store];
}

/// One progress observation from the ingest pipeline.
///
/// `done` and `total` are in the stage's own units — sections for validation and
/// storing, chunks for verification. `total == 0` is rendered as an empty bar
/// rather than a full one; see [`Progress::fraction`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Progress {
    pub stage: Stage,
    pub done: u64,
    pub total: u64,
    pub label: String,
}

impl Progress {
    /// The bar's ratio, clamped to `0.0..=1.0`. A zero total is 0.0: "nothing was
    /// asked for" must not draw as a finished bar.
    pub fn fraction(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        let ratio = self.done as f64 / self.total as f64;
        ratio.clamp(0.0, 1.0)
    }

    /// `done/total` with the stage name, the gauge's own label.
    pub fn text(&self) -> String {
        format!("{} {}/{}", self.stage.label(), self.done, self.total)
    }
}

/// One challenge row, with the aggregate the challenge list needs.
#[derive(Debug, Clone, PartialEq)]
pub struct ChallengeRow {
    pub id: i64,
    pub slug: String,
    pub version: i64,
    pub name: String,
    pub category: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub bundle_count: i64,
    pub latest_status: Option<Status>,
    pub latest_at: Option<String>,
}

/// One stored bundle.
#[derive(Debug, Clone, PartialEq)]
pub struct BundleRow {
    pub id: i64,
    pub challenge_id: i64,
    pub total_len: i64,
    pub sha256: Vec<u8>,
    pub commitment_root: Vec<u8>,
    pub suite_id: i32,
    pub ingested_at: String,
    pub source_path: Option<String>,
}

/// One section record, as the inspector renders it.
#[derive(Debug, Clone, PartialEq)]
pub struct SectionRow {
    pub id: i64,
    pub bundle_id: i64,
    pub name_id: i32,
    pub name: String,
    pub kind: i32,
    pub flags: i32,
    pub comp: i32,
    pub enc: i32,
    pub len_plain: i64,
    pub len_stored: i64,
    pub offset: i64,
    pub root: Vec<u8>,
    pub chunk_size: i64,
    pub chunk_index_off: i64,
    pub player_visible: bool,
    pub sealed: bool,
    pub external: bool,
}

impl SectionRow {
    /// The kind's name, or `unknown(<n>)` for a future kind. The number is data
    /// from the file, so it is formatted rather than looked up.
    pub fn kind_name(&self) -> String {
        match self.kind {
            1 => "manifest".to_owned(),
            2 => "artifact".to_owned(),
            3 => "generator".to_owned(),
            4 => "solver".to_owned(),
            5 => "writeup".to_owned(),
            6 => "entitlement".to_owned(),
            7 => "keys".to_owned(),
            8 => "progress".to_owned(),
            other => format!("unknown({other})"),
        }
    }

    /// The flag names this build knows, space-separated, or `-` for none.
    pub fn flag_names(&self) -> String {
        let bits = u16::try_from(self.flags).unwrap_or(u16::MAX);
        let mut names = Vec::new();
        if bits & ctf_format::SectionFlags::SEALED != 0 {
            names.push("SEALED");
        }
        if bits & ctf_format::SectionFlags::PLAYER_VISIBLE != 0 {
            names.push("PLAYER_VISIBLE");
        }
        if bits & ctf_format::SectionFlags::EXTERNAL != 0 {
            names.push("EXTERNAL");
        }
        if bits & ctf_format::SectionFlags::OPTIONAL != 0 {
            names.push("OPTIONAL");
        }
        if names.is_empty() {
            "-".to_owned()
        } else {
            names.join("|")
        }
    }

    pub fn comp_name(&self) -> &'static str {
        match self.comp {
            0 => "none",
            1 => "zstd",
            _ => "?",
        }
    }

    pub fn enc_name(&self) -> &'static str {
        match self.enc {
            0 => "none",
            1 => "aead-stream",
            _ => "?",
        }
    }
}

/// The latest verification row for a bundle.
#[derive(Debug, Clone, PartialEq)]
pub struct VerificationRow {
    pub bundle_id: i64,
    pub status: Status,
    /// The raw status text, kept so a row written by a newer build is displayed
    /// rather than misread through a default.
    pub status_text: String,
    pub reason: String,
    pub gate: Option<Value>,
    pub checked_at: String,
}

/// One row of the flat verification screen.
#[derive(Debug, Clone, PartialEq)]
pub struct VerificationView {
    pub bundle_id: i64,
    pub slug: String,
    pub version: i64,
    pub status: Status,
    pub status_text: String,
    pub reason: String,
    pub checked_at: String,
}

/// One audit row.
#[derive(Debug, Clone, PartialEq)]
pub struct AuditRow {
    pub id: i64,
    pub at: String,
    pub actor: String,
    pub action: String,
    pub detail: Value,
}

/// One entitlement chain record.
#[derive(Debug, Clone, PartialEq)]
pub struct EntitlementRow {
    pub subject: String,
    pub seq: i64,
    pub record: Value,
    pub prev_hash: Option<Vec<u8>>,
    pub hash: Vec<u8>,
    pub recorded_at: String,
}

/// A row returned by the serving query. Kept separate from [`SectionRow`] because
/// the serving surface is deliberately narrower than the inspector's.
#[derive(Debug, Clone, PartialEq)]
pub struct ServedRow {
    pub name_id: i32,
    pub name: String,
    pub len_plain: i64,
    pub root: Vec<u8>,
    pub flags: i32,
    pub player_visible: bool,
    pub sealed: bool,
}

/// Lowercase hex, for roots and digests.
pub fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Escape control characters so manifest text cannot act on the terminal.
///
/// The bundle is untrusted input even after it parses: a `name` may carry C0/C1
/// controls. Rendering goes through this, never through `Display` of raw text.
pub fn escape_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push_str(&format!("\\u{{{:x}}}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// One hexdump row: the offset, 16 bytes in two groups, and the ASCII rendering.
///
/// The same layout `ctf inspect` prints (design §10: "the same widget in CLI and
/// TUI"). Non-printable bytes render as `.`, so the row can never emit a control
/// sequence.
pub fn hexdump_row(offset: usize, row: &[u8]) -> String {
    let hex: Vec<String> = row.iter().map(|b| format!("{b:02x}")).collect();
    let (left, right) = hex.split_at(hex.len().min(8));
    let ascii: String = row
        .iter()
        .map(|&b| {
            if (0x20..0x7f).contains(&b) {
                char::from(b)
            } else {
                '.'
            }
        })
        .collect();
    format!(
        "  {offset:08x}  {:<23}  {:<23}  |{ascii}|",
        left.join(" "),
        right.join(" ")
    )
}

/// An annotated hexdump: a title, the region's offset, and its rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HexDump {
    pub title: String,
    pub offset: usize,
    pub rows: Vec<String>,
}

impl HexDump {
    /// Dump at most `max_rows` 16-byte rows of `bytes`, starting at `offset`.
    pub fn new(title: impl Into<String>, offset: usize, bytes: &[u8], max_rows: usize) -> Self {
        let rows = bytes
            .chunks(16)
            .take(max_rows)
            .enumerate()
            .map(|(i, row)| hexdump_row(offset + i * 16, row))
            .collect();
        Self {
            title: title.into(),
            offset,
            rows,
        }
    }
}
