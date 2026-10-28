//! The state machine. No database calls, no drawing.
//!
//! Key handling mutates only this struct and returns an [`Action`], which `main.rs`
//! turns into a background task. Keeping the two sides apart is what lets the
//! renderer tests drive every screen with a `TestBackend` and no Postgres, and what
//! keeps a failed query from unwinding a terminal.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::ingest::{IngestOutcome, ReleaseOutcome};
use crate::model::{
    AuditRow, BundleRow, ChallengeRow, EntitlementRow, HexDump, Progress, SectionRow, ServedRow,
    Status, VerificationRow, VerificationView,
};

/// The six operator screens (design §10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Challenges,
    Ingest,
    Inspector,
    Release,
    Verification,
    Audit,
}

impl Screen {
    pub const ALL: [Self; 6] = [
        Self::Challenges,
        Self::Ingest,
        Self::Inspector,
        Self::Release,
        Self::Verification,
        Self::Audit,
    ];

    pub const fn title(self) -> &'static str {
        match self {
            Self::Challenges => "Challenges",
            Self::Ingest => "Ingest",
            Self::Inspector => "Bundle inspector",
            Self::Release => "Seal release",
            Self::Verification => "Verification",
            Self::Audit => "Entitlements / audit",
        }
    }

    /// The next screen, wrapping.
    pub fn next(self) -> Self {
        let index = Self::ALL.iter().position(|s| *s == self).unwrap_or(0);
        Self::ALL
            .get((index + 1) % Self::ALL.len())
            .copied()
            .unwrap_or(Self::Challenges)
    }

    /// The previous screen, wrapping.
    pub fn previous(self) -> Self {
        let index = Self::ALL.iter().position(|s| *s == self).unwrap_or(0);
        let next = index.checked_sub(1).unwrap_or(Self::ALL.len() - 1);
        Self::ALL.get(next).copied().unwrap_or(Self::Challenges)
    }
}

/// Which text field currently owns typed characters. `None` means the screen's
/// table or action key handling is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    None,
    IngestPath,
    IngestDocument,
    IngestSecret,
    ReleaseKey,
}

/// What `main.rs` should do after a key. The UI never performs I/O itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Quit,
    RefreshChallenges,
    LoadBundles(i64),
    LoadDetail(i64),
    Ingest {
        path: String,
        document: Option<String>,
        secret: Option<String>,
    },
    Release {
        bundle_id: i64,
        key_path: String,
    },
    RefreshVerification,
    RefreshAudit,
}

/// The whole UI state.
#[derive(Debug, Clone)]
pub struct App {
    pub running: bool,
    pub screen: Screen,
    pub busy: bool,
    pub error: Option<String>,
    pub notice: Option<String>,
    pub focus: Field,

    pub challenges: Vec<ChallengeRow>,
    pub challenge_index: usize,

    pub bundles: Vec<BundleRow>,
    pub bundle_index: usize,

    pub sections: Vec<SectionRow>,
    pub verification: Option<VerificationRow>,
    pub servable: Vec<ServedRow>,
    pub hexdump: Option<HexDump>,
    pub detail_bundle_id: Option<i64>,

    pub ingest_path: String,
    pub ingest_document: String,
    pub ingest_secret: String,
    pub progress: Option<Progress>,

    pub release_key: String,
    pub release_report: Vec<String>,

    pub verification_list: Vec<VerificationView>,

    pub audit: Vec<AuditRow>,
    pub entitlements: Vec<EntitlementRow>,
}

impl Default for App {
    fn default() -> Self {
        Self {
            running: true,
            screen: Screen::Challenges,
            busy: false,
            error: None,
            notice: None,
            focus: Field::None,
            challenges: Vec::new(),
            challenge_index: 0,
            bundles: Vec::new(),
            bundle_index: 0,
            sections: Vec::new(),
            verification: None,
            servable: Vec::new(),
            hexdump: None,
            detail_bundle_id: None,
            ingest_path: String::new(),
            ingest_document: String::new(),
            ingest_secret: String::new(),
            progress: None,
            release_key: String::new(),
            release_report: Vec::new(),
            verification_list: Vec::new(),
            audit: Vec::new(),
            entitlements: Vec::new(),
        }
    }
}

/// A message from a background task. Errors arrive as text; nothing here can panic
/// a render.
#[derive(Debug)]
pub enum Msg {
    Challenges(Vec<ChallengeRow>),
    Bundles(Vec<BundleRow>),
    Detail {
        bundle_id: i64,
        sections: Vec<SectionRow>,
        verification: Option<VerificationRow>,
        servable: Vec<ServedRow>,
        hexdump: Option<HexDump>,
    },
    Progress(Progress),
    IngestDone(IngestOutcome),
    ReleaseDone(ReleaseOutcome),
    VerificationList(Vec<VerificationView>),
    Audit {
        audit: Vec<AuditRow>,
        entitlements: Vec<EntitlementRow>,
    },
    Error(String),
}

impl App {
    /// The challenge under the cursor, if any.
    pub fn selected_challenge(&self) -> Option<&ChallengeRow> {
        self.challenges.get(self.challenge_index)
    }

    /// The bundle under the cursor, if any.
    pub fn selected_bundle(&self) -> Option<&BundleRow> {
        self.bundles.get(self.bundle_index)
    }

    /// Move a list cursor with wrapping, without indexing.
    pub fn move_cursor(index: &mut usize, delta: isize, len: usize) {
        if len == 0 {
            *index = 0;
            return;
        }
        let position = (*index).min(len.saturating_sub(1)) as isize;
        let moved = (position + delta).rem_euclid(len as isize);
        *index = moved as usize;
    }

    /// Apply a background result. No I/O, no panics.
    pub fn apply(&mut self, msg: Msg) {
        match msg {
            Msg::Challenges(challenges) => {
                self.challenges = challenges;
                self.challenge_index = self
                    .challenge_index
                    .min(self.challenges.len().saturating_sub(1));
            }
            Msg::Bundles(bundles) => {
                self.bundles = bundles;
                self.bundle_index = self.bundle_index.min(self.bundles.len().saturating_sub(1));
            }
            Msg::Detail {
                bundle_id,
                sections,
                verification,
                servable,
                hexdump,
            } => {
                self.detail_bundle_id = Some(bundle_id);
                self.sections = sections;
                self.verification = verification;
                self.servable = servable;
                self.hexdump = hexdump;
            }
            Msg::Progress(progress) => {
                self.progress = Some(progress);
            }
            Msg::IngestDone(outcome) => {
                self.busy = false;
                self.notice = Some(format!(
                    "ingest {}: {}{}",
                    outcome.status.as_str(),
                    outcome.reason,
                    outcome
                        .bundle_id
                        .map(|id| format!(" (bundle {id})"))
                        .unwrap_or_default()
                ));
                if let Some(progress) = self.progress.as_mut() {
                    progress.done = progress.total;
                }
            }
            Msg::ReleaseDone(outcome) => {
                self.busy = false;
                self.release_report = vec![
                    format!("{} version {}", outcome.challenge, outcome.version),
                    format!("release mode: {}", outcome.release),
                    format!("members released: {}", outcome.members.len()),
                ];
                self.release_report.extend(
                    outcome
                        .members
                        .iter()
                        .map(|(name, size)| format!("  {name} ({size} bytes)")),
                );
                self.notice = Some(format!(
                    "released {} member(s) of {}",
                    outcome.members.len(),
                    outcome.challenge
                ));
            }
            Msg::VerificationList(list) => self.verification_list = list,
            Msg::Audit {
                audit,
                entitlements,
            } => {
                self.audit = audit;
                self.entitlements = entitlements;
            }
            Msg::Error(error) => {
                self.busy = false;
                self.error = Some(error);
            }
        }
    }

    /// Handle one key. Text fields consume printable characters; the rest of the
    /// screen's keys are navigation.
    pub fn on_key(&mut self, key: KeyEvent) -> Option<Action> {
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return Some(Action::Quit);
        }

        // A focused text field owns typing and deletion. Escape leaves the field, so
        // `q`/`Tab` become commands again.
        if self.focus != Field::None {
            match key.code {
                KeyCode::Esc => {
                    self.focus = Field::None;
                    return None;
                }
                KeyCode::Enter => {
                    self.focus = Field::None;
                    return self.submit();
                }
                KeyCode::Backspace => {
                    self.active_field_mut().pop();
                    return None;
                }
                KeyCode::Char(c)
                    if !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    self.active_field_mut().push(c);
                    return None;
                }
                _ => {}
            }
        }

        match key.code {
            KeyCode::Char('q') => Some(Action::Quit),
            KeyCode::Tab => {
                self.screen = self.screen.next();
                self.focus = self.default_focus();
                self.refresh_action()
            }
            KeyCode::BackTab => {
                self.screen = self.screen.previous();
                self.focus = self.default_focus();
                self.refresh_action()
            }
            KeyCode::Char('r') => self.refresh_action(),
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_selection(-1);
                None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_selection(1);
                None
            }
            KeyCode::Esc => {
                if self.screen == Screen::Inspector {
                    self.screen = Screen::Challenges;
                    self.focus = Field::None;
                }
                None
            }
            KeyCode::Enter => self.submit(),
            _ => None,
        }
    }

    fn default_focus(&self) -> Field {
        match self.screen {
            Screen::Ingest => Field::IngestPath,
            Screen::Release => Field::ReleaseKey,
            _ => Field::None,
        }
    }

    fn move_selection(&mut self, delta: isize) {
        match self.screen {
            Screen::Challenges => {
                Self::move_cursor(&mut self.challenge_index, delta, self.challenges.len());
            }
            Screen::Inspector => {
                Self::move_cursor(&mut self.bundle_index, delta, self.bundles.len());
            }
            Screen::Release | Screen::Verification | Screen::Audit | Screen::Ingest => {
                // These screens have no independent selection cursor; a focused field
                // is moved instead, and a table without a cursor does not silently
                // move a challenge the operator cannot see.
                let next = match self.focus {
                    Field::IngestPath => Field::IngestDocument,
                    Field::IngestDocument => Field::IngestSecret,
                    Field::IngestSecret => Field::IngestPath,
                    _ if self.screen == Screen::Ingest => Field::IngestPath,
                    _ => Field::None,
                };
                if self.screen == Screen::Ingest {
                    self.focus = if delta < 0 {
                        match self.focus {
                            Field::IngestPath => Field::IngestSecret,
                            Field::IngestDocument => Field::IngestPath,
                            Field::IngestSecret => Field::IngestDocument,
                            Field::None => Field::IngestSecret,
                            Field::ReleaseKey => Field::IngestPath,
                        }
                    } else {
                        next
                    };
                }
            }
        }
    }

    fn active_field_mut(&mut self) -> &mut String {
        match self.focus {
            Field::IngestPath => &mut self.ingest_path,
            Field::IngestDocument => &mut self.ingest_document,
            Field::IngestSecret => &mut self.ingest_secret,
            Field::ReleaseKey => &mut self.release_key,
            Field::None => &mut self.ingest_path,
        }
    }

    fn refresh_action(&self) -> Option<Action> {
        match self.screen {
            Screen::Challenges => Some(Action::RefreshChallenges),
            Screen::Inspector | Screen::Release => self
                .selected_challenge()
                .map(|challenge| Action::LoadBundles(challenge.id)),
            Screen::Verification => Some(Action::RefreshVerification),
            Screen::Audit => Some(Action::RefreshAudit),
            Screen::Ingest => None,
        }
    }

    fn submit(&mut self) -> Option<Action> {
        match self.screen {
            Screen::Challenges => {
                let challenge = self.selected_challenge()?;
                let id = challenge.id;
                self.screen = Screen::Inspector;
                Some(Action::LoadBundles(id))
            }
            Screen::Inspector => {
                let bundle = self.selected_bundle()?;
                Some(Action::LoadDetail(bundle.id))
            }
            Screen::Ingest => {
                let path = self.ingest_path.trim().to_owned();
                if path.is_empty() {
                    self.error = Some("an ingest needs a bundle path".to_owned());
                    return None;
                }
                let document = non_empty(&self.ingest_document);
                let secret = non_empty(&self.ingest_secret);
                if document.is_some() != secret.is_some() {
                    self.error = Some(
                        "the offline gate needs both an authoring document and the event secret"
                            .to_owned(),
                    );
                    return None;
                }
                self.busy = true;
                self.error = None;
                self.notice = None;
                self.progress = None;
                Some(Action::Ingest {
                    path,
                    document,
                    secret,
                })
            }
            Screen::Release => {
                let bundle_id = match self.selected_bundle() {
                    Some(bundle) => bundle.id,
                    None => {
                        self.error = Some("no bundle selected".to_owned());
                        return None;
                    }
                };
                let key_path = self.release_key.trim().to_owned();
                if key_path.is_empty() {
                    self.error = Some("a release needs a seal key file".to_owned());
                    return None;
                }
                self.busy = true;
                self.error = None;
                Some(Action::Release {
                    bundle_id,
                    key_path,
                })
            }
            Screen::Verification | Screen::Audit => self.refresh_action(),
        }
    }

    /// A representative state for the headless renderer tests. Every screen has
    /// content, including a tri-state verdict, a visible artifact, a sealed one, and
    /// a half-finished progress bar.
    #[allow(clippy::field_reassign_with_default)]
    pub fn sample() -> Self {
        let mut app = Self::default();
        app.challenges = vec![
            ChallengeRow {
                id: 1,
                slug: "whos-that-bird".to_owned(),
                version: 1,
                name: "Who's That Bird".to_owned(),
                category: Some("osint".to_owned()),
                created_at: "2026-10-28 10:00:00+00".to_owned(),
                updated_at: "2026-10-28 10:00:00+00".to_owned(),
                bundle_count: 1,
                latest_status: Some(Status::Unverified),
                latest_at: Some("2026-10-28 10:00:00+00".to_owned()),
            },
            ChallengeRow {
                id: 2,
                slug: "workstation-triage".to_owned(),
                version: 3,
                name: "Workstation Triage".to_owned(),
                category: Some("forensics".to_owned()),
                created_at: "2026-10-28 11:00:00+00".to_owned(),
                updated_at: "2026-10-28 11:00:00+00".to_owned(),
                bundle_count: 2,
                latest_status: Some(Status::Passed),
                latest_at: Some("2026-10-28 11:00:00+00".to_owned()),
            },
        ];
        app.bundles = vec![BundleRow {
            id: 7,
            challenge_id: 2,
            total_len: 18328,
            sha256: vec![0xab; 32],
            commitment_root: vec![0xcd; 32],
            suite_id: 1,
            ingested_at: "2026-10-28 11:00:00+00".to_owned(),
            source_path: Some("demo.ctf".to_owned()),
        }];
        app.sections = vec![
            SectionRow {
                id: 1,
                bundle_id: 7,
                name_id: 0,
                name: "manifest".to_owned(),
                kind: 1,
                flags: 0,
                comp: 0,
                enc: 0,
                len_plain: 285,
                len_stored: 285,
                offset: 4096,
                root: vec![0x11; 32],
                chunk_size: 0,
                chunk_index_off: 0,
                player_visible: false,
                sealed: false,
                external: false,
            },
            SectionRow {
                id: 2,
                bundle_id: 7,
                name_id: 1,
                name: "notes.md".to_owned(),
                kind: 2,
                flags: 2,
                comp: 0,
                enc: 0,
                len_plain: 9600,
                len_stored: 9600,
                offset: 8192,
                root: vec![0x22; 32],
                chunk_size: 4096,
                chunk_index_off: 17792,
                player_visible: true,
                sealed: false,
                external: false,
            },
            SectionRow {
                id: 3,
                bundle_id: 7,
                name_id: 2,
                name: "writeup".to_owned(),
                kind: 5,
                flags: 1,
                comp: 1,
                enc: 1,
                len_plain: 1024,
                len_stored: 1044,
                offset: 9216,
                root: vec![0x33; 32],
                chunk_size: 4096,
                chunk_index_off: 0,
                player_visible: false,
                sealed: true,
                external: false,
            },
        ];
        app.verification = Some(VerificationRow {
            bundle_id: 7,
            status: Status::Passed,
            status_text: "passed".to_owned(),
            reason: "the solver recovered the derived flag".to_owned(),
            gate: None,
            checked_at: "2026-10-28 11:00:00+00".to_owned(),
        });
        app.servable = vec![ServedRow {
            name_id: 1,
            name: "notes.md".to_owned(),
            len_plain: 9600,
            root: vec![0x22; 32],
            flags: 2,
            player_visible: true,
            sealed: false,
        }];
        app.hexdump = Some(HexDump::new(
            "header @ 0x0",
            0,
            b"\x89CTF\r\n\x1a\n\x00\x00\x03\x00\x40\x00\x00\x00workstation-triage",
            4,
        ));
        app.ingest_path = "spec/vectors/conformance/golden/demo.ctf".to_owned();
        app.ingest_document = "challenge.yml".to_owned();
        app.ingest_secret = "…".to_owned();
        app.progress = Some(Progress {
            stage: crate::model::Stage::Verify,
            done: 3,
            total: 6,
            label: "chunks of name_id 1".to_owned(),
        });
        app.release_key = "seal.key".to_owned();
        app.release_report = vec![
            "workstation-triage version 3".to_owned(),
            "release mode: event_end".to_owned(),
            "members released: 1".to_owned(),
            "  writeup (1024 bytes)".to_owned(),
        ];
        app.verification_list = vec![
            VerificationView {
                bundle_id: 7,
                slug: "workstation-triage".to_owned(),
                version: 3,
                status: Status::Passed,
                status_text: "passed".to_owned(),
                reason: "the solver recovered the derived flag".to_owned(),
                checked_at: "2026-10-28 11:00:00+00".to_owned(),
            },
            VerificationView {
                bundle_id: 8,
                slug: "baby-rop".to_owned(),
                version: 1,
                status: Status::Unverified,
                status_text: "unverified".to_owned(),
                reason: "the challenge declares a runtime, which needs a live instance".to_owned(),
                checked_at: "2026-10-28 10:30:00+00".to_owned(),
            },
            VerificationView {
                bundle_id: 9,
                slug: "sealed-chal".to_owned(),
                version: 2,
                status: Status::Failed,
                status_text: "failed".to_owned(),
                reason: "the solver produced a different flag than the derived flag".to_owned(),
                checked_at: "2026-10-28 10:00:00+00".to_owned(),
            },
        ];
        app.audit = vec![
            AuditRow {
                id: 2,
                at: "2026-10-28 11:00:00+00".to_owned(),
                actor: "operator".to_owned(),
                action: "ingest.stored".to_owned(),
                detail: serde_json::json!({"bundle_id": 7, "status": "passed"}),
            },
            AuditRow {
                id: 1,
                at: "2026-10-28 10:00:00+00".to_owned(),
                actor: "operator".to_owned(),
                action: "release.event_end".to_owned(),
                detail: serde_json::json!({"bundle_id": 3}),
            },
        ];
        app.entitlements = vec![EntitlementRow {
            subject: "team-42".to_owned(),
            seq: 2,
            record: serde_json::json!({"type": "transfer", "to": "team-43"}),
            prev_hash: Some(vec![0x01; 32]),
            hash: vec![0x02; 32],
            recorded_at: "2026-10-28 09:00:00+00".to_owned(),
        }];
        app
    }
}

fn non_empty(text: &str) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}
