//! `ctf-admin`: the operator surface (design §10).
//!
//! The binary owns the terminal and the background tasks; every DB statement lives
//! in `db.rs`/`ingest.rs` behind the library modules. Input that fails becomes the
//! error pane, never a panic.

use std::io;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use crossterm::event::{self, Event, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use sqlx::PgPool;
use tokio::sync::mpsc;

use ctf_format::{Bundle, SectionFlags};
use ctf_tui::app::{Action, App, Msg};
use ctf_tui::db;
use ctf_tui::ingest::{self, GateInputs};
use ctf_tui::model::{HexDump, hexdump_row};
use ctf_tui::ui;

#[derive(Parser)]
#[command(
    name = "ctf-admin",
    about = "Postgres-backed admin TUI for the .ctf format",
    version
)]
struct Args {
    /// Postgres connection string. `DATABASE_URL` is read when the flag is absent.
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,

    /// The actor recorded in every audit row.
    #[arg(long, default_value = "operator")]
    actor: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    let pool = match db::connect(&args.database_url).await {
        Ok(pool) => pool,
        Err(e) => {
            eprintln!("ctf-admin: {e}");
            return ExitCode::FAILURE;
        }
    };
    match run(pool, args.actor).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ctf-admin: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Restores the terminal on every exit path, including a panic during unwinding.
struct Restored;

impl Restored {
    fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen)?;
        Ok(Self)
    }
}

impl Drop for Restored {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

async fn run(pool: PgPool, actor: String) -> io::Result<()> {
    let mut app = App::default();
    let (tx, mut rx) = mpsc::unbounded_channel::<Msg>();

    load_challenges(&pool, &tx).await;

    let _restored = Restored::enter()?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    while app.running {
        while let Ok(message) = rx.try_recv() {
            app.apply(message);
        }
        terminal.draw(|frame| ui::draw(frame, &app))?;

        if event::poll(Duration::from_millis(50))? {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    if let Some(action) = app.on_key(key) {
                        dispatch(action, &pool, &tx, &actor, &mut app);
                    }
                }
                Event::Resize(_, _) => {}
                _ => {}
            }
        }
    }
    Ok(())
}

/// Turn a state-machine action into a background task. Nothing here blocks the
/// draw loop; progress and results come back as [`Msg`].
fn dispatch(
    action: Action,
    pool: &PgPool,
    tx: &mpsc::UnboundedSender<Msg>,
    actor: &str,
    app: &mut App,
) {
    match action {
        Action::Quit => app.running = false,
        Action::RefreshChallenges => {
            let pool = pool.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                load_challenges(&pool, &tx).await;
            });
        }
        Action::LoadBundles(challenge_id) => {
            let pool = pool.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                match db::bundles_for_challenge(&pool, challenge_id).await {
                    Ok(bundles) => {
                        let _ = tx.send(Msg::Bundles(bundles));
                    }
                    Err(e) => {
                        let _ = tx.send(Msg::Error(e.to_string()));
                    }
                }
            });
        }
        Action::LoadDetail(bundle_id) => {
            let pool = pool.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                load_detail(&pool, bundle_id, &tx).await;
            });
        }
        Action::Ingest {
            path,
            document,
            secret,
        } => {
            let pool = pool.clone();
            let tx = tx.clone();
            let actor = actor.to_owned();
            tokio::spawn(async move {
                let bytes = match tokio::fs::read(&path).await {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        let _ = tx.send(Msg::Error(format!("{path}: {e}")));
                        return;
                    }
                };
                let gate = match (document, secret) {
                    (Some(document), Some(secret)) => Some(GateInputs {
                        document: PathBuf::from(document),
                        secret_hex: secret,
                        subject: "reference".to_owned(),
                    }),
                    _ => None,
                };
                let progress_tx = tx.clone();
                let outcome = ingest::ingest(&pool, &bytes, gate, &actor, move |progress| {
                    let _ = progress_tx.send(Msg::Progress(progress));
                })
                .await;
                match outcome {
                    Ok(outcome) => {
                        let _ = tx.send(Msg::IngestDone(outcome));
                        load_challenges(&pool, &tx).await;
                        load_audit(&pool, &tx).await;
                    }
                    Err(e) => {
                        let _ = tx.send(Msg::Error(e.to_string()));
                    }
                }
            });
        }
        Action::Release {
            bundle_id,
            key_path,
        } => {
            let pool = pool.clone();
            let tx = tx.clone();
            let actor = actor.to_owned();
            tokio::spawn(async move {
                let key = match ingest::read_key_file(std::path::Path::new(&key_path)) {
                    Ok(key) => key,
                    Err(e) => {
                        let _ = tx.send(Msg::Error(format!("{key_path}: {e}")));
                        return;
                    }
                };
                match ingest::release(&pool, bundle_id, &key, &actor).await {
                    Ok(outcome) => {
                        let _ = tx.send(Msg::ReleaseDone(outcome));
                        load_audit(&pool, &tx).await;
                    }
                    Err(e) => {
                        let _ = tx.send(Msg::Error(e.to_string()));
                    }
                }
            });
        }
        Action::RefreshVerification => {
            let pool = pool.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                match db::verification_list(&pool).await {
                    Ok(list) => {
                        let _ = tx.send(Msg::VerificationList(list));
                    }
                    Err(e) => {
                        let _ = tx.send(Msg::Error(e.to_string()));
                    }
                }
            });
        }
        Action::RefreshAudit => {
            let pool = pool.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                load_audit(&pool, &tx).await;
            });
        }
    }
}

async fn load_challenges(pool: &PgPool, tx: &mpsc::UnboundedSender<Msg>) {
    match db::challenges(pool).await {
        Ok(challenges) => {
            let _ = tx.send(Msg::Challenges(challenges));
        }
        Err(e) => {
            let _ = tx.send(Msg::Error(e.to_string()));
        }
    }
}

async fn load_audit(pool: &PgPool, tx: &mpsc::UnboundedSender<Msg>) {
    let audit = db::audit_log(pool, 200).await;
    let entitlements = db::entitlements(pool, 200).await;
    match (audit, entitlements) {
        (Ok(audit), Ok(entitlements)) => {
            let _ = tx.send(Msg::Audit {
                audit,
                entitlements,
            });
        }
        (Err(e), _) | (_, Err(e)) => {
            let _ = tx.send(Msg::Error(e.to_string()));
        }
    }
}

/// Sections, the latest verdict, the side of the serving rule the platform may
/// hand out, and an annotated dump of the header and first payload.
async fn load_detail(pool: &PgPool, bundle_id: i64, tx: &mpsc::UnboundedSender<Msg>) {
    let sections = match db::sections(pool, bundle_id).await {
        Ok(sections) => sections,
        Err(e) => {
            let _ = tx.send(Msg::Error(e.to_string()));
            return;
        }
    };
    let verification = match db::verification(pool, bundle_id).await {
        Ok(verification) => verification,
        Err(e) => {
            let _ = tx.send(Msg::Error(e.to_string()));
            return;
        }
    };
    let servable = match db::served_artifacts(pool, bundle_id).await {
        Ok(servable) => servable,
        Err(e) => {
            let _ = tx.send(Msg::Error(e.to_string()));
            return;
        }
    };
    let bytes = match db::bundle_bytes(pool, bundle_id).await {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            let _ = tx.send(Msg::Error(format!("bundle {bundle_id} is not stored")));
            return;
        }
        Err(e) => {
            let _ = tx.send(Msg::Error(e.to_string()));
            return;
        }
    };
    let hexdump = dump_for(&bytes);
    let _ = tx.send(Msg::Detail {
        bundle_id,
        sections,
        verification,
        servable,
        hexdump,
    });
}

/// The header, then the first inline payload's opening bytes. Both regions are
/// bounded, so a large bundle is inspected without copying it into the UI.
fn dump_for(bytes: &[u8]) -> Option<HexDump> {
    let header = bytes.get(..64.min(bytes.len()))?;
    let mut rows: Vec<String> = header
        .chunks(16)
        .enumerate()
        .map(|(index, row)| hexdump_row(index * 16, row))
        .collect();
    let mut title = "header @ 0x0".to_owned();

    if let Ok(bundle) = Bundle::parse(bytes) {
        let payload = bundle.sections.iter().find(|record| {
            !record.flags.contains(SectionFlags::EXTERNAL)
                && record.offset > 0
                && record.len_stored > 0
        });
        if let Some(record) = payload {
            let start = usize::try_from(record.offset).ok();
            let end = start.and_then(|start| {
                usize::try_from(record.len_stored)
                    .ok()
                    .and_then(|len| start.checked_add(len))
            });
            if let (Some(start), Some(end)) = (start, end)
                && let Some(region) = bytes.get(start..end)
            {
                title = format!("header, then first payload @ {start:#x}");
                rows.extend(
                    region
                        .chunks(16)
                        .take(16)
                        .enumerate()
                        .map(|(index, row)| hexdump_row(start + index * 16, row)),
                );
                rows.insert(4, String::new());
            }
        }
    }

    Some(HexDump {
        title,
        offset: 0,
        rows,
    })
}
