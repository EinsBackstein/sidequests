//! Headless renderer tests: every screen is drawn through `TestBackend`, so a
//! broken layout or an unescaped control character fails here rather than in an
//! operator's terminal.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ratatui::Terminal;
use ratatui::backend::TestBackend;

use ctf_tui::app::{Action, App, Field, Screen};
use ctf_tui::ui;

fn render(app: &App, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test terminal");
    terminal
        .draw(|frame| ui::draw(frame, app))
        .expect("draw must not panic");
    let buffer = terminal.backend().buffer();
    let mut text = String::new();
    for cell in buffer.content() {
        text.push_str(cell.symbol());
    }
    text
}

#[test]
fn the_challenge_list_shows_every_verdict_and_name() {
    let mut app = App::sample();
    app.screen = Screen::Challenges;
    let text = render(&app, 140, 40);
    assert!(text.contains("challenges"), "{text}");
    assert!(text.contains("whos-that-bird"), "{text}");
    assert!(text.contains("workstation-triage"), "{text}");
    assert!(text.contains("unverified"), "{text}");
    assert!(text.contains("passed"), "{text}");
}

#[test]
fn the_ingest_screen_renders_a_non_zero_progress_gauge() {
    let mut app = App::sample();
    app.screen = Screen::Ingest;
    let progress = app.progress.clone().expect("sample has progress");
    assert!(progress.fraction() > 0.0, "the fixture must be mid-ingest");
    let text = render(&app, 140, 40);
    assert!(text.contains("ingest"), "{text}");
    assert!(text.contains("verify 3/6"), "{text}");
    assert!(text.contains("3 of 6 units complete"), "{text}");
    // The stage list names the pipeline the operator is watching.
    assert!(text.contains("validate"), "{text}");
    assert!(text.contains("store"), "{text}");
}

#[test]
fn an_empty_gauge_is_zero_not_full() {
    let mut app = App::sample();
    app.screen = Screen::Ingest;
    app.progress = None;
    let text = render(&app, 140, 40);
    assert!(text.contains("no ingest running"), "{text}");
    assert!(!text.contains("100%"), "{text}");
}

#[test]
fn the_inspector_shows_sections_serving_and_a_hexdump() {
    let mut app = App::sample();
    app.screen = Screen::Inspector;
    let text = render(&app, 160, 45);
    assert!(text.contains("sections"), "{text}");
    assert!(text.contains("notes.md"), "{text}");
    assert!(text.contains("writeup"), "{text}");
    assert!(text.contains("SEALED"), "{text}");
    assert!(text.contains("PLAYER_VISIBLE"), "{text}");
    assert!(text.contains("serving: 1 artifact(s)"), "{text}");
    assert!(text.contains("hexdump"), "{text}");
    assert!(text.contains("00000000"), "{text}");
    assert!(text.contains("header"), "{text}");
}

#[test]
fn the_release_screen_shows_the_audit_report() {
    let mut app = App::sample();
    app.screen = Screen::Release;
    let text = render(&app, 140, 40);
    assert!(text.contains("seal release"), "{text}");
    assert!(text.contains("seal.key"), "{text}");
    assert!(text.contains("release mode: event_end"), "{text}");
    assert!(text.contains("writeup (1024 bytes)"), "{text}");
}

#[test]
fn the_verification_screen_shows_the_tri_state_and_reasons() {
    let mut app = App::sample();
    app.screen = Screen::Verification;
    let text = render(&app, 150, 40);
    assert!(text.contains("verification status"), "{text}");
    assert!(text.contains("passed"), "{text}");
    assert!(text.contains("unverified"), "{text}");
    assert!(text.contains("failed"), "{text}");
    assert!(text.contains("runtime"), "{text}");
}

#[test]
fn the_audit_screen_shows_ingest_release_and_handoff_rows() {
    let mut app = App::sample();
    app.screen = Screen::Audit;
    let text = render(&app, 160, 45);
    assert!(text.contains("audit log"), "{text}");
    assert!(text.contains("ingest.stored"), "{text}");
    assert!(text.contains("release.event_end"), "{text}");
    assert!(text.contains("entitlement"), "{text}");
    assert!(text.contains("team-42"), "{text}");
    assert!(text.contains("transfer"), "{text}");
}

#[test]
fn a_db_error_renders_as_a_pane_and_never_panics() {
    let mut app = App::sample();
    app.screen = Screen::Challenges;
    app.error = Some("connection refused\nwhile connecting to Postgres".to_owned());
    let text = render(&app, 140, 40);
    assert!(text.contains("error"), "{text}");
    assert!(text.contains("connection refused"), "{text}");
}

#[test]
fn control_characters_in_manifest_text_are_escaped() {
    let mut app = App::sample();
    app.screen = Screen::Challenges;
    if let Some(challenge) = app.challenges.first_mut() {
        challenge.name = "evil\u{1b}[31mname".to_owned();
    }
    let text = render(&app, 140, 40);
    assert!(
        !text.contains('\u{1b}'),
        "escape reached the terminal: {text:?}"
    );
    assert!(text.contains("\\u{1b}"), "escape should be visible: {text}");
}

#[test]
fn keyboard_navigation_cycles_screens_and_quit_is_global() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut app = App::sample();
    app.screen = Screen::Challenges;
    let action = app.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    assert_eq!(app.screen, Screen::Ingest);
    assert_eq!(app.focus, Field::IngestPath);
    // The ingest screen has nothing to fetch, so navigation must not invent an
    // action. A screen that does need data must request it.
    assert_eq!(action, None);

    let action = app.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    assert_eq!(app.screen, Screen::Inspector);
    assert!(matches!(action, Some(Action::LoadBundles(_))));

    app.focus = Field::None;
    let quit = app.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));
    assert_eq!(quit, Some(Action::Quit));
}
