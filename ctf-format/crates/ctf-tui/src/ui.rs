//! Rendering only. Reads [`App`] and draws; never touches a database.
//!
//! Manifest text is untrusted even after the bundle parses (a `name` may carry
//! control characters), so every string that came from a file or a row goes through
//! [`crate::model::escape_text`] or [`clip`] before it reaches a `Cell`.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Gauge, Paragraph, Row, Table, Tabs, Wrap};

use crate::app::{App, Field, Screen};
use crate::model::{Status, escape_text, hex};

/// Draw the whole screen.
pub fn draw(frame: &mut Frame<'_>, app: &App) {
    let area = frame.area();
    let outer = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(6),
        Constraint::Length(if app.error.is_some() { 4 } else { 2 }),
    ])
    .split(area);

    draw_tabs(frame, outer.first().copied().unwrap_or(area), app);
    if let Some(body) = outer.get(1).copied() {
        match app.screen {
            Screen::Challenges => draw_challenges(frame, body, app),
            Screen::Ingest => draw_ingest(frame, body, app),
            Screen::Inspector => draw_inspector(frame, body, app),
            Screen::Release => draw_release(frame, body, app),
            Screen::Verification => draw_verification(frame, body, app),
            Screen::Audit => draw_audit(frame, body, app),
        }
    }
    if let Some(footer) = outer.get(2).copied() {
        draw_footer(frame, footer, app);
    }
}

fn draw_tabs(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let selected = Screen::ALL
        .iter()
        .position(|screen| *screen == app.screen)
        .unwrap_or(0);
    let tabs = Tabs::new(Screen::ALL.iter().map(|screen| screen.title()))
        .select(selected)
        .block(Block::default().borders(Borders::ALL).title(" ctf-admin "))
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_widget(tabs, area);
}

fn draw_challenges(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let rows = app.challenges.iter().enumerate().map(|(index, challenge)| {
        let style = selected_style(index == app.challenge_index);
        Row::new(vec![
            Cell::from(clip(&challenge.slug, 28)),
            Cell::from(challenge.version.to_string()),
            Cell::from(clip(&challenge.name, 30)),
            Cell::from(clip(challenge.category.as_deref().unwrap_or("-"), 12)),
            Cell::from(challenge.bundle_count.to_string()),
            Cell::from(status_span(challenge.latest_status)),
            Cell::from(clip(challenge.latest_at.as_deref().unwrap_or("-"), 26)),
        ])
        .style(style)
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(30),
            Constraint::Length(5),
            Constraint::Length(32),
            Constraint::Length(14),
            Constraint::Length(8),
            Constraint::Length(12),
            Constraint::Min(12),
        ],
    )
    .header(
        Row::new(vec![
            "slug", "ver", "name", "category", "bundles", "latest", "checked",
        ])
        .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(Block::default().borders(Borders::ALL).title(" challenges "))
    .column_spacing(1);

    if app.challenges.is_empty() {
        frame.render_widget(
            Paragraph::new(
                "No challenges ingested yet.\n\nTab to Ingest, give a bundle path, and press Enter.",
            )
            .block(Block::default().borders(Borders::ALL).title(" challenges "))
            .wrap(Wrap { trim: false }),
            area,
        );
    } else {
        frame.render_widget(table, area);
    }
}

fn draw_ingest(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let chunks = Layout::vertical([
        Constraint::Length(7),
        Constraint::Length(3),
        Constraint::Length(6),
        Constraint::Min(3),
    ])
    .split(area);

    let field = |label: &str, value: &str, focused: bool, secret: bool| {
        let marker = if focused { ">" } else { " " };
        let shown = if secret {
            if value.is_empty() {
                "not set".to_owned()
            } else {
                "set (not displayed)".to_owned()
            }
        } else {
            clip(value, 80)
        };
        Line::from(vec![
            Span::styled(
                format!("{marker} {label:<10} "),
                if focused {
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                },
            ),
            Span::raw(shown),
        ])
    };
    let form = Paragraph::new(vec![
        Line::from("Foreground ingest: validate → verify chunks → offline gate → store."),
        field(
            "bundle",
            &app.ingest_path,
            app.focus == Field::IngestPath,
            false,
        ),
        field(
            "document",
            &app.ingest_document,
            app.focus == Field::IngestDocument,
            false,
        ),
        field(
            "secret",
            &app.ingest_secret,
            app.focus == Field::IngestSecret,
            true,
        ),
        Line::from(Span::styled(
            "Enter runs · Up/Down moves fields · Esc leaves the field",
            Style::default().fg(Color::DarkGray),
        )),
    ])
    .block(Block::default().borders(Borders::ALL).title(" ingest "))
    .wrap(Wrap { trim: false });
    frame.render_widget(form, chunks.first().copied().unwrap_or(area));

    let gauge_area = chunks.get(1).copied().unwrap_or(area);
    match &app.progress {
        Some(progress) => {
            let gauge = Gauge::default()
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(format!(" {} ", progress.stage.label())),
                )
                .gauge_style(
                    Style::default()
                        .fg(Color::LightGreen)
                        .bg(Color::Black)
                        .add_modifier(Modifier::BOLD),
                )
                .ratio(progress.fraction())
                .label(format!(
                    "{} — {}",
                    progress.text(),
                    clip(&progress.label, 40)
                ));
            frame.render_widget(gauge, gauge_area);
        }
        None => {
            let gauge = Gauge::default()
                .block(Block::default().borders(Borders::ALL).title(" progress "))
                .ratio(0.0)
                .label("no ingest running");
            frame.render_widget(gauge, gauge_area);
        }
    }

    let stages = chunks.get(2).copied().unwrap_or(area);
    let lines = app
        .progress
        .as_ref()
        .map(|progress| {
            crate::model::Stage::ALL
                .iter()
                .map(|stage| {
                    let marker = if stage_index(*stage) < stage_index(progress.stage) {
                        "done"
                    } else if *stage == progress.stage {
                        "now "
                    } else {
                        "    "
                    };
                    Line::from(format!("  {marker} {}", stage.label()))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| {
            vec![
                Line::from("  stages: validate · verify · gate · store"),
                Line::from("  A pass is never reported unless the offline gate ran."),
            ]
        });
    frame.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(" stages ")),
        stages,
    );

    let detail = chunks.get(3).copied().unwrap_or(area);
    let mut lines = Vec::new();
    if let Some(notice) = &app.notice {
        lines.push(Line::from(clip(notice, 160)));
    }
    if let Some(progress) = &app.progress {
        lines.push(Line::from(format!(
            "  {} of {} units complete",
            progress.done, progress.total
        )));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(" result "))
            .wrap(Wrap { trim: false }),
        detail,
    );
}

fn draw_inspector(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let columns = Layout::horizontal([Constraint::Length(34), Constraint::Min(40)]).split(area);
    let left = columns.first().copied().unwrap_or(area);
    let right = columns.get(1).copied().unwrap_or(area);

    let bundles = app.bundles.iter().enumerate().map(|(index, bundle)| {
        let line = format!(
            "#{} {:>8} B  {}",
            bundle.id,
            bundle.total_len,
            clip(
                bundle.ingested_at.get(..19).unwrap_or(&bundle.ingested_at),
                19
            )
        );
        let style = selected_style(index == app.bundle_index);
        Row::new(vec![Cell::from(line)]).style(style)
    });
    frame.render_widget(
        Table::new(bundles, [Constraint::Min(30)])
            .header(Row::new(vec!["bundles"]).style(Style::default().add_modifier(Modifier::BOLD)))
            .block(Block::default().borders(Borders::ALL).title(" bundles ")),
        left,
    );

    let rows = Layout::vertical([
        Constraint::Length(9),
        Constraint::Length(5),
        Constraint::Min(6),
    ])
    .split(right);

    let sections = app.sections.iter().map(|section| {
        Row::new(vec![
            Cell::from(section.name_id.to_string()),
            Cell::from(clip(&section.kind_name(), 12)),
            Cell::from(clip(&section.name, 24)),
            Cell::from(clip(&section.flag_names(), 24)),
            Cell::from(section.len_plain.to_string()),
            Cell::from(section.len_stored.to_string()),
            Cell::from(clip(section.comp_name(), 5)),
            Cell::from(clip(section.enc_name(), 12)),
            Cell::from(section.chunk_size.to_string()),
        ])
    });
    frame.render_widget(
        Table::new(
            sections,
            [
                Constraint::Length(4),
                Constraint::Length(13),
                Constraint::Length(26),
                Constraint::Length(26),
                Constraint::Length(10),
                Constraint::Length(10),
                Constraint::Length(6),
                Constraint::Length(12),
                Constraint::Length(10),
            ],
        )
        .header(
            Row::new(vec![
                "id", "kind", "name", "flags", "plain", "stored", "comp", "enc", "chunk",
            ])
            .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .block(Block::default().borders(Borders::ALL).title(" sections "))
        .column_spacing(1),
        rows.first().copied().unwrap_or(right),
    );

    let mut meta = Vec::new();
    if let Some(verification) = &app.verification {
        meta.push(Line::from(vec![
            Span::raw("verification: "),
            status_span(Some(verification.status)),
            Span::raw(format!("  {}", clip(&verification.reason, 100))),
        ]));
    }
    meta.push(Line::from(format!(
        "serving: {} artifact(s) pass both checks",
        app.servable.len()
    )));
    for artifact in app.servable.iter().take(3) {
        meta.push(Line::from(format!(
            "  {} ({} bytes) root {}",
            clip(&artifact.name, 40),
            artifact.len_plain,
            hex(&artifact.root).get(..16).unwrap_or("-")
        )));
    }
    frame.render_widget(
        Paragraph::new(meta).block(Block::default().borders(Borders::ALL).title(" status ")),
        rows.get(1).copied().unwrap_or(right),
    );

    let dump_area = rows.get(2).copied().unwrap_or(right);
    match &app.hexdump {
        Some(dump) => {
            let lines = std::iter::once(Line::from(format!(
                "{}  @ {:#x}, escaped",
                dump.title, dump.offset
            )))
            .chain(dump.rows.iter().cloned().map(Line::from))
            .collect::<Vec<_>>();
            frame.render_widget(
                Paragraph::new(lines)
                    .block(Block::default().borders(Borders::ALL).title(" hexdump ")),
                dump_area,
            );
        }
        None => {
            frame.render_widget(
                Paragraph::new(
                    "Select a bundle and press Enter to load its section table and hexdump.",
                )
                .block(Block::default().borders(Borders::ALL).title(" hexdump "))
                .wrap(Wrap { trim: false }),
                dump_area,
            );
        }
    }
}

fn draw_release(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let rows = Layout::vertical([Constraint::Length(7), Constraint::Min(5)]).split(area);
    let bundle = app.selected_bundle().map(|bundle| {
        format!(
            "bundle #{} — {} bytes, ingested {}",
            bundle.id, bundle.total_len, bundle.ingested_at
        )
    });
    let marker = if app.focus == Field::ReleaseKey {
        ">"
    } else {
        " "
    };
    let form = Paragraph::new(vec![
        Line::from(
            "Calls release_at_event_end with the offline seal key and records the audit row.",
        ),
        Line::from(
            bundle.unwrap_or_else(|| "no bundle selected — choose a challenge first".to_owned()),
        ),
        Line::from(vec![
            Span::styled(
                format!("{marker} key file  "),
                if app.focus == Field::ReleaseKey {
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                },
            ),
            Span::raw(clip(&app.release_key, 80)),
        ]),
        Line::from(Span::styled(
            "Enter releases · Esc leaves the field",
            Style::default().fg(Color::DarkGray),
        )),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" seal release "),
    )
    .wrap(Wrap { trim: false });
    frame.render_widget(form, rows.first().copied().unwrap_or(area));

    let report = app
        .release_report
        .iter()
        .map(|line| Line::from(clip(line, 160)))
        .collect::<Vec<_>>();
    frame.render_widget(
        Paragraph::new(report)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" release report "),
            )
            .wrap(Wrap { trim: false }),
        rows.get(1).copied().unwrap_or(area),
    );
}

fn draw_verification(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let rows = app.verification_list.iter().map(|verification| {
        Row::new(vec![
            Cell::from(format!(
                "{} v{}",
                clip(&verification.slug, 28),
                verification.version
            )),
            Cell::from(status_span(Some(verification.status))),
            Cell::from(clip(&verification.reason, 80)),
            Cell::from(clip(&verification.checked_at, 26)),
        ])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(34),
            Constraint::Length(12),
            Constraint::Min(30),
            Constraint::Length(28),
        ],
    )
    .header(
        Row::new(vec!["challenge", "status", "reason", "checked"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" verification status "),
    )
    .column_spacing(1);

    if app.verification_list.is_empty() {
        frame.render_widget(
            Paragraph::new("No verification rows yet. Press r to refresh.")
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" verification status "),
                )
                .wrap(Wrap { trim: false }),
            area,
        );
    } else {
        frame.render_widget(table, area);
    }
}

fn draw_audit(frame: &mut Frame<'_>, area: Rect, app: &App) {
    // Stacked rather than side-by-side: an entitlement record is JSON and needs
    // the full width to stay readable, while the audit detail column benefits
    // from it too. Vertical space is cheap on the audit screen.
    let regions = Layout::vertical([Constraint::Min(10), Constraint::Length(9)]).split(area);
    let audit_rows = app.audit.iter().map(|row| {
        Row::new(vec![
            Cell::from(row.id.to_string()),
            Cell::from(clip(&row.at, 19)),
            Cell::from(clip(&row.actor, 12)),
            Cell::from(clip(&row.action, 22)),
            Cell::from(clip(&row.detail.to_string(), 60)),
        ])
    });
    frame.render_widget(
        Table::new(
            audit_rows,
            [
                Constraint::Length(6),
                Constraint::Length(20),
                Constraint::Length(13),
                Constraint::Length(23),
                Constraint::Min(30),
            ],
        )
        .header(
            Row::new(vec!["id", "at", "actor", "action", "detail"])
                .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .block(Block::default().borders(Borders::ALL).title(" audit log "))
        .column_spacing(1),
        regions.first().copied().unwrap_or(area),
    );

    let entitlement_rows = app.entitlements.iter().map(|row| {
        Row::new(vec![
            Cell::from(clip(&row.subject, 18)),
            Cell::from(row.seq.to_string()),
            Cell::from(clip(&row.record.to_string(), 48)),
            Cell::from(hex(&row.hash).get(..12).unwrap_or("-").to_owned()),
        ])
    });
    frame.render_widget(
        Table::new(
            entitlement_rows,
            [
                Constraint::Length(20),
                Constraint::Length(5),
                Constraint::Min(30),
                Constraint::Length(14),
            ],
        )
        .header(
            Row::new(vec!["subject", "seq", "record", "hash"])
                .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" entitlement / handoff chain "),
        )
        .column_spacing(1),
        regions.get(1).copied().unwrap_or(area),
    );
}

fn draw_footer(frame: &mut Frame<'_>, area: Rect, app: &App) {
    if let Some(error) = &app.error {
        let paragraph = Paragraph::new(clip(error, 400))
            .style(Style::default().fg(Color::White))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Red))
                    .title(" error "),
            )
            .wrap(Wrap { trim: false });
        frame.render_widget(paragraph, area);
        return;
    }
    let hints = format!(
        "Tab/Shift-Tab screens · j/k move · Enter act · r refresh · q quit    {}{}",
        if app.busy { "· busy " } else { "" },
        app.notice
            .as_ref()
            .map(|notice| format!("· {}", clip(notice, 80)))
            .unwrap_or_default()
    );
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            clip(&hints, 180),
            Style::default().fg(Color::DarkGray),
        ))),
        area,
    );
}

fn selected_style(selected: bool) -> Style {
    if selected {
        Style::default()
            .fg(Color::Black)
            .bg(Color::LightCyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    }
}

fn status_span(status: Option<Status>) -> Span<'static> {
    match status {
        Some(Status::Passed) => Span::styled("passed", Style::default().fg(Color::LightGreen)),
        Some(Status::Unverified) => Span::styled("unverified", Style::default().fg(Color::Yellow)),
        Some(Status::Failed) => Span::styled("failed", Style::default().fg(Color::LightRed)),
        Some(Status::Rejected) => Span::styled("rejected", Style::default().fg(Color::Magenta)),
        None => Span::styled("none", Style::default().fg(Color::DarkGray)),
    }
}

fn stage_index(stage: crate::model::Stage) -> usize {
    crate::model::Stage::ALL
        .iter()
        .position(|candidate| *candidate == stage)
        .unwrap_or(0)
}

/// Escape, then cut to `width` characters. Escaping first means a control character
/// counts as its visible escape sequence, never as a byte that can act on the
/// terminal.
fn clip(text: &str, width: usize) -> String {
    let escaped = escape_text(text);
    if escaped.chars().count() <= width {
        return escaped;
    }
    let mut out: String = escaped.chars().take(width.saturating_sub(1)).collect();
    out.push('…');
    out
}
