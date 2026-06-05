use std::io;
use std::time::Duration;

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame, Terminal,
};

use crate::app::{AppState, Shared, Status};

pub fn run(state: Shared) -> io::Result<()> {
    enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;

    let result = event_loop(&mut terminal, &state);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: &Shared,
) -> io::Result<()> {
    loop {
        terminal.draw(|f| render(f, &state.lock().unwrap()))?;

        if !event::poll(Duration::from_millis(40))? {
            continue;
        }

        let Event::Key(key) = event::read()? else { continue };
        if key.kind != KeyEventKind::Press {
            continue;
        }

        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);

        match key.code {
            KeyCode::Char('q') | KeyCode::Char('Q') => break,

            KeyCode::Up | KeyCode::Char('k') => state.lock().unwrap().move_up(),
            KeyCode::Down | KeyCode::Char('j') => state.lock().unwrap().move_down(),

            KeyCode::PageUp | KeyCode::Char('u') if ctrl => {
                state.lock().unwrap().scroll_up();
            }
            KeyCode::PageDown | KeyCode::Char('d') if ctrl => {
                state.lock().unwrap().scroll_down();
            }

            KeyCode::Char('f') | KeyCode::Char('F') => {
                state.lock().unwrap().forward_selected();
            }
            KeyCode::Char('d') | KeyCode::Char('D') if !ctrl => {
                state.lock().unwrap().drop_selected();
            }
            KeyCode::Char('a') | KeyCode::Char('A') => {
                state.lock().unwrap().forward_all_pending();
            }
            KeyCode::Char('e') | KeyCode::Char('E') => {
                open_editor(terminal, state)?;
            }

            _ => {}
        }
    }
    Ok(())
}

fn open_editor(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: &Shared,
) -> io::Result<()> {
    let (id, bytes) = {
        let s = state.lock().unwrap();
        match s.selected_req() {
            Some(r) if r.status == Status::Pending => {
                let b = r.edited.clone().unwrap_or_else(|| r.raw.clone());
                (r.id, b)
            }
            _ => return Ok(()),
        }
    };

    let tmp = "/tmp/rustman_edit.http";
    std::fs::write(tmp, &bytes)?;

    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;

    let editor = std::env::var("EDITOR")
        .or_else(|_| std::env::var("VISUAL"))
        .unwrap_or_else(|_| "vi".into());
    std::process::Command::new(&editor).arg(tmp).status()?;

    enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen)?;
    terminal.clear()?;

    let edited = std::fs::read(tmp)?;
    state.lock().unwrap().set_edited(id, edited);
    Ok(())
}

// ── Rendering ─────────────────────────────────────────────────────────────────

fn render(f: &mut Frame, state: &AppState) {
    let area = f.area();
    let rows = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .split(area);

    // ── Title ─────────────────────────────────────────────────────────────────
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                " rustman ",
                Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                " MITM Proxy  ·  proxy 127.0.0.1:8080  ·  HTTPS = tunnel (no cert needed)",
                Style::default().fg(Color::DarkGray),
            ),
        ])),
        rows[0],
    );

    // ── Body ──────────────────────────────────────────────────────────────────
    let cols = Layout::horizontal([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(rows[1]);

    draw_list(f, state, cols[0]);
    draw_detail(f, state, cols[1]);

    // ── Help bar ──────────────────────────────────────────────────────────────
    f.render_widget(
        Paragraph::new(Line::from(vec![
            kb("[F]"), Span::raw("orward  "),
            kb("[D]"), Span::raw("rop  "),
            kb("[A]"), Span::raw("ll  "),
            kb("[E]"), Span::raw("dit($EDITOR)  "),
            kb("[↑↓]"), Span::raw(" nav  "),
            kb("[PgUp/Dn]"), Span::raw(" scroll  "),
            kb("[Q]"), Span::raw("uit"),
        ])),
        rows[2],
    );
}

fn kb(s: &'static str) -> Span<'static> {
    Span::styled(s, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
}

fn draw_list(f: &mut Frame, state: &AppState, area: Rect) {
    let pending = state.requests.iter().filter(|r| r.status == Status::Pending).count();

    let items: Vec<ListItem> = state
        .requests
        .iter()
        .map(|r| {
            let (color, sym) = match r.status {
                Status::Pending   => (Color::Yellow,   "●"),
                Status::Forwarding => (Color::Cyan,    "→"),
                Status::Forwarded => (Color::Green,    "✓"),
                Status::Dropped   => (Color::Red,      "✗"),
                Status::Tunnel    => (Color::DarkGray, "⇌"),
            };
            let mark = if r.edited.is_some() { "*" } else { " " };
            let line = format!("{sym}{mark} {}", r.summary());
            ListItem::new(Span::styled(line, Style::default().fg(color)))
        })
        .collect();

    let mut ls = ListState::default();
    if !state.requests.is_empty() {
        ls.select(Some(state.selected));
    }

    f.render_stateful_widget(
        List::new(items)
            .block(
                Block::bordered()
                    .title(format!(" Requests  [{pending} pending] ")),
            )
            .highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD)),
        area,
        &mut ls,
    );
}

fn draw_detail(f: &mut Frame, state: &AppState, area: Rect) {
    let halves = Layout::vertical([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    draw_request(f, state, halves[0]);
    draw_response(f, state, halves[1]);
}

fn draw_request(f: &mut Frame, state: &AppState, area: Rect) {
    let (title, text, border_color) = match state.selected_req() {
        None => (
            " Request ".into(),
            "No request selected.\n\nPoint FoxyProxy (or any browser proxy) at 127.0.0.1:8080\nHTTP traffic will be intercepted here.\nHTTPS tunnels pass through automatically.".into(),
            Color::DarkGray,
        ),
        Some(r) => {
            let color = match r.status {
                Status::Pending    => Color::Yellow,
                Status::Forwarding => Color::Cyan,
                Status::Forwarded  => Color::Green,
                Status::Dropped    => Color::Red,
                Status::Tunnel     => Color::DarkGray,
            };
            let edited = if r.edited.is_some() { " [edited — F to send]" } else { "" };
            let t = format!(" {:?}{}  {}:{} ", r.status, edited, r.host, r.port);
            (t, r.display_text(), color)
        }
    };

    let lines: Vec<Line> = text
        .lines()
        .skip(state.scroll as usize)
        .map(|l| Line::raw(l.to_string()))
        .collect();

    f.render_widget(
        Paragraph::new(lines)
            .block(Block::bordered().title(title).border_style(Style::default().fg(border_color)))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_response(f: &mut Frame, state: &AppState, area: Rect) {
    let text = match state.selected_req() {
        Some(r) if r.response.is_some() => r.response_text(),
        Some(r) if r.status == Status::Pending || r.status == Status::Forwarding => {
            "Waiting for response…".into()
        }
        Some(r) if r.status == Status::Tunnel => {
            "HTTPS tunnel — content encrypted, not intercepted.\nInstall the CA cert to enable HTTPS interception.".into()
        }
        _ => String::new(),
    };

    // Rough scroll for response: offset by request line-count.
    let req_lines = state
        .selected_req()
        .map(|r| r.display_text().lines().count())
        .unwrap_or(0);
    let skip = (state.scroll as usize).saturating_sub(req_lines);

    let lines: Vec<Line> = text
        .lines()
        .skip(skip)
        .map(|l| Line::raw(l.to_string()))
        .collect();

    f.render_widget(
        Paragraph::new(lines)
            .block(Block::bordered().title(" Response ").border_style(Style::default().fg(Color::Blue)))
            .wrap(Wrap { trim: false }),
        area,
    );
}
