use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use ratatui::Frame;

use crate::collector::{self, Snapshot};
use crate::error::TraceletError;
use crate::filter::FilterArgs;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Focus {
    Stream,
    Top,
}

struct Ui {
    focus: Focus,
    stream: ListState,
    top: ListState,
    paused: bool,
}

impl Ui {
    fn new() -> Ui {
        let mut stream = ListState::default();
        stream.select(Some(0));
        let mut top = ListState::default();
        top.select(Some(0));
        Ui {
            focus: Focus::Stream,
            stream,
            top,
            paused: false,
        }
    }

    fn scroll(&mut self, up: bool, amount: u16) {
        let state = match self.focus {
            Focus::Stream => &mut self.stream,
            Focus::Top => &mut self.top,
        };
        if up {
            state.scroll_up_by(amount);
        } else {
            state.scroll_down_by(amount);
        }
    }

    fn jump(&mut self, to_end: bool) {
        let state = match self.focus {
            Focus::Stream => &mut self.stream,
            Focus::Top => &mut self.top,
        };
        if to_end {
            state.select(Some(usize::MAX));
        } else {
            state.select(Some(0));
        }
    }

    fn toggle_focus(&mut self) {
        self.focus = match self.focus {
            Focus::Stream => Focus::Top,
            Focus::Top => Focus::Stream,
        };
    }

    fn apply(&mut self, action: KeyAction) {
        match action {
            KeyAction::None | KeyAction::Quit => {}
            KeyAction::TogglePause => self.paused = !self.paused,
            KeyAction::ScrollUp => self.scroll(true, 1),
            KeyAction::ScrollDown => self.scroll(false, 1),
            KeyAction::PageUp => self.scroll(true, 15),
            KeyAction::PageDown => self.scroll(false, 15),
            KeyAction::First => self.jump(false),
            KeyAction::Last => self.jump(true),
            KeyAction::NextPane => self.toggle_focus(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyAction {
    None,
    Quit,
    TogglePause,
    ScrollUp,
    ScrollDown,
    PageUp,
    PageDown,
    First,
    Last,
    NextPane,
}

fn key_action(key: KeyEvent) -> KeyAction {
    if key.kind == KeyEventKind::Release {
        return KeyAction::None;
    }
    let repeated = key.kind == KeyEventKind::Repeat;
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return KeyAction::Quit;
    }
    let action = match key.code {
        KeyCode::Char('q') => Some(KeyAction::Quit),
        KeyCode::Char(' ') => Some(KeyAction::TogglePause),
        KeyCode::Up => Some(KeyAction::ScrollUp),
        KeyCode::Down => Some(KeyAction::ScrollDown),
        KeyCode::PageUp => Some(KeyAction::PageUp),
        KeyCode::PageDown => Some(KeyAction::PageDown),
        KeyCode::Home => Some(KeyAction::First),
        KeyCode::End => Some(KeyAction::Last),
        KeyCode::Tab | KeyCode::BackTab => Some(KeyAction::NextPane),
        _ => None,
    };
    match (action, repeated) {
        (Some(KeyAction::TogglePause | KeyAction::Quit | KeyAction::NextPane), true) => {
            KeyAction::None
        }
        (Some(action), _) => action,
        (None, _) => KeyAction::None,
    }
}

const KEYS: &str =
    "space pause | up/down scroll | pgup/pgdn page | home newest | end oldest | tab focus | q quit";

fn stream_rows(snap: &Snapshot) -> (Vec<String>, usize) {
    let total = snap.stream.len();
    let rows: Vec<String> = snap
        .stream
        .iter()
        .map(|row| {
            format!(
                "{:<12} {:<7} {:<16} {:<8} {}",
                row.wall, row.pid, row.process, row.event, row.details
            )
        })
        .collect();
    (rows, total)
}

fn draw(f: &mut Frame<'_>, snap: &Snapshot, ui: &Ui) {
    let root = Layout::vertical([
        Constraint::Length(6),
        Constraint::Length(9),
        Constraint::Min(6),
        Constraint::Length(3),
    ])
    .split(f.area());

    let o = &snap.overview;
    let overview = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("events/s ", Style::new().fg(Color::DarkGray)),
            Span::raw(format!("{:<6}", o.rate)),
            Span::styled("processes ", Style::new().fg(Color::DarkGray)),
            Span::raw(format!("{:<6}", o.processes)),
            Span::styled("tcp ", Style::new().fg(Color::DarkGray)),
            Span::raw(format!("{:<6}", o.tcp_total)),
            Span::styled("file ", Style::new().fg(Color::DarkGray)),
            Span::raw(format!("{:<6}", o.file_total)),
            Span::styled("dropped ", Style::new().fg(Color::DarkGray)),
            Span::raw(format!("{}", o.dropped)),
        ]),
        Line::from(format!(
            "state: {}",
            if ui.paused { "PAUSED" } else { "live" }
        )),
        Line::styled(KEYS, Style::new().fg(Color::DarkGray)),
    ])
    .block(Block::new().borders(Borders::ALL).title("overview"));
    f.render_widget(overview, root[0]);

    let mix = if snap.distribution.is_empty() {
        "no events yet".to_string()
    } else {
        snap.distribution
            .iter()
            .map(|(name, count)| format!("{name} {count}"))
            .collect::<Vec<_>>()
            .join("  ")
    };
    let mut latency_lines: Vec<Line<'_>> = if snap.latency.is_empty() {
        vec![Line::from("no latency samples")]
    } else {
        snap.latency
            .iter()
            .map(|(name, s)| {
                Line::from(format!(
                    "{:<7} n {:>7}  p50 {:>9}  p95 {:>9}  p99 {:>9}",
                    name,
                    s.count,
                    crate::hist::format_ns(s.p50),
                    crate::hist::format_ns(s.p95),
                    crate::hist::format_ns(s.p99)
                ))
            })
            .collect()
    };
    latency_lines.push(Line::from(""));
    latency_lines.push(Line::from(Span::styled(
        mix,
        Style::new().fg(Color::DarkGray),
    )));
    f.render_widget(
        Paragraph::new(latency_lines).block(
            Block::new()
                .borders(Borders::ALL)
                .title("latency (syscall service time)"),
        ),
        root[1],
    );

    let stream_focus = ui.focus == Focus::Stream;
    let (rows, total) = stream_rows(snap);
    let stream_items: Vec<ListItem<'_>> = rows
        .iter()
        .map(|row| ListItem::from(Span::raw(row.clone())))
        .collect();
    let stream_title = format!(
        "events {}{}",
        total,
        if total > rows.len() { "+" } else { "" }
    );
    f.render_stateful_widget(
        List::new(stream_items)
            .block(
                Block::new()
                    .borders(Borders::ALL)
                    .border_style(if stream_focus {
                        Style::new().fg(Color::Cyan)
                    } else {
                        Style::new()
                    })
                    .title(stream_title),
            )
            .highlight_style(
                Style::new()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            ),
        root[2],
        &mut ui.stream.clone(),
    );

    let top_focus = ui.focus == Focus::Top;
    let top_items: Vec<ListItem<'_>> = snap
        .top
        .iter()
        .map(|row| {
            ListItem::from(Span::raw(format!(
                "{:<16} pid {:<7} {:>8}",
                row.process, row.pid, row.count
            )))
        })
        .collect();
    f.render_stateful_widget(
        List::new(top_items)
            .block(
                Block::new()
                    .borders(Borders::ALL)
                    .border_style(if top_focus {
                        Style::new().fg(Color::Cyan)
                    } else {
                        Style::new()
                    })
                    .title("top processes"),
            )
            .highlight_style(
                Style::new()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            ),
        root[3],
        &mut ui.top.clone(),
    );
}

pub fn run(args: &FilterArgs, buffer_mb: u32) -> Result<(), TraceletError> {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        ratatui::restore();
        default_hook(info);
    }));

    let shared = collector::spawn(args, buffer_mb)?;
    let mut terminal = ratatui::init();
    let result = event_loop(&mut terminal, &shared);
    ratatui::restore();
    result
}

fn event_loop(
    terminal: &mut ratatui::DefaultTerminal,
    shared: &Arc<Mutex<collector::Shared>>,
) -> Result<(), TraceletError> {
    let mut ui = Ui::new();
    let mut last = Instant::now() - Duration::from_secs(2);
    loop {
        if !crate::RUNNING.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(());
        }
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                let action = key_action(key);
                if action != KeyAction::None {
                    ui.apply(action);
                    last = Instant::now();
                    if action == KeyAction::Quit {
                        return Ok(());
                    }
                    let guard = shared.lock().unwrap();
                    let snap = Snapshot::take(&guard);
                    terminal.draw(|f| draw(f, &snap, &ui))?;
                    continue;
                }
            }
        }
        if !ui.paused && last.elapsed() >= Duration::from_secs(1) {
            last = Instant::now();
            let guard = shared.lock().unwrap();
            let snap = Snapshot::take(&guard);
            terminal.draw(|f| draw(f, &snap, &ui))?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{key_action, stream_rows, KeyAction, Ui};
    use crate::collector::{self, Snapshot};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn sample_snapshot() -> Snapshot {
        Snapshot {
            overview: collector::Overview {
                rate: 3,
                processes: 2,
                tcp_total: 1,
                file_total: 2,
                dropped: 0,
            },
            stream: vec![collector::StreamRow {
                wall: "12:00:00.000".into(),
                pid: 42,
                process: "bash".into(),
                event: "EXEC",
                details: "/bin/ls".into(),
            }],
            top: vec![collector::TopRow {
                process: "bash".into(),
                pid: 42,
                count: 2,
            }],
            distribution: vec![("EXEC".to_string(), 1)],
            latency: vec![],
        }
    }

    #[test]
    fn keys_map_to_actions() {
        let press =
            |code, modifiers| key_action(ratatui::crossterm::event::KeyEvent::new(code, modifiers));
        use ratatui::crossterm::event::{KeyCode, KeyModifiers};
        assert_eq!(
            press(KeyCode::Char('q'), KeyModifiers::NONE),
            KeyAction::Quit
        );
        assert_eq!(
            press(KeyCode::Char('c'), KeyModifiers::CONTROL),
            KeyAction::Quit
        );
        assert_eq!(
            press(KeyCode::Char(' '), KeyModifiers::NONE),
            KeyAction::TogglePause
        );
        assert_eq!(press(KeyCode::Tab, KeyModifiers::NONE), KeyAction::NextPane);
        assert_eq!(press(KeyCode::Up, KeyModifiers::NONE), KeyAction::ScrollUp);
    }

    #[test]
    fn ui_toggles_pause_and_focus() {
        let mut ui = Ui::new();
        assert!(!ui.paused);
        ui.apply(KeyAction::TogglePause);
        assert!(ui.paused);
        ui.apply(KeyAction::NextPane);
        assert_eq!(ui.focus, super::Focus::Top);
    }

    #[test]
    fn stream_rows_format_all_columns() {
        let (rows, total) = stream_rows(&sample_snapshot());
        assert_eq!(total, 1);
        assert!(rows[0].contains("12:00:00.000"));
        assert!(rows[0].contains("42"));
        assert!(rows[0].contains("bash"));
        assert!(rows[0].contains("EXEC"));
        assert!(rows[0].contains("/bin/ls"));
    }

    #[test]
    fn draw_renders_all_panes() {
        let ui = Ui::new();
        let snap = sample_snapshot();
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).expect("test terminal");
        terminal.draw(|f| super::draw(f, &snap, &ui)).expect("draw");
        let text = terminal.backend().to_string();
        assert!(text.contains("overview"));
        assert!(text.contains("latency"));
        assert!(text.contains("events 1"));
        assert!(text.contains("top processes"));
        assert!(text.contains("/bin/ls"));
        assert!(text.contains("state: live"));
    }
}
