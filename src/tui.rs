use std::{
    io::{self, Stdout},
    time::{Duration, Instant},
};

use anyhow::Result;
use chrono::{Local, Utc};
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    prelude::*,
    widgets::{
        BarChart, Block, BorderType, Borders, Gauge, List, ListItem, ListState, Paragraph, Wrap,
    },
};

use crate::{
    analysis,
    journal::{BoxLocation, PwnJournal},
    models::{BoxSummary, CommandEntry, Phase},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UiMode {
    Dashboard,
    Replay,
}

pub fn run_dashboard(journal: PwnJournal, location: BoxLocation) -> Result<()> {
    run_tui(journal, location, UiMode::Dashboard)
}

pub fn run_replay(journal: PwnJournal, location: BoxLocation) -> Result<()> {
    run_tui(journal, location, UiMode::Replay)
}

fn run_tui(journal: PwnJournal, location: BoxLocation, mode: UiMode) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;

    let guard = TerminalGuard;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let mut app = App::new(journal, location, mode)?;

    let result = app.run(&mut terminal);
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    drop(guard);
    result
}

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let mut stdout = io::stdout();
        let _ = execute!(stdout, LeaveAlternateScreen);
    }
}

struct App {
    journal: PwnJournal,
    location: BoxLocation,
    summary: BoxSummary,
    entries: Vec<CommandEntry>,
    selected: usize,
    mode: UiMode,
    should_quit: bool,
    follow: bool,
    playing: bool,
    speed: f64,
    next_auto_advance: Instant,
    last_refresh: Instant,
}

impl App {
    fn new(journal: PwnJournal, location: BoxLocation, mode: UiMode) -> Result<Self> {
        let summary = journal.summary_for_location(&location)?;
        let entries = journal.read_entries(&location)?;
        let selected = match mode {
            UiMode::Dashboard => entries.len().saturating_sub(1),
            UiMode::Replay => 0,
        };

        Ok(Self {
            journal,
            location,
            summary,
            entries,
            selected,
            mode,
            should_quit: false,
            follow: mode == UiMode::Dashboard,
            playing: mode == UiMode::Replay,
            speed: 1.0,
            next_auto_advance: Instant::now() + Duration::from_millis(900),
            last_refresh: Instant::now(),
        })
    }

    fn run(&mut self, terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
        while !self.should_quit {
            terminal.draw(|frame| self.render(frame))?;
            self.tick()?;

            if event::poll(Duration::from_millis(120))? {
                if let Event::Key(key) = event::read()? {
                    self.handle_key(key.code, key.modifiers);
                }
            }
        }

        Ok(())
    }

    fn tick(&mut self) -> Result<()> {
        if self.follow && self.last_refresh.elapsed() >= Duration::from_millis(900) {
            self.reload()?;
            self.last_refresh = Instant::now();
        }

        if self.mode == UiMode::Replay && self.playing {
            if self.entries.len() > 1
                && self.selected < self.entries.len() - 1
                && Instant::now() >= self.next_auto_advance
            {
                self.selected += 1;
                self.next_auto_advance = Instant::now() + self.replay_delay_for(self.selected);
            }
        }

        Ok(())
    }

    fn reload(&mut self) -> Result<()> {
        let previous_len = self.entries.len();
        let keep_last = self.selected + 1 == previous_len;

        self.summary = self.journal.summary_for_location(&self.location)?;
        self.entries = self.journal.read_entries(&self.location)?;

        if self.entries.is_empty() {
            self.selected = 0;
        } else if keep_last {
            self.selected = self.entries.len() - 1;
        } else {
            self.selected = self.selected.min(self.entries.len() - 1);
        }

        Ok(())
    }

    fn handle_key(&mut self, code: KeyCode, modifiers: KeyModifiers) {
        match (self.mode, code, modifiers) {
            (_, KeyCode::Char('q'), _) | (_, KeyCode::Esc, _) => self.should_quit = true,
            (UiMode::Dashboard, KeyCode::Down, _) | (UiMode::Dashboard, KeyCode::Char('j'), _) => {
                self.select_next()
            }
            (UiMode::Dashboard, KeyCode::Up, _) | (UiMode::Dashboard, KeyCode::Char('k'), _) => {
                self.select_previous()
            }
            (UiMode::Dashboard, KeyCode::Home, _)
            | (UiMode::Dashboard, KeyCode::Char('g'), KeyModifiers::SHIFT) => self.selected = 0,
            (UiMode::Dashboard, KeyCode::End, _) | (UiMode::Dashboard, KeyCode::Char('G'), _) => {
                self.selected = self.entries.len().saturating_sub(1)
            }
            (UiMode::Dashboard, KeyCode::Char('r'), _) => {
                let _ = self.reload();
            }
            (UiMode::Dashboard, KeyCode::Char('f'), _) => {
                self.follow = !self.follow;
            }
            (UiMode::Dashboard, KeyCode::Char('p'), _) => {
                self.toggle_session();
            }
            (UiMode::Dashboard, KeyCode::Char('x'), _) => {
                self.stop_session();
            }
            (UiMode::Replay, KeyCode::Char(' '), _) => {
                self.playing = !self.playing;
                self.next_auto_advance = Instant::now() + self.replay_delay_for(self.selected);
            }
            (UiMode::Replay, KeyCode::Right, _) | (UiMode::Replay, KeyCode::Char('l'), _) => {
                self.step_forward()
            }
            (UiMode::Replay, KeyCode::Left, _) | (UiMode::Replay, KeyCode::Char('h'), _) => {
                self.step_backward()
            }
            (UiMode::Replay, KeyCode::Up, _) => self.speed_up(),
            (UiMode::Replay, KeyCode::Down, _) => self.speed_down(),
            (UiMode::Replay, KeyCode::Char('+'), _) | (UiMode::Replay, KeyCode::Char('='), _) => {
                self.speed_up()
            }
            (UiMode::Replay, KeyCode::Char('-'), _) => self.speed_down(),
            (UiMode::Replay, KeyCode::Home, _)
            | (UiMode::Replay, KeyCode::Char('g'), KeyModifiers::SHIFT) => self.selected = 0,
            (UiMode::Replay, KeyCode::End, _) | (UiMode::Replay, KeyCode::Char('G'), _) => {
                self.selected = self.entries.len().saturating_sub(1)
            }
            (UiMode::Replay, KeyCode::Char('r'), _) => {
                let _ = self.reload();
            }
            _ => {}
        }

        self.selected = self.selected.min(self.entries.len().saturating_sub(1));
    }

    fn select_next(&mut self) {
        if self.selected + 1 < self.entries.len() {
            self.selected += 1;
        }
    }

    fn select_previous(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    fn step_forward(&mut self) {
        self.selected = (self.selected + 1).min(self.entries.len().saturating_sub(1));
        self.next_auto_advance = Instant::now() + self.replay_delay_for(self.selected);
    }

    fn step_backward(&mut self) {
        self.selected = self.selected.saturating_sub(1);
        self.next_auto_advance = Instant::now() + self.replay_delay_for(self.selected);
    }

    fn speed_up(&mut self) {
        self.speed = (self.speed * 1.25).min(8.0);
    }

    fn speed_down(&mut self) {
        self.speed = (self.speed / 1.25).max(0.25);
    }

    fn replay_delay_for(&self, index: usize) -> Duration {
        if self.entries.len() < 2 || index >= self.entries.len() - 1 {
            return Duration::from_millis(900);
        }

        let current = self.entries[index].timestamp;
        let next = self.entries[index + 1].timestamp;
        let delta = next
            .signed_duration_since(current)
            .num_milliseconds()
            .max(300) as f64;
        let adjusted = (delta / self.speed.max(0.25)).round() as u64;
        Duration::from_millis(adjusted.clamp(180, 8_000))
    }

    fn render(&self, frame: &mut Frame<'_>) {
        let root = Layout::default()
            .direction(Direction::Vertical)
            .constraints(
                [
                    Constraint::Length(3),
                    Constraint::Min(14),
                    Constraint::Length(3),
                ]
                .as_ref(),
            )
            .split(frame.area());

        self.render_header(frame, root[0]);

        let body = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(
                [
                    Constraint::Length(38),
                    Constraint::Min(46),
                    Constraint::Length(40),
                ]
                .as_ref(),
            )
            .split(root[1]);

        self.render_session_panel(frame, body[0]);
        self.render_timeline_panel(frame, body[1]);
        self.render_detail_panel(frame, body[2]);

        self.render_footer(frame, root[2]);
    }

    fn render_header(&self, frame: &mut Frame<'_>, area: Rect) {
        let mut lines = Vec::new();
        let status = self.summary.session_status_label();
        let title = Span::styled(
            " PwnJournal ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
        let subtitle = Span::styled(
            format!(
                " {} / {} / {} commands / {} ",
                self.location.platform.label(),
                self.summary.metadata.name,
                self.entries.len(),
                status
            ),
            Style::default().fg(Color::Cyan),
        );
        lines.push(Line::from(vec![title, Span::raw("  "), subtitle]));

        if let Some(ip) = self.summary.metadata.ip.as_ref() {
            lines.push(Line::from(Span::styled(
                format!(" target: {} ", ip),
                Style::default().fg(Color::Green),
            )));
        } else {
            lines.push(Line::from(Span::styled(
                " target: not set ",
                Style::default().fg(Color::DarkGray),
            )));
        }

        let block = Block::default()
            .title(Span::styled(
                " dashboard ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .style(Style::default().bg(Color::Rgb(11, 14, 20)));
        let paragraph = Paragraph::new(lines).block(block);
        frame.render_widget(paragraph, area);
    }

    fn render_session_panel(&self, frame: &mut Frame<'_>, area: Rect) {
        let mut body = Vec::new();
        body.push(Line::from(vec![
            Span::styled("status:", label_style()),
            Span::styled(
                format!(" {}", self.summary.session_status_label()),
                Self::status_style(self.summary.session_status_label()),
            ),
        ]));
        body.push(Line::from(vec![
            Span::styled("platform:", label_style()),
            Span::raw(format!(" {}", self.summary.metadata.platform.label())),
        ]));
        body.push(Line::from(vec![
            Span::styled("box:", label_style()),
            Span::raw(format!(" {}", self.summary.metadata.name)),
        ]));
        body.push(Line::from(vec![
            Span::styled("commands:", label_style()),
            Span::raw(format!(" {}", self.summary.command_count)),
        ]));
        body.push(Line::from(vec![
            Span::styled("phases:", label_style()),
            Span::raw(format!(" {}", self.summary.phase_counts_compact())),
        ]));

        if let Some(duration) = self.summary.duration(Utc::now()) {
            body.push(Line::from(vec![
                Span::styled("session:", label_style()),
                Span::raw(format!(" {}m", duration.num_minutes())),
            ]));
        }

        if !self.summary.flags.is_empty() {
            body.push(Line::from(vec![
                Span::styled("flags:", label_style()),
                Span::raw(format!(" {}", self.summary.flags.join(", "))),
            ]));
        }

        let list = Paragraph::new(body)
            .block(panel_block("session"))
            .wrap(Wrap { trim: true });
        frame.render_widget(list, area);
    }

    fn render_timeline_panel(&self, frame: &mut Frame<'_>, area: Rect) {
        if self.entries.is_empty() {
            frame.render_widget(
                Paragraph::new("no commands logged yet")
                    .block(panel_block("timeline"))
                    .style(dim_style()),
                area,
            );
            return;
        }

        let (start, end) = visible_window(self.entries.len(), self.selected, 12);
        let window = &self.entries[start..end];
        let items: Vec<ListItem<'_>> = window
            .iter()
            .map(|entry| {
                let local_time = entry
                    .timestamp
                    .with_timezone(&Local)
                    .format("%H:%M:%S")
                    .to_string();
                let phase = Span::styled(
                    format!("[{}]", entry.phase.short_label()),
                    phase_style(entry.phase),
                );
                let command =
                    Span::styled(entry.short_command(40), Style::default().fg(Color::White));
                let time = Span::styled(local_time, Style::default().fg(Color::DarkGray));

                let mut second_line = Vec::new();
                second_line.push(Span::styled(
                    format!("cwd: {}", entry.short_cwd(34)),
                    Style::default().fg(Color::DarkGray),
                ));
                if !entry.flags.is_empty() {
                    second_line.push(Span::raw("  "));
                    second_line.push(Span::styled(
                        format!("flags: {}", entry.flags.join(", ")),
                        Style::default().fg(Color::Yellow),
                    ));
                }

                ListItem::new(Text::from(vec![
                    Line::from(vec![time, Span::raw(" "), phase, Span::raw(" "), command]),
                    Line::from(second_line),
                ]))
            })
            .collect();

        let mut state = ListState::default();
        state.select(Some(self.selected.saturating_sub(start)));

        let list = List::new(items)
            .block(panel_block("timeline"))
            .highlight_style(
                Style::default()
                    .bg(Color::Rgb(24, 28, 38))
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol(">> ");

        frame.render_stateful_widget(list, area, &mut state);
    }

    fn render_detail_panel(&self, frame: &mut Frame<'_>, area: Rect) {
        let panel = panel_block(match self.mode {
            UiMode::Dashboard => "details",
            UiMode::Replay => "replay",
        });

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(
                [
                    Constraint::Length(12),
                    Constraint::Min(8),
                    Constraint::Length(7),
                ]
                .as_ref(),
            )
            .split(area);

        let detail_text = if let Some(entry) = self.entries.get(self.selected) {
            let mut lines = vec![
                Line::from(vec![
                    Span::styled("phase:", label_style()),
                    Span::raw(format!(" {}", entry.phase.label())),
                ]),
                Line::from(vec![
                    Span::styled("cwd:", label_style()),
                    Span::raw(format!(" {}", entry.cwd)),
                ]),
                Line::from(vec![
                    Span::styled("time:", label_style()),
                    Span::raw(format!(
                        " {}",
                        entry
                            .timestamp
                            .with_timezone(&Local)
                            .format("%Y-%m-%d %H:%M:%S")
                    )),
                ]),
                Line::from(vec![
                    Span::styled("explanation:", label_style()),
                    Span::raw(format!(
                        " {}",
                        entry
                            .explanation
                            .clone()
                            .unwrap_or_else(|| entry.phase.summary().to_string())
                    )),
                ]),
            ];

            if !entry.ports.is_empty() {
                lines.push(Line::from(vec![
                    Span::styled("ports:", label_style()),
                    Span::raw(format!(
                        " {}",
                        entry
                            .ports
                            .iter()
                            .map(|port| port.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )),
                ]));
            }
            if let Some(ip) = &entry.ip {
                lines.push(Line::from(vec![
                    Span::styled("ip:", label_style()),
                    Span::raw(format!(" {}", ip)),
                ]));
            }
            if !entry.flags.is_empty() {
                lines.push(Line::from(vec![
                    Span::styled("flags:", label_style()),
                    Span::raw(format!(" {}", entry.flags.join(", "))),
                ]));
            }
            if analysis::is_critical(&entry.command) {
                lines.push(Line::from(vec![
                    Span::styled("note:", label_style()),
                    Span::styled(" critical one-liner", Style::default().fg(Color::Red)),
                ]));
            }

            Paragraph::new(lines).block(panel).wrap(Wrap { trim: true })
        } else {
            Paragraph::new("select a command to inspect it here")
                .block(panel)
                .style(dim_style())
        };
        frame.render_widget(detail_text, chunks[0]);

        let chart_data = build_phase_chart(&self.summary);
        let chart = BarChart::default()
            .block(panel_block("phase distribution"))
            .data(&chart_data)
            .bar_width(6)
            .bar_gap(1)
            .value_style(Style::default().fg(Color::White))
            .bar_style(Style::default().fg(Color::Cyan))
            .label_style(Style::default().fg(Color::DarkGray));
        frame.render_widget(chart, chunks[1]);

        let footer_text = if self.mode == UiMode::Replay {
            format!(
                "{} / {}  speed x{:.2}  {}",
                self.selected + 1,
                self.entries.len(),
                self.speed,
                if self.playing { "playing" } else { "paused" }
            )
        } else {
            format!(
                "{} / {}  live {}",
                self.selected + 1,
                self.entries.len(),
                if self.follow { "on" } else { "off" }
            )
        };

        let progress = if self.entries.len() <= 1 {
            0.0
        } else {
            self.selected as f64 / (self.entries.len() - 1) as f64
        };

        let gauge = Gauge::default()
            .block(panel_block("status"))
            .gauge_style(Style::default().fg(Color::Green).bg(Color::Rgb(18, 20, 28)))
            .ratio(progress)
            .label(Span::styled(footer_text, Style::default().fg(Color::White)));
        frame.render_widget(gauge, chunks[2]);
    }

    fn render_footer(&self, frame: &mut Frame<'_>, area: Rect) {
        let help = match self.mode {
            UiMode::Dashboard => {
                "q quit  j/k move  g/G jump  r refresh  f follow  p pause/resume  x stop"
            }
            UiMode::Replay => "q quit  space play/pause  h/l step  +/- speed  r refresh",
        };

        let footer = Paragraph::new(help)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .style(Style::default().bg(Color::Rgb(11, 14, 20)))
                    .title(Span::styled(" controls ", Style::default().fg(Color::Cyan))),
            )
            .style(Style::default().fg(Color::DarkGray));
        frame.render_widget(footer, area);
    }
}

fn panel_block(title: &str) -> Block<'static> {
    Block::default()
        .title(Span::styled(
            format!(" {} ", title),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .style(Style::default().bg(Color::Rgb(11, 14, 20)))
}

fn label_style() -> Style {
    Style::default()
        .fg(Color::DarkGray)
        .add_modifier(Modifier::BOLD)
}

fn dim_style() -> Style {
    Style::default().fg(Color::DarkGray)
}

fn phase_style(phase: Phase) -> Style {
    match phase {
        Phase::Scanning => Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
        Phase::Enumeration => Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
        Phase::Web => Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD),
        Phase::Exploitation => Style::default()
            .fg(Color::Magenta)
            .add_modifier(Modifier::BOLD),
        Phase::Privesc => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        Phase::Loot => Style::default()
            .fg(Color::LightGreen)
            .add_modifier(Modifier::BOLD),
        Phase::Unknown => Style::default()
            .fg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    }
}

fn build_phase_chart(summary: &BoxSummary) -> [(&'static str, u64); 7] {
    [
        (
            Phase::Scanning.short_label(),
            summary
                .phase_counts
                .get(&Phase::Scanning)
                .copied()
                .unwrap_or(0) as u64,
        ),
        (
            Phase::Enumeration.short_label(),
            summary
                .phase_counts
                .get(&Phase::Enumeration)
                .copied()
                .unwrap_or(0) as u64,
        ),
        (
            Phase::Web.short_label(),
            summary.phase_counts.get(&Phase::Web).copied().unwrap_or(0) as u64,
        ),
        (
            Phase::Exploitation.short_label(),
            summary
                .phase_counts
                .get(&Phase::Exploitation)
                .copied()
                .unwrap_or(0) as u64,
        ),
        (
            Phase::Privesc.short_label(),
            summary
                .phase_counts
                .get(&Phase::Privesc)
                .copied()
                .unwrap_or(0) as u64,
        ),
        (
            Phase::Loot.short_label(),
            summary.phase_counts.get(&Phase::Loot).copied().unwrap_or(0) as u64,
        ),
        (
            Phase::Unknown.short_label(),
            summary
                .phase_counts
                .get(&Phase::Unknown)
                .copied()
                .unwrap_or(0) as u64,
        ),
    ]
}

fn visible_window(total: usize, selected: usize, max_items: usize) -> (usize, usize) {
    if total <= max_items {
        return (0, total);
    }

    let half = max_items / 2;
    let start = selected.saturating_sub(half);
    let end = (start + max_items).min(total);
    let start = end.saturating_sub(max_items);
    (start, end)
}

impl App {
    fn toggle_session(&mut self) {
        let box_name = Some(self.location.display_name.as_str());
        let platform = Some(self.location.platform);
        let result = if self
            .summary
            .session
            .as_ref()
            .is_some_and(|session| session.is_paused())
        {
            self.journal.resume_box(box_name, platform)
        } else {
            self.journal.pause_box(box_name, platform)
        };

        if let Ok(summary) = result {
            self.summary = summary;
            let _ = self.reload();
        }
    }

    fn stop_session(&mut self) {
        if let Ok(summary) = self.journal.stop_box(
            Some(&self.location.display_name),
            Some(self.location.platform),
        ) {
            self.summary = summary;
            self.follow = false;
            self.playing = false;
            let _ = self.reload();
        }
    }

    fn status_style(status: &str) -> Style {
        match status {
            "ACTIVE" => Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
            "PAUSED" => Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
            _ => Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        }
    }
}
