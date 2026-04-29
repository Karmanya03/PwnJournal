use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use comfy_table::{Attribute, Cell, Color, Table, presets::UTF8_FULL};

use crate::{
    daemon,
    journal::{LogOutcome, LogSpec, PruneReport, PwnJournal, ShellKind, StartSpec},
    models::{EntrySource, Phase, Platform},
    tui,
};

#[derive(Debug, Parser)]
#[command(
    name = "pwnj",
    version,
    about = "CTF-aware command logger and write-up generator"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    Start {
        box_name: String,
        #[arg(long)]
        ip: Option<String>,
        #[arg(long, value_enum, default_value_t = Platform::Htb)]
        platform: Platform,
    },
    Stop {
        box_name: Option<String>,
        #[arg(long, value_enum)]
        platform: Option<Platform>,
    },
    Pause {
        box_name: Option<String>,
        #[arg(long, value_enum)]
        platform: Option<Platform>,
    },
    Resume {
        box_name: Option<String>,
        #[arg(long, value_enum)]
        platform: Option<Platform>,
    },
    Log {
        #[arg(long = "box")]
        box_name: Option<String>,
        #[arg(long, value_enum)]
        platform: Option<Platform>,
        #[arg(long)]
        ip: Option<String>,
        #[arg(long, value_enum)]
        phase: Option<Phase>,
        #[arg(long)]
        command: String,
        #[arg(long)]
        cwd: Option<PathBuf>,
    },
    Prune {
        box_name: Option<String>,
        #[arg(long, value_enum)]
        platform: Option<Platform>,
        #[arg(long)]
        apply: bool,
    },
    List,
    Writeup {
        box_name: Option<String>,
        #[arg(long, value_enum)]
        platform: Option<Platform>,
        #[arg(long)]
        stdout: bool,
    },
    Journal {
        box_name: Option<String>,
        #[arg(long, value_enum)]
        platform: Option<Platform>,
    },
    Replay {
        box_name: Option<String>,
        #[arg(long, value_enum)]
        platform: Option<Platform>,
    },
    Hook {
        #[arg(value_enum)]
        shell: ShellKindArg,
    },
    Daemon,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ShellKindArg {
    Zsh,
    Bash,
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    let journal = PwnJournal::new()?;

    match cli.command {
        Commands::Start {
            box_name,
            ip,
            platform,
        } => {
            let summary = journal.start_box(StartSpec {
                box_name: box_name.clone(),
                platform,
                ip,
            })?;
            print_box_summary("Started", &summary);
            Ok(())
        }
        Commands::Stop { box_name, platform } => {
            let summary = journal.stop_box(box_name.as_deref(), platform)?;
            print_box_summary("Stopped", &summary);
            Ok(())
        }
        Commands::Pause { box_name, platform } => {
            let summary = journal.pause_box(box_name.as_deref(), platform)?;
            print_box_summary("Paused", &summary);
            Ok(())
        }
        Commands::Resume { box_name, platform } => {
            let summary = journal.resume_box(box_name.as_deref(), platform)?;
            print_box_summary("Resumed", &summary);
            Ok(())
        }
        Commands::Log {
            box_name,
            platform,
            ip,
            phase,
            command,
            cwd,
        } => {
            let cwd = cwd
                .unwrap_or(std::env::current_dir().context("failed to resolve current directory")?);
            let source = match std::env::var("PWNJOURNAL_SOURCE") {
                Ok(value) if value.eq_ignore_ascii_case("hook") => EntrySource::Hook,
                Ok(value) if value.eq_ignore_ascii_case("replay") => EntrySource::Replay,
                _ => EntrySource::Manual,
            };
            match journal.log_command(LogSpec {
                box_name,
                platform,
                ip,
                phase,
                command,
                cwd,
                source,
            })? {
                LogOutcome::Recorded(entry) => {
                    println!(
                        "logged {} [{}] -> {}",
                        entry.timestamp.format("%Y-%m-%d %H:%M:%S"),
                        entry.phase.label(),
                        entry.box_name
                    );
                }
                LogOutcome::Skipped { reason } => {
                    println!("skipped: {}", reason);
                }
            }
            Ok(())
        }
        Commands::Prune {
            box_name,
            platform,
            apply,
        } => {
            let report = journal.prune_box(box_name.as_deref(), platform, apply)?;
            print_prune_report(&report, apply);
            Ok(())
        }
        Commands::List => {
            print_box_list(&journal)?;
            Ok(())
        }
        Commands::Writeup {
            box_name,
            platform,
            stdout,
        } => {
            let location = journal.resolve_existing_box(box_name.as_deref(), platform)?;
            let rendered = journal.writeup(&location)?;
            if stdout {
                print!("{}", rendered.markdown);
            }
            println!(
                "wrote {} ({} commands) to {}",
                location.display_name,
                rendered.stats.visible_command_count,
                rendered.path.display()
            );
            Ok(())
        }
        Commands::Journal { box_name, platform } => {
            let location = journal.resolve_existing_box(box_name.as_deref(), platform)?;
            tui::run_dashboard(journal, location)
        }
        Commands::Replay { box_name, platform } => {
            let location = journal.resolve_existing_box(box_name.as_deref(), platform)?;
            tui::run_replay(journal, location)
        }
        Commands::Hook { shell } => {
            let shell = match shell {
                ShellKindArg::Zsh => ShellKind::Zsh,
                ShellKindArg::Bash => ShellKind::Bash,
            };
            print!("{}", journal.shell_hook(shell));
            Ok(())
        }
        Commands::Daemon => daemon::run(&journal),
    }
}

fn print_box_summary(action: &str, summary: &crate::models::BoxSummary) {
    let now = chrono::Utc::now();
    let started = summary
        .metadata
        .started_at
        .map(|value| value.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "-".into());
    let stopped = summary
        .metadata
        .stopped_at
        .map(|value| value.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "-".into());

    println!(
        "{} {} on {}",
        action,
        summary.metadata.name,
        summary.metadata.platform.label()
    );
    println!("  status   : {}", summary.session_status_label());
    println!("  commands : {}", summary.command_count);
    println!("  started  : {}", started);
    println!("  stopped  : {}", stopped);
    println!("  phases   : {}", summary.phase_counts_compact());
    if let Some(duration) = summary.duration(now) {
        println!("  elapsed  : {}m", duration.num_minutes().max(0));
    }
    if !summary.flags.is_empty() {
        println!("  flags    : {}", summary.flags.join(", "));
    }
    if let Some(ip) = &summary.metadata.ip {
        println!("  ip       : {}", ip);
    }
}

fn print_box_list(journal: &PwnJournal) -> Result<()> {
    let summaries = journal.list_boxes()?;
    if summaries.is_empty() {
        println!("no boxes logged yet. use `pwnj start <box>` first.");
        return Ok(());
    }

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec![
        "Platform",
        "Box",
        "Commands",
        "Last Seen",
        "Phases",
        "Flags",
        "Status",
    ]);

    for summary in summaries {
        let last_seen = summary
            .last_command_at
            .map(|value| value.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "-".into());
        let status = summary.session_status_label();
        let status_cell = if summary.active {
            Cell::new(status)
                .fg(Color::Green)
                .add_attribute(Attribute::Bold)
        } else if status == "PAUSED" {
            Cell::new(status)
                .fg(Color::Yellow)
                .add_attribute(Attribute::Bold)
        } else {
            Cell::new(status).fg(Color::DarkGrey)
        };

        table.add_row(vec![
            Cell::new(summary.metadata.platform.label()).fg(Color::Cyan),
            Cell::new(summary.metadata.name.clone()).fg(Color::White),
            Cell::new(summary.command_count).fg(Color::Yellow),
            Cell::new(last_seen).fg(Color::DarkGrey),
            Cell::new(summary.phase_counts_compact()).fg(Color::Magenta),
            Cell::new(if summary.flags.is_empty() {
                "-".into()
            } else {
                summary.flags.join(", ")
            })
            .fg(Color::Blue),
            status_cell,
        ]);
    }

    println!("{}", table);
    Ok(())
}

fn print_prune_report(report: &PruneReport, applied: bool) {
    println!(
        "commands: {} -> {}",
        report.original_count, report.kept_count
    );
    println!(
        "removed: {} low-signal, {} duplicate",
        report.removed_noise_count, report.removed_duplicate_count
    );
    if let Some(path) = &report.backup_path {
        println!("backup: {}", path.display());
    }
    if !report.sample_removed.is_empty() {
        println!("sample removals:");
        for item in &report.sample_removed {
            println!("  - {}", item);
        }
    }
    println!("mode: {}", if applied { "applied" } else { "preview" });
}
