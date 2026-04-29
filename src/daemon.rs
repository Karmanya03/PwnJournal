use std::{
    io::{BufRead, BufReader},
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    thread,
};

use anyhow::{Context, Result, anyhow};

use crate::{
    journal::{LogSpec, PwnJournal},
    models::EntrySource,
};

pub fn run(journal: &PwnJournal) -> Result<()> {
    let address = journal.config.daemon.socket_address();
    let listener = TcpListener::bind(&address)
        .with_context(|| format!("failed to bind daemon on {}", address))?;

    println!("pwnj daemon listening on {}", address);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let journal = journal.clone();
                thread::spawn(move || {
                    if let Err(error) = handle_client(journal, stream) {
                        eprintln!("daemon client error: {error:#}");
                    }
                });
            }
            Err(error) => {
                eprintln!("daemon accept error: {error:#}");
            }
        }
    }

    Ok(())
}

fn handle_client(journal: PwnJournal, stream: TcpStream) -> Result<()> {
    let peer = stream
        .peer_addr()
        .ok()
        .map(format_address)
        .unwrap_or_else(|| "unknown".to_string());
    let mut reader = BufReader::new(stream);
    let mut line = String::new();

    loop {
        line.clear();
        let bytes = reader
            .read_line(&mut line)
            .with_context(|| format!("failed to read daemon payload from {peer}"))?;
        if bytes == 0 {
            break;
        }

        let payload = line.trim_end_matches(['\r', '\n']);
        if payload.is_empty() {
            continue;
        }

        match parse_message(payload)? {
            Message::Log { cwd, command } => {
                let outcome = journal.log_command(LogSpec {
                    box_name: None,
                    platform: None,
                    ip: None,
                    phase: None,
                    command,
                    cwd: PathBuf::from(cwd),
                    source: EntrySource::Hook,
                })?;

                match outcome {
                    crate::journal::LogOutcome::Recorded(entry) => {
                        println!(
                            "logged {} [{}] from {}",
                            entry.timestamp.format("%Y-%m-%d %H:%M:%S"),
                            entry.phase.label(),
                            peer
                        );
                    }
                    crate::journal::LogOutcome::Skipped { reason } => {
                        println!("skipped hook payload from {}: {}", peer, reason);
                    }
                }
            }
        }
    }

    Ok(())
}

#[derive(Debug)]
enum Message {
    Log { cwd: String, command: String },
}

fn parse_message(input: &str) -> Result<Message> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut escaped = false;

    for ch in input.chars() {
        if escaped {
            match ch {
                'n' => current.push('\n'),
                'r' => current.push('\r'),
                '|' => current.push('|'),
                '\\' => current.push('\\'),
                other => {
                    current.push('\\');
                    current.push(other);
                }
            }
            escaped = false;
            continue;
        }

        match ch {
            '\\' => escaped = true,
            '|' if parts.len() < 2 => {
                parts.push(current);
                current = String::new();
            }
            other => current.push(other),
        }
    }

    if escaped {
        current.push('\\');
    }

    parts.push(current);

    if parts.len() != 3 {
        return Err(anyhow!("invalid daemon payload: expected LOG|cwd|command"));
    }

    match parts[0].as_str() {
        "LOG" => Ok(Message::Log {
            cwd: parts[1].clone(),
            command: parts[2].clone(),
        }),
        other => Err(anyhow!("unsupported daemon message type: {}", other)),
    }
}

fn format_address(address: SocketAddr) -> String {
    address.to_string()
}
