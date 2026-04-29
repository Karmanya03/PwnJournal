use std::{borrow::Cow, collections::BTreeSet};

use chrono::Duration;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::models::CommandEntry;
use crate::{models::Phase, rules::RuleBook};

static IPV4_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").expect("valid IPv4 regex"));
static FLAG_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\b(?:flag|htb|thm)\{[^}\s]+\}").expect("valid flag regex"));
static PORT_LIST_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:-p|--ports?)\s+([0-9,\-\/]+)").expect("valid port-list regex")
});
static PORT_TCP_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(\d{2,5})/(?:tcp|udp)\b").expect("valid nmap port regex"));
static PORT_COLON_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r":(\d{2,5})\b").expect("valid colon port regex"));
static SHELL_NOISE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?ix)^
        (?:
            pwd|
            clear|
            cls|
            history|
            reset|
            stty\s+sane|
            jobs|
            fg|
            bg|
            alias|
            unalias|
            exit|
            cd(?:\s+[^;&|]+)?|
            pushd(?:\s+[^;&|]+)?|
            popd(?:\s+[^;&|]+)?|
            ls|
            dir
        )
    \s*$",
    )
    .expect("valid shell noise regex")
});

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanupRuleSpec {
    #[serde(rename = "match")]
    pub matches: Vec<String>,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct CompiledCleanupRule {
    regexes: Vec<Regex>,
    pub reason: String,
}

static CRITICAL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(python3?\s+-c|perl\s+-e|bash\s+-c|bash\s+-i|nc\s+-e|socat\b|mkfifo\b|base64\s+-d|openssl\s+enc\b|sudo\s+-l\b|getcap\b|find\s+/.+-perm\b|chmod\s+u\+s\b)")
        .expect("valid critical-command regex")
});

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DropReason {
    ShellNoise,
    ExactDuplicate,
    Custom(String),
}

impl DropReason {
    pub fn label(&self) -> Cow<'_, str> {
        match self {
            DropReason::ShellNoise => Cow::Borrowed("shell noise"),
            DropReason::ExactDuplicate => Cow::Borrowed("duplicate"),
            DropReason::Custom(reason) => Cow::Borrowed(reason.as_str()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RemovedCommand {
    pub command: String,
    pub reason: DropReason,
}

#[derive(Debug, Clone)]
pub struct CleanupReport {
    pub kept: Vec<CommandEntry>,
    pub removed: Vec<RemovedCommand>,
}

pub fn compile_cleanup_rules(
    specs: &[CleanupRuleSpec],
) -> anyhow::Result<Vec<CompiledCleanupRule>> {
    specs
        .iter()
        .map(|spec| {
            let regexes = spec
                .matches
                .iter()
                .map(|pattern| {
                    Regex::new(pattern).map_err(|error| {
                        anyhow::anyhow!("failed to compile cleanup regex `{}`: {}", pattern, error)
                    })
                })
                .collect::<anyhow::Result<Vec<_>>>()?;

            Ok(CompiledCleanupRule {
                regexes,
                reason: spec.reason.clone(),
            })
        })
        .collect()
}

#[derive(Debug, Clone)]
pub struct CommandAnalysis {
    pub phase: Phase,
    pub explanation: String,
    pub ips: Vec<String>,
    pub ports: Vec<u16>,
    pub flags: Vec<String>,
    pub critical: bool,
    pub highlights: Vec<String>,
}

pub fn analyze(command: &str, rules: &RuleBook, explicit_phase: Option<Phase>) -> CommandAnalysis {
    let (phase, explanation) = match explicit_phase {
        Some(phase) => {
            let explanation = rules
                .classify(command)
                .map(|(_, explanation)| explanation)
                .unwrap_or_else(|| phase.summary().to_string());
            (phase, explanation)
        }
        None => rules
            .classify(command)
            .unwrap_or_else(|| (Phase::Unknown, Phase::Unknown.summary().to_string())),
    };

    let ips = extract_ips(command);
    let ports = extract_ports(command);
    let flags = extract_flags(command);
    let critical = is_critical(command);

    let mut highlights = Vec::new();
    if critical {
        highlights.push("Critical one-liner".to_string());
    }
    if command.contains("-p-") {
        highlights.push("Full port sweep".to_string());
    }
    if !ips.is_empty() {
        highlights.push(format!("IPs: {}", ips.join(", ")));
    }
    if !ports.is_empty() {
        highlights.push(format!("Ports: {}", join_ports(&ports)));
    }
    if !flags.is_empty() {
        highlights.push(format!("Flags: {}", flags.join(", ")));
    }

    CommandAnalysis {
        phase,
        explanation,
        ips,
        ports,
        flags,
        critical,
        highlights,
    }
}

pub fn is_critical(command: &str) -> bool {
    CRITICAL_RE.is_match(command)
}

pub fn noise_reason(command: &str) -> Option<DropReason> {
    let trimmed = command.trim();
    if trimmed.is_empty() || SHELL_NOISE_RE.is_match(trimmed) {
        Some(DropReason::ShellNoise)
    } else {
        None
    }
}

pub fn cleanup_entries(entries: &[CommandEntry]) -> CleanupReport {
    let mut kept = Vec::with_capacity(entries.len());
    let mut removed = Vec::new();

    for entry in entries {
        if let Some(reason) = noise_reason(&entry.command) {
            removed.push(RemovedCommand {
                command: entry.command.clone(),
                reason,
            });
            continue;
        }

        if let Some(previous) = kept.last() {
            if is_duplicate(previous, entry) {
                removed.push(RemovedCommand {
                    command: entry.command.clone(),
                    reason: DropReason::ExactDuplicate,
                });
                continue;
            }
        }

        kept.push(entry.clone());
    }

    CleanupReport { kept, removed }
}

pub fn cleanup_entries_with_rules(
    entries: &[CommandEntry],
    custom_rules: &[CompiledCleanupRule],
) -> CleanupReport {
    let mut kept = Vec::with_capacity(entries.len());
    let mut removed = Vec::new();

    for entry in entries {
        if let Some(rule) = custom_cleanup_reason(&entry.command, custom_rules) {
            removed.push(RemovedCommand {
                command: entry.command.clone(),
                reason: DropReason::Custom(rule),
            });
            continue;
        }

        if let Some(reason) = noise_reason(&entry.command) {
            removed.push(RemovedCommand {
                command: entry.command.clone(),
                reason,
            });
            continue;
        }

        if let Some(previous) = kept.last() {
            if is_duplicate(previous, entry) {
                removed.push(RemovedCommand {
                    command: entry.command.clone(),
                    reason: DropReason::ExactDuplicate,
                });
                continue;
            }
        }

        kept.push(entry.clone());
    }

    CleanupReport { kept, removed }
}

fn extract_ips(command: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();

    for ip in IPV4_RE.find_iter(command).map(|m| m.as_str()) {
        if is_valid_ipv4(ip) {
            seen.insert(ip.to_string());
        }
    }

    seen.into_iter().collect()
}

fn extract_flags(command: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    for flag in FLAG_RE.find_iter(command).map(|m| m.as_str()) {
        seen.insert(flag.to_string());
    }
    seen.into_iter().collect()
}

fn extract_ports(command: &str) -> Vec<u16> {
    let mut ports = BTreeSet::new();

    for capture in PORT_LIST_RE.captures_iter(command) {
        if let Some(matched) = capture.get(1) {
            add_port_segment(matched.as_str(), &mut ports);
        }
    }

    for capture in PORT_TCP_RE.captures_iter(command) {
        if let Ok(port) = capture[1].parse::<u16>() {
            if port > 0 {
                ports.insert(port);
            }
        }
    }

    for capture in PORT_COLON_RE.captures_iter(command) {
        if let Ok(port) = capture[1].parse::<u16>() {
            if port > 0 {
                ports.insert(port);
            }
        }
    }

    ports.into_iter().collect()
}

fn add_port_segment(segment: &str, ports: &mut BTreeSet<u16>) {
    for token in segment.split([',', '/']) {
        let token = token.trim();
        if token.is_empty() || token == "-" {
            continue;
        }

        if let Some((start, end)) = token.split_once('-') {
            if let (Ok(start), Ok(end)) = (start.trim().parse::<u16>(), end.trim().parse::<u16>()) {
                let range_start = start.min(end);
                let range_end = start.max(end);
                for port in range_start..=range_end {
                    if port > 0 {
                        ports.insert(port);
                    }
                }
            }
            continue;
        }

        if let Ok(port) = token.parse::<u16>() {
            if port > 0 {
                ports.insert(port);
            }
        }
    }
}

fn join_ports(ports: &[u16]) -> String {
    ports
        .iter()
        .map(|port| port.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn is_valid_ipv4(value: &str) -> bool {
    value
        .split('.')
        .filter_map(|octet| octet.parse::<u16>().ok())
        .all(|octet| octet <= 255)
}

fn is_duplicate(previous: &CommandEntry, current: &CommandEntry) -> bool {
    previous.cwd == current.cwd
        && previous.command.trim() == current.command.trim()
        && current.timestamp.signed_duration_since(previous.timestamp) <= Duration::seconds(30)
}

fn custom_cleanup_reason(command: &str, custom_rules: &[CompiledCleanupRule]) -> Option<String> {
    custom_rules.iter().find_map(|rule| {
        if rule.regexes.iter().any(|regex| regex.is_match(command)) {
            Some(rule.reason.clone())
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RuleBook;
    use chrono::Utc;

    #[test]
    fn detects_scanning_phase_and_signals() {
        let rules = RuleBook::builtin();
        let result = analyze("nmap -sC -sV -p 22,80 10.10.10.10", &rules, None);

        assert_eq!(result.phase, Phase::Scanning);
        assert!(result.ips.contains(&"10.10.10.10".to_string()));
        assert!(result.ports.contains(&22));
        assert!(result.ports.contains(&80));
    }

    #[test]
    fn detects_flag_and_critical() {
        let rules = RuleBook::builtin();
        let result = analyze("python3 -c 'print(\"HTB{demo}\")'", &rules, None);

        assert!(result.critical);
        assert!(result.flags.contains(&"HTB{demo}".to_string()));
    }

    #[test]
    fn cleanup_filters_noise_and_duplicates() {
        use chrono::TimeZone;

        let entries = vec![
            CommandEntry {
                timestamp: Utc.with_ymd_and_hms(2026, 4, 29, 10, 0, 0).unwrap(),
                cwd: "/home/kali".into(),
                command: "pwd".into(),
                box_name: "Demo".into(),
                platform: crate::models::Platform::Htb,
                phase: Phase::Unknown,
                explanation: None,
                ip: None,
                ports: vec![],
                flags: vec![],
                source: crate::models::EntrySource::Hook,
            },
            CommandEntry {
                timestamp: Utc.with_ymd_and_hms(2026, 4, 29, 10, 0, 5).unwrap(),
                cwd: "/home/kali".into(),
                command: "nmap -sV 10.10.10.10".into(),
                box_name: "Demo".into(),
                platform: crate::models::Platform::Htb,
                phase: Phase::Scanning,
                explanation: None,
                ip: None,
                ports: vec![],
                flags: vec![],
                source: crate::models::EntrySource::Hook,
            },
            CommandEntry {
                timestamp: Utc.with_ymd_and_hms(2026, 4, 29, 10, 0, 15).unwrap(),
                cwd: "/home/kali".into(),
                command: "nmap -sV 10.10.10.10".into(),
                box_name: "Demo".into(),
                platform: crate::models::Platform::Htb,
                phase: Phase::Scanning,
                explanation: None,
                ip: None,
                ports: vec![],
                flags: vec![],
                source: crate::models::EntrySource::Hook,
            },
        ];

        let report = cleanup_entries_with_rules(&entries, &[]);
        assert_eq!(report.kept.len(), 1);
        assert_eq!(report.removed.len(), 2);
    }
}
