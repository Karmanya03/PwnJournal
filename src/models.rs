use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Ord,
    PartialOrd,
    Serialize,
    Deserialize,
    ValueEnum,
    Default,
)]
#[serde(rename_all = "PascalCase")]
pub enum Phase {
    Scanning,
    Enumeration,
    Web,
    Exploitation,
    Privesc,
    Loot,
    #[default]
    Unknown,
}

impl Phase {
    pub const ORDERED: [Phase; 7] = [
        Phase::Scanning,
        Phase::Enumeration,
        Phase::Web,
        Phase::Exploitation,
        Phase::Privesc,
        Phase::Loot,
        Phase::Unknown,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Phase::Scanning => "Scanning",
            Phase::Enumeration => "Enumeration",
            Phase::Web => "Web",
            Phase::Exploitation => "Exploitation",
            Phase::Privesc => "Privesc",
            Phase::Loot => "Loot",
            Phase::Unknown => "Other",
        }
    }

    pub fn short_label(self) -> &'static str {
        match self {
            Phase::Scanning => "Scan",
            Phase::Enumeration => "Enum",
            Phase::Web => "Web",
            Phase::Exploitation => "Exploit",
            Phase::Privesc => "PrivEsc",
            Phase::Loot => "Loot",
            Phase::Unknown => "Other",
        }
    }

    pub fn summary(self) -> &'static str {
        match self {
            Phase::Scanning => "We used discovery tooling to map the exposed attack surface.",
            Phase::Enumeration => {
                "We enumerated service details, directories, and application structure."
            }
            Phase::Web => "We focused on HTTP inputs, request crafting, and web-specific abuse.",
            Phase::Exploitation => "We converted the findings into a foothold or shell path.",
            Phase::Privesc => "We looked for local escalation paths and permission mistakes.",
            Phase::Loot => "We captured proof artifacts and verified the final flags.",
            Phase::Unknown => {
                "This command did not match a known phase and was kept as supporting context."
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum, Default)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    #[default]
    Htb,
    Thm,
}

impl Platform {
    pub fn label(self) -> &'static str {
        match self {
            Platform::Htb => "HTB",
            Platform::Thm => "THM",
        }
    }

    pub fn folder(self) -> &'static str {
        self.label()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum, Default)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    #[default]
    Active,
    Paused,
}

impl SessionStatus {
    pub fn label(self) -> &'static str {
        match self {
            SessionStatus::Active => "ACTIVE",
            SessionStatus::Paused => "PAUSED",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntrySource {
    Hook,
    Manual,
    Replay,
    Imported,
}

impl Default for EntrySource {
    fn default() -> Self {
        EntrySource::Hook
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandEntry {
    pub timestamp: DateTime<Utc>,
    pub cwd: String,
    pub command: String,
    pub box_name: String,
    #[serde(default)]
    pub platform: Platform,
    #[serde(default)]
    pub phase: Phase,
    #[serde(default)]
    pub explanation: Option<String>,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub flags: Vec<String>,
    #[serde(default)]
    pub source: EntrySource,
}

impl CommandEntry {
    pub fn short_command(&self, limit: usize) -> String {
        shorten(&self.command, limit)
    }

    pub fn short_cwd(&self, limit: usize) -> String {
        shorten(&self.cwd, limit)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoxMetadata {
    pub name: String,
    #[serde(default)]
    pub platform: Platform,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub started_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub stopped_at: Option<DateTime<Utc>>,
}

impl Default for BoxMetadata {
    fn default() -> Self {
        Self {
            name: String::new(),
            platform: Platform::default(),
            ip: None,
            tags: Vec::new(),
            notes: None,
            started_at: None,
            stopped_at: None,
        }
    }
}

impl BoxMetadata {
    pub fn new(name: impl Into<String>, platform: Platform, ip: Option<String>) -> Self {
        Self {
            name: name.into(),
            platform,
            ip,
            tags: Vec::new(),
            notes: None,
            started_at: None,
            stopped_at: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    pub box_name: String,
    pub platform: Platform,
    #[serde(default)]
    pub ip: Option<String>,
    pub started_at: DateTime<Utc>,
    #[serde(default)]
    pub status: SessionStatus,
    #[serde(default)]
    pub paused_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub paused_seconds: i64,
}

impl SessionState {
    pub fn is_active(&self) -> bool {
        matches!(self.status, SessionStatus::Active)
    }

    pub fn is_paused(&self) -> bool {
        matches!(self.status, SessionStatus::Paused)
    }

    pub fn label(&self) -> &'static str {
        self.status.label()
    }

    pub fn pause(&mut self, now: DateTime<Utc>) {
        if self.is_active() {
            self.status = SessionStatus::Paused;
            self.paused_at = Some(now);
        }
    }

    pub fn resume(&mut self, now: DateTime<Utc>) {
        if let Some(paused_at) = self.paused_at.take() {
            let paused_delta = now.signed_duration_since(paused_at);
            self.paused_seconds += paused_delta.num_seconds().max(0);
        }
        self.status = SessionStatus::Active;
    }

    pub fn effective_elapsed(&self, now: DateTime<Utc>) -> Duration {
        let mut elapsed = now.signed_duration_since(self.started_at);
        elapsed -= Duration::seconds(self.paused_seconds.max(0));

        if let Some(paused_at) = self.paused_at {
            if self.is_paused() {
                elapsed -= now.signed_duration_since(paused_at);
            }
        }

        elapsed.max(Duration::zero())
    }
}

#[derive(Debug, Clone)]
pub struct BoxSummary {
    pub metadata: BoxMetadata,
    pub command_count: usize,
    pub last_command_at: Option<DateTime<Utc>>,
    pub phase_counts: BTreeMap<Phase, usize>,
    pub flags: Vec<String>,
    pub session: Option<SessionState>,
    pub active: bool,
}

impl BoxSummary {
    pub fn duration(&self, now: DateTime<Utc>) -> Option<Duration> {
        if let Some(session) = &self.session {
            return Some(session.effective_elapsed(now));
        }

        let start = self.metadata.started_at?;
        let end = self.metadata.stopped_at.unwrap_or(now);
        Some((end - start).max(Duration::zero()))
    }

    pub fn session_status_label(&self) -> &'static str {
        self.session
            .as_ref()
            .map(SessionState::label)
            .unwrap_or("idle")
    }

    pub fn phase_counts_compact(&self) -> String {
        Phase::ORDERED
            .iter()
            .map(|phase| {
                let count = self.phase_counts.get(phase).copied().unwrap_or(0);
                format!("{}:{}", phase.short_label(), count)
            })
            .collect::<Vec<_>>()
            .join("  ")
    }
}

fn shorten(value: &str, limit: usize) -> String {
    let mut output = String::new();
    for (index, ch) in value.chars().enumerate() {
        if index >= limit {
            output.push_str("...");
            return output;
        }
        output.push(ch);
    }
    output
}
