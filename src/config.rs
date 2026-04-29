use std::{fs, path::Path};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::{
    analysis,
    rules::{RuleBook, RuleSpec},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfigFile {
    #[serde(default)]
    pub daemon: DaemonConfig,
    #[serde(default)]
    pub cleanup_rules: Vec<analysis::CleanupRuleSpec>,
    #[serde(default)]
    pub phase_hints: Vec<RuleSpec>,
}

impl Default for AppConfigFile {
    fn default() -> Self {
        Self {
            daemon: DaemonConfig::default(),
            cleanup_rules: Vec::new(),
            phase_hints: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    #[serde(default = "default_daemon_host")]
    pub host: String,
    #[serde(default = "default_daemon_port")]
    pub port: u16,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            host: default_daemon_host(),
            port: default_daemon_port(),
        }
    }
}

impl DaemonConfig {
    pub fn socket_address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub daemon: DaemonConfig,
    pub cleanup_rules: Vec<analysis::CompiledCleanupRule>,
    pub phase_rules: RuleBook,
}

impl RuntimeConfig {
    pub fn load_or_create(path: &Path) -> Result<Self> {
        if !path.exists() {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).with_context(|| {
                    format!("failed to create config directory {}", parent.display())
                })?;
            }
            fs::write(path, default_config_template())
                .with_context(|| format!("failed to write default config to {}", path.display()))?;
        }

        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read config file at {}", path.display()))?;
        let file: AppConfigFile = serde_yaml::from_str(&contents)
            .with_context(|| format!("failed to parse config file at {}", path.display()))?;

        Ok(Self {
            daemon: file.daemon,
            cleanup_rules: analysis::compile_cleanup_rules(&file.cleanup_rules)?,
            phase_rules: RuleBook::from_phase_hints(&file.phase_hints)?,
        })
    }
}

fn default_daemon_host() -> String {
    "127.0.0.1".to_string()
}

fn default_daemon_port() -> u16 {
    41737
}

fn default_config_template() -> String {
    r#"# PwnJournal user config
#
# This file is intentionally small and editable.
# Add cleanup rules for harmless shell noise you do not want in write-ups.
# Add phase hints when your box has a weird personality and refuses to behave.

daemon:
  host: 127.0.0.1
  port: 41737

cleanup_rules:
  - match:
      - '^(pwd|clear|cls|history|ls|dir)$'
    reason: shell noise
  - match:
      - '^cd(\s+.*)?$'
    reason: navigation only

phase_hints:
  - match:
      - '\bffuf\b'
      - '\bgobuster\b'
    phase: Enumeration
    explanation: Directory fuzzing because the box clearly forgot to label its secrets.
  - match:
      - '\bsudo\s+-l\b'
      - '\bgetcap\b'
    phase: Privesc
    explanation: Local privilege escalation checks, the part where Linux starts pretending it was always this way.
"#
    .to_string()
}
