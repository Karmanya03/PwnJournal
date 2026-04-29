use std::{fs, path::Path};

use anyhow::{Context, Result};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

use crate::models::Phase;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleFile {
    #[serde(default)]
    pub rules: Vec<RuleSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSpec {
    #[serde(rename = "match")]
    pub matches: Vec<String>,
    pub phase: Phase,
    pub explanation: String,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    regexes: Vec<Regex>,
    phase: Phase,
    explanation: String,
}

#[derive(Debug, Clone)]
pub struct RuleBook {
    rules: Vec<CompiledRule>,
}

impl RuleBook {
    pub fn builtin() -> Self {
        Self {
            rules: compile_specs(&builtin_rule_specs())
                .expect("builtin rule patterns must compile"),
        }
    }

    pub fn from_phase_hints(custom_specs: &[RuleSpec]) -> Result<Self> {
        let mut specs = custom_specs.to_vec();
        specs.extend(builtin_rule_specs());

        Ok(Self {
            rules: compile_specs(&specs)?,
        })
    }

    pub fn load(path: &Path) -> Result<Self> {
        let mut specs = builtin_rule_specs();

        if path.exists() {
            let contents = fs::read_to_string(path)
                .with_context(|| format!("failed to read rules file at {}", path.display()))?;
            let file: RuleFile = serde_yaml::from_str(&contents)
                .with_context(|| format!("failed to parse YAML rules at {}", path.display()))?;
            let mut custom = file.rules;
            custom.append(&mut specs);
            specs = custom;
        }

        Ok(Self {
            rules: compile_specs(&specs)?,
        })
    }

    pub fn classify(&self, command: &str) -> Option<(Phase, String)> {
        self.rules.iter().find_map(|rule| {
            if rule.regexes.iter().any(|regex| regex.is_match(command)) {
                Some((rule.phase, rule.explanation.clone()))
            } else {
                None
            }
        })
    }
}

fn compile_specs(specs: &[RuleSpec]) -> Result<Vec<CompiledRule>> {
    specs
        .iter()
        .map(|spec| {
            let regexes = spec
                .matches
                .iter()
                .map(|pattern| {
                    RegexBuilder::new(pattern)
                        .case_insensitive(true)
                        .build()
                        .with_context(|| format!("failed to compile rule regex `{}`", pattern))
                })
                .collect::<Result<Vec<_>>>()?;

            Ok(CompiledRule {
                regexes,
                phase: spec.phase,
                explanation: spec.explanation.clone(),
            })
        })
        .collect()
}

fn builtin_rule_specs() -> Vec<RuleSpec> {
    vec![
        RuleSpec {
            matches: vec![r"\b(nmap|rustscan|masscan|naabu|unicornscan|arp-scan)\b".into()],
            phase: Phase::Scanning,
            explanation: "Port scanning to discover exposed services and map the attack surface.".into(),
        },
        RuleSpec {
            matches: vec![r"\b(gobuster|ffuf|feroxbuster|dirsearch|whatweb|nikto|wfuzz|httpx)\b".into()],
            phase: Phase::Enumeration,
            explanation: "Enumeration of directories, service banners, and application structure.".into(),
        },
        RuleSpec {
            matches: vec![r"\b(sqlmap|burp|jwt|csrf|xss|lfi|rfi|sqli|request|cookie|webshell)\b".into(), r"https?://".into()],
            phase: Phase::Web,
            explanation: "Focused HTTP interaction or web-specific abuse against the application surface.".into(),
        },
        RuleSpec {
            matches: vec![r"\b(python3?\s+-c|perl\s+-e|bash\s+-c|bash\s+-i|nc\s+-e|socat\b|mkfifo\b)".into()],
            phase: Phase::Exploitation,
            explanation: "One-liner payload or pivot chain used to gain or stabilize a shell.".into(),
        },
        RuleSpec {
            matches: vec![r"\b(sudo|getcap|find\s+/.+-perm|linpeas|pspy|pkexec|suid|capsh|writable\s+cron)\b".into()],
            phase: Phase::Privesc,
            explanation: "Privilege-escalation enumeration and local permission abuse.".into(),
        },
        RuleSpec {
            matches: vec![r"\b(flag\{[^}]+\}|HTB\{[^}]+\}|THM\{[^}]+\}|cat\s+.*flag|grep\s+.*flag|root\.txt|user\.txt)\b".into()],
            phase: Phase::Loot,
            explanation: "Loot capture and final flag verification.".into(),
        },
    ]
}
