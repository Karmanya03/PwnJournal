use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Utc};

use crate::{
    analysis,
    config::RuntimeConfig,
    models::{
        BoxMetadata, BoxSummary, CommandEntry, EntrySource, Phase, Platform, SessionState,
        SessionStatus,
    },
    writeup::{RenderedWriteup, render_markdown},
};

#[derive(Debug, Clone)]
pub struct JournalPaths {
    pub root: PathBuf,
    pub state_file: PathBuf,
    pub config_file: PathBuf,
}

#[derive(Debug, Clone)]
pub struct BoxLocation {
    pub platform: Platform,
    pub display_name: String,
    pub slug: String,
    pub dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct StartSpec {
    pub box_name: String,
    pub platform: Platform,
    pub ip: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LogSpec {
    pub box_name: Option<String>,
    pub platform: Option<Platform>,
    pub ip: Option<String>,
    pub phase: Option<Phase>,
    pub command: String,
    pub cwd: PathBuf,
    pub source: EntrySource,
}

#[derive(Debug, Clone)]
pub enum LogOutcome {
    Recorded(CommandEntry),
    Skipped { reason: String },
}

#[derive(Debug, Clone)]
pub struct PruneReport {
    pub original_count: usize,
    pub kept_count: usize,
    pub removed_noise_count: usize,
    pub removed_duplicate_count: usize,
    pub backup_path: Option<PathBuf>,
    pub sample_removed: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PwnJournal {
    pub paths: JournalPaths,
    pub config: RuntimeConfig,
}

impl PwnJournal {
    pub fn new() -> Result<Self> {
        let paths = JournalPaths::resolve()?;
        let config = RuntimeConfig::load_or_create(&paths.config_file)?;
        Ok(Self { paths, config })
    }

    pub fn active_session(&self) -> Result<Option<SessionState>> {
        read_json_if_exists(&self.paths.state_file)
    }

    pub fn start_box(&self, spec: StartSpec) -> Result<BoxSummary> {
        let location = self.ensure_box_location(spec.platform, &spec.box_name)?;
        let now = Utc::now();
        let mut metadata = self.load_metadata(&location)?;
        metadata.name = spec.box_name.clone();
        metadata.platform = spec.platform;
        if spec.ip.is_some() {
            metadata.ip = spec.ip.clone();
        }
        if metadata.started_at.is_none() {
            metadata.started_at = Some(now);
        }
        metadata.stopped_at = None;

        let mut session = match self.active_session()? {
            Some(session)
                if session.box_name == spec.box_name && session.platform == spec.platform =>
            {
                session
            }
            _ => SessionState {
                box_name: spec.box_name.clone(),
                platform: spec.platform,
                ip: spec.ip.clone(),
                started_at: now,
                status: SessionStatus::Active,
                paused_at: None,
                paused_seconds: 0,
            },
        };

        if session.is_paused() {
            session.resume(now);
        }
        if spec.ip.is_some() {
            session.ip = spec.ip.clone();
        }

        self.save_metadata(&location, &metadata)?;
        self.save_session(&session)?;
        self.summary_for_location(&location)
    }

    pub fn pause_box(
        &self,
        box_name: Option<&str>,
        platform: Option<Platform>,
    ) -> Result<BoxSummary> {
        let location = self.resolve_existing_box(box_name, platform)?;
        let mut session = self.current_session_for_location(&location)?;
        session.pause(Utc::now());
        self.save_session(&session)?;
        self.summary_for_location(&location)
    }

    pub fn resume_box(
        &self,
        box_name: Option<&str>,
        platform: Option<Platform>,
    ) -> Result<BoxSummary> {
        let location = self.resolve_existing_box(box_name, platform)?;
        let mut session = self.current_session_for_location(&location)?;
        session.resume(Utc::now());
        self.save_session(&session)?;
        self.summary_for_location(&location)
    }

    pub fn stop_box(
        &self,
        box_name: Option<&str>,
        platform: Option<Platform>,
    ) -> Result<BoxSummary> {
        self.stop_location(box_name, platform, Utc::now())
    }

    pub fn log_command(&self, spec: LogSpec) -> Result<LogOutcome> {
        let location = match self.resolve_log_location(spec.box_name.as_deref(), spec.platform) {
            Ok(location) => location,
            Err(error) => {
                if spec.box_name.is_none() {
                    return Ok(LogOutcome::Skipped {
                        reason: "no active session".to_string(),
                    });
                }
                return Err(error);
            }
        };

        if let Some(session) = self.active_session()? {
            if session.box_name == location.display_name
                && session.platform == location.platform
                && session.is_paused()
            {
                return Ok(LogOutcome::Skipped {
                    reason: format!("session `{}` is paused", session.box_name),
                });
            }
        }

        if matches!(spec.source, EntrySource::Hook) {
            if let Some(reason) = analysis::noise_reason(&spec.command) {
                return Ok(LogOutcome::Skipped {
                    reason: reason.label().to_string(),
                });
            }
        }

        let metadata = self.load_metadata(&location)?;
        let analysis = analysis::analyze(&spec.command, &self.config.phase_rules, spec.phase);
        let ip = spec
            .ip
            .or(metadata.ip.clone())
            .or_else(|| analysis.ips.first().cloned());

        let entry = CommandEntry {
            timestamp: Utc::now(),
            cwd: spec.cwd.to_string_lossy().to_string(),
            command: spec.command,
            box_name: metadata.name.clone(),
            platform: location.platform,
            phase: analysis.phase,
            explanation: Some(analysis.explanation),
            ip: ip.clone(),
            ports: analysis.ports,
            flags: analysis.flags,
            source: spec.source,
        };

        self.append_entry(&location, &entry)?;

        if metadata.ip.is_none() && ip.is_some() {
            let mut updated = metadata.clone();
            updated.ip = ip;
            self.save_metadata(&location, &updated)?;
        }

        Ok(LogOutcome::Recorded(entry))
    }

    pub fn prune_box(
        &self,
        box_name: Option<&str>,
        platform: Option<Platform>,
        apply: bool,
    ) -> Result<PruneReport> {
        let location = self.resolve_existing_box(box_name, platform)?;
        let entries = self.read_entries(&location)?;
        let cleanup = analysis::cleanup_entries_with_rules(&entries, &self.config.cleanup_rules);

        let removed_noise_count = cleanup
            .removed
            .iter()
            .filter(|removed| matches!(removed.reason, analysis::DropReason::ShellNoise))
            .count();
        let removed_duplicate_count = cleanup
            .removed
            .iter()
            .filter(|removed| matches!(removed.reason, analysis::DropReason::ExactDuplicate))
            .count();

        let mut backup_path = None;
        if apply {
            let commands_path = self.commands_path(&location);
            if commands_path.exists() {
                let backup = self.backup_commands_path(&location);
                fs::copy(&commands_path, &backup).with_context(|| {
                    format!(
                        "failed to back up {} to {}",
                        commands_path.display(),
                        backup.display()
                    )
                })?;
                backup_path = Some(backup);
            }
            self.write_entries(&location, &cleanup.kept)?;
        }

        Ok(PruneReport {
            original_count: entries.len(),
            kept_count: cleanup.kept.len(),
            removed_noise_count,
            removed_duplicate_count,
            backup_path,
            sample_removed: cleanup
                .removed
                .iter()
                .take(5)
                .map(|removed| format!("{} ({})", removed.command, removed.reason.label()))
                .collect(),
        })
    }

    pub fn list_boxes(&self) -> Result<Vec<BoxSummary>> {
        let mut summaries = Vec::new();

        for platform in [Platform::Htb, Platform::Thm] {
            let platform_dir = self.paths.platform_dir(platform);
            if !platform_dir.exists() {
                continue;
            }

            for entry in fs::read_dir(&platform_dir).with_context(|| {
                format!(
                    "failed to read platform directory {}",
                    platform_dir.display()
                )
            })? {
                let entry = entry?;
                if !entry.file_type()?.is_dir() {
                    continue;
                }

                let dir = entry.path();
                let slug = entry.file_name().to_string_lossy().to_string();
                let location = BoxLocation {
                    platform,
                    display_name: slug.clone(),
                    slug,
                    dir,
                };

                if let Ok(summary) = self.summary_for_location(&location) {
                    summaries.push(summary);
                }
            }
        }

        summaries.sort_by(|left, right| {
            session_rank(left.session.as_ref().map(|session| session.status))
                .cmp(&session_rank(
                    right.session.as_ref().map(|session| session.status),
                ))
                .then_with(|| right.last_command_at.cmp(&left.last_command_at))
                .then_with(|| {
                    left.metadata
                        .name
                        .to_lowercase()
                        .cmp(&right.metadata.name.to_lowercase())
                })
        });

        Ok(summaries)
    }

    pub fn read_entries(&self, location: &BoxLocation) -> Result<Vec<CommandEntry>> {
        let path = self.commands_path(location);
        if !path.exists() {
            return Ok(Vec::new());
        }

        let file = File::open(&path)
            .with_context(|| format!("failed to open command log at {}", path.display()))?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(entry) = serde_json::from_str::<CommandEntry>(&line) {
                entries.push(entry);
            }
        }

        entries.sort_by_key(|entry| entry.timestamp);
        Ok(entries)
    }

    pub fn load_metadata(&self, location: &BoxLocation) -> Result<BoxMetadata> {
        let path = self.metadata_path(location);
        if path.exists() {
            read_json(&path)
        } else {
            Ok(BoxMetadata::new(
                location.display_name.clone(),
                location.platform,
                None,
            ))
        }
    }

    pub fn writeup(&self, location: &BoxLocation) -> Result<RenderedWriteup> {
        let metadata = self.load_metadata(location)?;
        let entries = self.read_entries(location)?;
        let path = self.writeup_path(location);
        let rendered = render_markdown(
            &metadata,
            &entries,
            &self.config.phase_rules,
            &self.config.cleanup_rules,
            path.clone(),
        );

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create write-up directory {}", parent.display())
            })?;
        }

        fs::write(&path, rendered.markdown.as_bytes())
            .with_context(|| format!("failed to write markdown to {}", path.display()))?;

        Ok(rendered)
    }

    pub fn resolve_existing_box(
        &self,
        box_name: Option<&str>,
        platform: Option<Platform>,
    ) -> Result<BoxLocation> {
        match box_name {
            Some(name) => self.find_box_location(platform, name),
            None => {
                let session = self
                    .active_session()?
                    .ok_or_else(|| anyhow!("no active session found"))?;
                self.find_box_location(Some(session.platform), &session.box_name)
            }
        }
    }

    pub fn resolve_log_location(
        &self,
        box_name: Option<&str>,
        platform: Option<Platform>,
    ) -> Result<BoxLocation> {
        if let Some(name) = box_name {
            if let Ok(location) = self.find_box_location(platform, name) {
                return Ok(location);
            }

            let platform = platform
                .or_else(|| {
                    self.active_session()
                        .ok()
                        .flatten()
                        .map(|session| session.platform)
                })
                .unwrap_or(Platform::Htb);
            return self.ensure_box_location(platform, name);
        }

        if let Some(session) = self.active_session()? {
            return self.find_box_location(Some(session.platform), &session.box_name);
        }

        bail!("no active box found. run `pwnj start <box>` or pass `--box`.");
    }

    pub fn ensure_box_location(&self, platform: Platform, box_name: &str) -> Result<BoxLocation> {
        let slug = sanitize_box_name(box_name);
        let dir = self.paths.box_dir(platform, &slug);
        fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create box directory {}", dir.display()))?;

        let location = BoxLocation {
            platform,
            display_name: box_name.to_string(),
            slug,
            dir,
        };

        if !self.metadata_path(&location).exists() {
            let metadata = BoxMetadata::new(box_name.to_string(), platform, None);
            self.save_metadata(&location, &metadata)?;
        }

        Ok(location)
    }

    pub fn find_box_location(
        &self,
        platform: Option<Platform>,
        query: &str,
    ) -> Result<BoxLocation> {
        let query_slug = sanitize_box_name(query).to_lowercase();
        let mut matches = Vec::new();

        for candidate_platform in platform.into_iter().chain([Platform::Htb, Platform::Thm]) {
            let platform_dir = self.paths.platform_dir(candidate_platform);
            if !platform_dir.exists() {
                continue;
            }

            for entry in fs::read_dir(&platform_dir)
                .with_context(|| format!("failed to read {}", platform_dir.display()))?
            {
                let entry = entry?;
                if !entry.file_type()?.is_dir() {
                    continue;
                }

                let dir = entry.path();
                let slug = entry.file_name().to_string_lossy().to_string();
                let location = BoxLocation {
                    platform: candidate_platform,
                    display_name: slug.clone(),
                    slug: slug.clone(),
                    dir: dir.clone(),
                };
                let metadata = self
                    .load_metadata(&location)
                    .unwrap_or_else(|_| BoxMetadata::new(slug.clone(), candidate_platform, None));
                let metadata_slug = sanitize_box_name(&metadata.name).to_lowercase();

                if metadata.name.eq_ignore_ascii_case(query)
                    || slug.eq_ignore_ascii_case(query)
                    || metadata_slug == query_slug
                {
                    matches.push(BoxLocation {
                        platform: candidate_platform,
                        display_name: metadata.name,
                        slug,
                        dir,
                    });
                }
            }

            if platform.is_some() {
                break;
            }
        }

        match matches.len() {
            0 => bail!("box `{}` was not found", query),
            1 => Ok(matches.remove(0)),
            _ => bail!("multiple boxes matched `{}`; specify --platform", query),
        }
    }

    pub fn summary_for_location(&self, location: &BoxLocation) -> Result<BoxSummary> {
        let metadata = self.load_metadata(location)?;
        let entries = self.read_entries(location)?;
        let session = self.active_session()?.filter(|session| {
            session.box_name == metadata.name && session.platform == metadata.platform
        });
        let active = session.as_ref().map_or(false, SessionState::is_active);

        let mut phase_counts = BTreeMap::new();
        for phase in Phase::ORDERED {
            phase_counts.insert(phase, 0);
        }

        let mut flags = BTreeSet::new();
        let mut last_command_at = None;
        for entry in &entries {
            *phase_counts.entry(entry.phase).or_default() += 1;
            for flag in &entry.flags {
                flags.insert(flag.clone());
            }
            last_command_at = Some(
                last_command_at.map_or(entry.timestamp, |current: DateTime<Utc>| {
                    current.max(entry.timestamp)
                }),
            );
        }

        Ok(BoxSummary {
            metadata,
            command_count: entries.len(),
            last_command_at,
            phase_counts,
            flags: flags.into_iter().collect(),
            session,
            active,
        })
    }

    pub fn shell_hook(&self, shell: ShellKind) -> String {
        let host = &self.config.daemon.host;
        let port = self.config.daemon.port;

        match shell {
            ShellKind::Zsh => format!(
                r#"# Add this to ~/.zshrc
autoload -Uz add-zsh-hook
zmodload zsh/net/tcp 2>/dev/null

typeset -g PWNJOURNAL_DAEMON_HOST="{host}"
typeset -g PWNJOURNAL_DAEMON_PORT="{port}"
typeset -g PWNJOURNAL_DAEMON_FD=""

__pwnj_escape() {{
    local value="$1"
    value="${{value//\\/\\\\}}"
    value="${{value//$'\n'/\\n}}"
    value="${{value//$'\r'/\\r}}"
    value="${{value//|/\\|}}"
    printf '%s' "$value"
}}

__pwnj_connect() {{
    ztcp "$PWNJOURNAL_DAEMON_HOST" "$PWNJOURNAL_DAEMON_PORT" || return 1
    PWNJOURNAL_DAEMON_FD="$REPLY"
}}

__pwnj_send() {{
    local payload="$1"
    if [[ -z "$PWNJOURNAL_DAEMON_FD" ]]; then
        __pwnj_connect || return 1
    fi

    print -r -- "$payload" >&$PWNJOURNAL_DAEMON_FD || {{
        PWNJOURNAL_DAEMON_FD=""
        __pwnj_connect || return 1
        print -r -- "$payload" >&$PWNJOURNAL_DAEMON_FD
    }}
}}

__pwnj_preexec() {{
    local cmd="$1"
    case "$cmd" in
        pwnj\ *|pwnjournal\ *|__pwnj_preexec*|__pwnj_connect*|__pwnj_send*|pwnj-daemon*) return ;;
    esac

    local cwd escaped_cwd escaped_cmd payload
    cwd="$PWD"
    escaped_cwd="$(__pwnj_escape "$cwd")"
    escaped_cmd="$(__pwnj_escape "$cmd")"
    payload="LOG|$escaped_cwd|$escaped_cmd"

    __pwnj_send "$payload" || pwnj log --command "$cmd" --cwd "$PWD" >/dev/null 2>&1
}}

add-zsh-hook preexec __pwnj_preexec
"#,
                host = host,
                port = port
            ),
            ShellKind::Bash => format!(
                r#"# Add this to ~/.bashrc
export PWNJOURNAL_DAEMON_HOST="{host}"
export PWNJOURNAL_DAEMON_PORT="{port}"

__pwnj_escape() {{
    local value="$1"
    value="${{value//\\/\\\\}}"
    value="${{value//$'\n'/\\n}}"
    value="${{value//$'\r'/\\r}}"
    value="${{value//|/\\|}}"
    printf '%s' "$value"
}}

__pwnj_connect() {{
    exec 9<>/dev/tcp/$PWNJOURNAL_DAEMON_HOST/$PWNJOURNAL_DAEMON_PORT
}}

__pwnj_send() {{
    local payload="$1"
    if [[ -z "${{PWNJOURNAL_DAEMON_FD_OPEN:-}}" ]]; then
        __pwnj_connect && PWNJOURNAL_DAEMON_FD_OPEN=1
    fi

    if [[ -n "${{PWNJOURNAL_DAEMON_FD_OPEN:-}}" ]]; then
        printf '%s\n' "$payload" >&9 || {{
            PWNJOURNAL_DAEMON_FD_OPEN=
            __pwnj_connect && printf '%s\n' "$payload" >&9
        }}
    fi
}}

__pwnj_preexec() {{
    local cmd="$BASH_COMMAND"
    case "$cmd" in
        pwnj\ *|pwnjournal\ *|__pwnj_preexec*|__pwnj_connect*|__pwnj_send*|pwnj-daemon*) return ;;
    esac

    local escaped_cwd escaped_cmd payload
    escaped_cwd="$(__pwnj_escape "$PWD")"
    escaped_cmd="$(__pwnj_escape "$cmd")"
    payload="LOG|$escaped_cwd|$escaped_cmd"

    __pwnj_send "$payload" || pwnj log --command "$cmd" --cwd "$PWD" >/dev/null 2>&1
}}

trap '__pwnj_preexec' DEBUG
"#,
                host = host,
                port = port
            ),
        }
    }

    fn current_session_for_location(&self, location: &BoxLocation) -> Result<SessionState> {
        let session = self
            .active_session()?
            .ok_or_else(|| anyhow!("no active session found"))?;

        if session.box_name != location.display_name || session.platform != location.platform {
            bail!(
                "the active session does not match `{}`",
                location.display_name
            );
        }

        Ok(session)
    }

    fn save_session(&self, session: &SessionState) -> Result<()> {
        write_json_pretty(&self.paths.state_file, session)
    }

    fn clear_session(&self) -> Result<()> {
        if self.paths.state_file.exists() {
            fs::remove_file(&self.paths.state_file)
                .with_context(|| format!("failed to remove {}", self.paths.state_file.display()))?;
        }
        Ok(())
    }

    fn stop_location(
        &self,
        box_name: Option<&str>,
        platform: Option<Platform>,
        when: DateTime<Utc>,
    ) -> Result<BoxSummary> {
        let location = if let Some(name) = box_name {
            self.find_box_location(platform, name)?
        } else {
            let session = self
                .active_session()?
                .ok_or_else(|| anyhow!("no active session to stop"))?;
            self.find_box_location(Some(session.platform), &session.box_name)?
        };

        let mut metadata = self.load_metadata(&location)?;
        metadata.stopped_at = Some(when);
        self.save_metadata(&location, &metadata)?;

        if let Some(session) = self.active_session()? {
            if session.box_name == metadata.name && session.platform == metadata.platform {
                self.clear_session()?;
            }
        }

        self.summary_for_location(&location)
    }

    fn save_metadata(&self, location: &BoxLocation, metadata: &BoxMetadata) -> Result<()> {
        write_json_pretty(&self.metadata_path(location), metadata)
    }

    fn append_entry(&self, location: &BoxLocation, entry: &CommandEntry) -> Result<()> {
        let path = self.commands_path(location);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("failed to open {}", path.display()))?;

        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, entry)
            .with_context(|| format!("failed to serialize command entry to {}", path.display()))?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        Ok(())
    }

    fn write_entries(&self, location: &BoxLocation, entries: &[CommandEntry]) -> Result<()> {
        let path = self.commands_path(location);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }

        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)
            .with_context(|| format!("failed to open {} for rewrite", path.display()))?;

        let mut writer = BufWriter::new(file);
        for entry in entries {
            serde_json::to_writer(&mut writer, entry).with_context(|| {
                format!("failed to serialize command entry to {}", path.display())
            })?;
            writer.write_all(b"\n")?;
        }
        writer.flush()?;
        Ok(())
    }

    fn backup_commands_path(&self, location: &BoxLocation) -> PathBuf {
        let stamp = Utc::now().format("%Y%m%d%H%M%S");
        location.dir.join(format!("commands.jsonl.bak-{}", stamp))
    }

    fn commands_path(&self, location: &BoxLocation) -> PathBuf {
        location.dir.join("commands.jsonl")
    }

    fn metadata_path(&self, location: &BoxLocation) -> PathBuf {
        location.dir.join("box.json")
    }

    fn writeup_path(&self, location: &BoxLocation) -> PathBuf {
        location.dir.join("writeup.md")
    }
}

impl JournalPaths {
    pub fn resolve() -> Result<Self> {
        let root = env::var_os("PWNJOURNAL_HOME")
            .map(PathBuf::from)
            .or_else(|| dirs::home_dir().map(|home| home.join(".pwnjournal")))
            .ok_or_else(|| anyhow!("unable to determine a home directory for PwnJournal"))?;

        fs::create_dir_all(&root)
            .with_context(|| format!("failed to create PwnJournal root at {}", root.display()))?;

        let state_file = root.join("current.json");
        let config_file = root.join("config.yaml");
        Ok(Self {
            root,
            state_file,
            config_file,
        })
    }

    pub fn platform_dir(&self, platform: Platform) -> PathBuf {
        self.root.join(platform.folder())
    }

    pub fn box_dir(&self, platform: Platform, slug: &str) -> PathBuf {
        self.platform_dir(platform).join(slug)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellKind {
    Zsh,
    Bash,
}

fn sanitize_box_name(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for ch in value.chars() {
        if matches!(ch, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') || ch.is_control() {
            output.push('_');
        } else {
            output.push(ch);
        }
    }

    let trimmed = output.trim().trim_matches('.');
    if trimmed.is_empty() {
        "box".to_string()
    } else {
        trimmed.to_string()
    }
}

fn session_rank(status: Option<SessionStatus>) -> u8 {
    match status {
        Some(SessionStatus::Active) => 0,
        Some(SessionStatus::Paused) => 1,
        None => 2,
    }
}

fn read_json_if_exists<T: for<'de> serde::Deserialize<'de>>(path: &Path) -> Result<Option<T>> {
    if !path.exists() {
        return Ok(None);
    }

    Ok(Some(read_json(path)?))
}

fn read_json<T: for<'de> serde::Deserialize<'de>>(path: &Path) -> Result<T> {
    let contents =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&contents)
        .with_context(|| format!("failed to parse JSON at {}", path.display()))
}

fn write_json_pretty<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let contents = serde_json::to_string_pretty(value)
        .with_context(|| format!("failed to serialize JSON for {}", path.display()))?;
    fs::write(path, contents).with_context(|| format!("failed to write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::sanitize_box_name;

    #[test]
    fn sanitizes_invalid_path_characters() {
        assert_eq!(sanitize_box_name("Resolute/One"), "Resolute_One");
    }
}
