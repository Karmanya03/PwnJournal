<p align="center">
	<img src="assets/PwnJournal-Logo.png" alt="PwnJournal logo" width="240" />
</p>

<h1 align="center">PwnJournal</h1>

<p align="center">
	<strong>A local-first CTF logger, phase classifier, and Markdown write-up generator.</strong><br />
	Because scrollback archaeology is only fun until the second box starts looking exactly like the first one.
</p>

<p align="center">
	<a href="#installation"><img src="https://img.shields.io/badge/Installation-0f172a?style=for-the-badge&labelColor=0f172a&color=22c55e" alt="Installation" /></a>
	<a href="#quick-start"><img src="https://img.shields.io/badge/Quick%20Start-0f172a?style=for-the-badge&labelColor=0f172a&color=14b8a6" alt="Quick Start" /></a>
	<a href="#command-reference"><img src="https://img.shields.io/badge/Commands-0f172a?style=for-the-badge&labelColor=0f172a&color=38bdf8" alt="Commands" /></a>
	<a href="#configuration"><img src="https://img.shields.io/badge/Config-0f172a?style=for-the-badge&labelColor=0f172a&color=f59e0b" alt="Configuration" /></a>
	<a href="#daemon"><img src="https://img.shields.io/badge/Daemon-0f172a?style=for-the-badge&labelColor=0f172a&color=f97316" alt="Daemon" /></a>
	<a href="#tui"><img src="https://img.shields.io/badge/TUI-0f172a?style=for-the-badge&labelColor=0f172a&color=8b5cf6" alt="TUI" /></a>
	<a href="#troubleshooting"><img src="https://img.shields.io/badge/Troubleshooting-0f172a?style=for-the-badge&labelColor=0f172a&color=64748b" alt="Troubleshooting" /></a>
</p>

PwnJournal captures shell activity, classifies it into CTF phases, prunes the ceremonial noise, and turns the result into a clean write-up draft. It stays on your machine, talks only to loopback, and tries very hard not to be dramatic about it.

## What It Does

- Logs commands manually or through a shell hook.
- Uses a lightweight local daemon so the shell does not spawn the full CLI for every command.
- Infers phases such as Scanning, Enumeration, Web, Exploitation, Privesc, Loot, and Unknown.
- Applies configurable cleanup rules so `pwd`, `cd`, `history`, and their equally unhelpful cousins stop wasting vertical space.
- Generates a Markdown write-up that already has enough structure to look intentional.
- Keeps the workflow local-first, which is polite for both privacy and latency.

## Binaries

- `pwnj` is the primary CLI.
- `pwnjournal` remains as a compatibility alias, because migrations enjoy leaving tiny scars.

## 🚀 Installation

We provide multiple ways to install PwnJournal. Choose the method that best fits your environment.

### 📦 Automated Install (Recommended)

The easiest way to install and configure PwnJournal system-wide is to use our bootstrap scripts.

**Linux / macOS:**
```bash
curl -sSL https://raw.githubusercontent.com/Karmanya03/PwnJournal/main/scripts/install.sh | bash
```

**Windows (Run in an Administrator PowerShell):**
```powershell
irm https://raw.githubusercontent.com/Karmanya03/PwnJournal/main/scripts/install.ps1 | iex
```

### ⚡ Pre-built Release (Windows)

If you don't have Cargo installed and just want the binary, you can download and extract the latest Windows release automatically:
```powershell
irm https://raw.githubusercontent.com/Karmanya03/PwnJournal/main/scripts/install-release.ps1 | iex
```

### 🛠️ Manual Build from Source

If you prefer to build manually from source, make sure you have [Rust](https://rustup.rs/) installed:

```bash
# Build locally from the cloned repository
cargo install --locked --path .

# Or build directly from GitHub
cargo install --locked --git https://github.com/Karmanya03/PwnJournal.git --tag v0.1.0
```

<details>
<summary><strong>⚙️ Manual PATH Configuration</strong></summary>

If you didn't use the automated scripts, you might need to add PwnJournal to your system PATH manually:

- **Bash / Zsh:** Add `export PATH="$HOME/.cargo/bin:$PATH"` to your `~/.bashrc` or `~/.zshrc`.
- **Fish:** Run `set -Ux fish_user_paths $HOME/.cargo/bin $fish_user_paths`.
- **Windows:** Add `%USERPROFILE%\.cargo\bin` to the User PATH in Environment Variables.

</details>

### 🪝 Shell Hook Setup

Once installed, setup the shell hook to automatically capture your commands.

**For Bash:**
```bash
eval "$(pwnj hook bash)"
```

**For Zsh:**
```bash
eval "$(pwnj hook zsh)"
```

*Pro tip: Add these snippets to your shell profile (`~/.bashrc` or `~/.zshrc`) to make them persistent.*

### 🎯 Typical Workflow

1. Work the box normally. The hook sends `LOG\|cwd\|command` messages to the daemon on `127.0.0.1:41737`. If the daemon is down, the hook falls back to `pwnj log`, because resilience should not require a ceremonial reboot.
2. Generate the write-up when the box is done pretending to be difficult.

```bash
pwnj writeup legacy --stdout
```

## Feature Overview

### Logging

PwnJournal can record commands from two paths: manual CLI input and shell hook traffic. The hook is designed to be lightweight and local, so your shell does not keep spawning the whole application just to say `ls` again.

### Phase Detection

Commands are classified into phases like Scanning, Enumeration, Web, Exploitation, Privesc, Loot, and Unknown. You can also add phase hints in the config file when a target insists on being weird on purpose.

### Cleanup Rules

The generated write-up is filtered by configurable cleanup rules. This is where you tell the tool which commands are evidence and which commands are just the terminal clearing its throat.

### Write-up Generation

The output is a Markdown draft with session metadata, phase coverage, observed signals, critical one-liners, and phase-by-phase command sections. It is meant to save you from starting every write-up with a blank page and an existential crisis.

### TUI Dashboard

The terminal UI shows session state, a live command timeline, details for the selected command, and a phase distribution chart. It is built to stay dense without turning into an unreadable wall of boxes.

## Command Reference

| Command | Purpose | Example |
| --- | --- | --- |
| `pwnj start <box> [--ip ...] [--platform htb/thm]` | Start a new session or resume an existing one. | `pwnj start sightless --ip 10.10.11.32 --platform htb` |
| `pwnj stop [box] [--platform ...]` | Stop the current or named session. | `pwnj stop sightless` |
| `pwnj pause [box] [--platform ...]` | Pause tracking without losing the session. | `pwnj pause` |
| `pwnj resume [box] [--platform ...]` | Resume a paused session. | `pwnj resume sightless` |
| `pwnj log --command "..." [--box ...] [--cwd ...] [--phase ...]` | Record a command manually. | `pwnj log --command "nmap -sC -sV 10.10.11.32" --phase Scanning` |
| `pwnj prune [box] [--apply]` | Preview or apply cleanup rules. | `pwnj prune sightless --apply` |
| `pwnj list` | Show all tracked boxes. | `pwnj list` |
| `pwnj writeup [box] [--stdout]` | Render a Markdown write-up. | `pwnj writeup sightless --stdout` |
| `pwnj journal [box]` | Open the live TUI dashboard. | `pwnj journal sightless` |
| `pwnj replay [box]` | Rewind the session timeline. | `pwnj replay sightless` |
| `pwnj hook <bash/zsh>` | Print the shell hook snippet. | `pwnj hook zsh` |
| `pwnj daemon` | Start the local loopback logger. | `pwnj daemon` |
| `pwnj help [command]` / `pwnj <command> --help` | Show the built-in help for the full CLI or any individual subcommand. | `pwnj start --help` |

## Configuration

The first run creates `~/.pwnjournal/config.yaml`. Edit it to customize the daemon host and port, cleanup rules, and phase hints.

```yaml
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
		explanation: Directory fuzzing, because the target refuses to annotate itself.
```

You can move the data root by setting `PWNJOURNAL_HOME`. If you do not, the tool uses `~/.pwnjournal` and keeps things simple.

## Daemon

`pwnj daemon` listens on the configured loopback address and accepts one-line payloads in the form `LOG|cwd|command`. The shell hook escapes separators before sending, so paths and commands survive the trip without becoming modern art.

The daemon is intentionally small. It exists to keep shell hooks fast and to make the logging path feel like a local plumbing problem rather than a process-management hobby.

## Shell Hook

Use `pwnj hook bash` or `pwnj hook zsh` to print a snippet you can paste into your shell startup file.

- Bash uses `DEBUG` trap forwarding.
- Zsh uses `add-zsh-hook preexec`.
- Both try the daemon first and fall back to `pwnj log` if the socket path is unavailable.

## Data Layout

Each box gets its own small evidence kit under the data root:

- `commands.jsonl` for raw session commands.
- `box.json` for metadata and session state.
- `writeup.md` for the generated draft.

That is the full blast radius. No hidden cache forests, no surprise databases, no mysterious objects multiplying in the dark.

## TUI

Use `pwnj journal <box>` for the live dashboard and `pwnj replay <box>` for playback mode.

The dashboard shows:

- Session metadata and status.
- A scrolling command timeline.
- Command details for the selected entry.
- A phase distribution chart.

The replay view adds playback controls so you can step through a session like a very determined film editor.

## Troubleshooting

- If commands are not being logged, make sure `pwnj daemon` is running before opening a new shell.
- If the hook feels noisy, add cleanup rules to `~/.pwnjournal/config.yaml`.
- If phase labels look wrong, add phase hints for the patterns you care about.
- If PwnJournal writes data somewhere unexpected, check `PWNJOURNAL_HOME`.
- If you only want to inspect the draft, run `pwnj writeup <box> --stdout`.

## Notes

- The tool is local-first and loopback-bound.
- The shell hook avoids heavyweight process spawning.
- The cleanup rules are configurable so you can decide which commands count as evidence and which ones are just the terminal being chatty.
- The README buttons above are intentionally plain and functional: enough polish to feel intentional, not enough gloss to start pretending it is a landing page for a SaaS that bills by the vowel.

## FAQ

**Q: Will PwnJournal hack the box for me?**  
A: No. It just patiently records your majestic failures and occasional triumphs so you don't have to desperately scroll back up to remember what flags you passed to `nmap` 4 hours ago.

**Q: Is this going to send my zero-days to the cloud?**  
A: The only cloud this talks to is the dust cloud blowing out of your laptop's cooling fan. Everything is strictly local, loopback-bound, and completely antisocial.

**Q: I ran `rm -rf /` by mistake. Did PwnJournal log it?**  
A: Yes, and it will be beautifully formatted in your Markdown write-up under the "Unknown" phase. Your sacrifice will look extremely professional.

**Q: Why Rust?**  
A: Because if you're going to use a tool while poking at memory corruption vulnerabilities, the least you can do is have the compiler relentlessly yell at you about lifetimes.

---

<p align="center">
  Built with ☕ and unresolved shell trauma by <a href="https://github.com/Karmanya03">Karmanya</a>.<br/>
  If this tool saved you from agonizing terminal scrollback archaeology, consider dropping a ⭐ on the repo!
</p>
