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

## Installation

### One-line install

```bash
cargo install --locked --path .
```

This builds the project from the repository root and installs both `pwnj` and `pwnjournal` into Cargo's bin directory.

### Direct release install

If you want to install from the latest GitHub release instead of building from source, grab the prebuilt Windows bundle and extract it into your Cargo bin directory:

```powershell
$installDir = Join-Path $HOME '.cargo\bin'; $archive = Join-Path $env:TEMP 'PwnJournal-latest.zip'; Invoke-WebRequest 'https://github.com/Karmanya03/PwnJournal/releases/latest/download/PwnJournal-windows-x64.zip' -OutFile $archive; Expand-Archive $archive -DestinationPath $installDir -Force
```

That drops the release binaries straight into the directory your shell already expects. If you are on another platform, build from source with `cargo install --locked --path .` until platform-specific release assets are added.

For Linux or any other Unix-like shell, the same tagged release can be installed directly from GitHub source with Cargo:

```bash
cargo install --locked --git https://github.com/Karmanya03/PwnJournal.git --tag v0.1.0
```

If you want that install plus PATH refresh in one line on Linux:

```bash
cargo install --locked --git https://github.com/Karmanya03/PwnJournal.git --tag v0.1.0 && export PATH="$HOME/.cargo/bin:$PATH"
```

### One-line PATH setup

If `pwnj` is not on your PATH after install, use one of these shortcuts:

- Bash / Zsh current session:

	```bash
	export PATH="$HOME/.cargo/bin:$PATH"
	```

- Bash / Zsh persistent setup:

	```bash
	echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc
	```

- Fish:

	```fish
	fish -c 'set -Ux fish_user_paths $HOME/.cargo/bin $fish_user_paths'
	```

- PowerShell current session:

	```powershell
	$env:Path = "$env:Path;$HOME\.cargo\bin"
	```

- PowerShell persistent setup:

	```powershell
	$cargoBin = Join-Path $HOME '.cargo\bin'; [Environment]::SetEnvironmentVariable('Path', "$env:Path;$cargoBin", 'User')
	```

### Auto PATH setup

If you want a one-liner that both installs and refreshes PATH in the current shell, use the variant for your environment:

- Bash / Zsh:

	```bash
	cargo install --locked --path . && export PATH="$HOME/.cargo/bin:$PATH"
	```

- Fish:

	```fish
	cargo install --locked --path .; set -Ux fish_user_paths $HOME/.cargo/bin $fish_user_paths
	```

- PowerShell:

	```powershell
	cargo install --locked --path .; $env:Path = "$env:Path;$HOME\.cargo\bin"
	```

### Manual PATH setup

- Bash / Zsh: add `export PATH="$HOME/.cargo/bin:$PATH"` to `~/.bashrc`, `~/.zshrc`, or the shell file you actually load, then reopen the terminal.
- Fish: add `set -Ux fish_user_paths $HOME/.cargo/bin $fish_user_paths` to your Fish config or run the one-liner above once.
- Windows: add `%USERPROFILE%\.cargo\bin` to the User PATH in Environment Variables, then restart your shell or editor.
- Temporary check: run `pwnj --help` from the same terminal after setting PATH so you know the shell can actually see the binary.

## Quick Start

1. Start the daemon in one terminal.

	 ```bash
	 pwnj daemon
	 ```

2. Start a box session in another terminal.

	 ```bash
	 pwnj start legacy --platform htb --ip 10.10.10.10
	 ```

3. Install the shell hook.

	 ```bash
	 eval "$(pwnj hook bash)"
	 ```

	 For zsh:

	 ```bash
	 eval "$(pwnj hook zsh)"
	 ```

4. Work the box normally. The hook sends `LOG|cwd|command` messages to the daemon on `127.0.0.1:41737`. If the daemon is down, the hook falls back to `pwnj log`, because resilience should not require a ceremonial reboot.

5. Generate the write-up when the box is done pretending to be difficult.

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

| Command | Purpose |
| --- | --- |
| `pwnj start <box> [--ip ...] [--platform htb|thm]` | Start or resume a box session. |
| `pwnj stop [box] [--platform ...]` | Stop the current or named session. |
| `pwnj pause [box] [--platform ...]` | Pause tracking without losing the session. |
| `pwnj resume [box] [--platform ...]` | Resume a paused session. |
| `pwnj log --command "..." [--box ...] [--cwd ...] [--phase ...]` | Record a command manually. |
| `pwnj prune [box] [--apply]` | Preview or apply cleanup rules. |
| `pwnj list` | Show all tracked boxes. |
| `pwnj writeup [box] [--stdout]` | Render a Markdown write-up. |
| `pwnj journal [box]` | Open the live TUI dashboard. |
| `pwnj replay [box]` | Rewind the session timeline. |
| `pwnj hook bash|zsh` | Print the shell hook snippet. |
| `pwnj daemon` | Start the local loopback logger. |
| `pwnj help [command]` / `pwnj <command> --help` | Show the built-in help for the full CLI or any individual subcommand. |

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
