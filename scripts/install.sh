#!/usr/bin/env bash
set -e

echo "[+] Installing PwnJournal via Cargo..."
cargo install --locked --git https://github.com/Karmanya03/PwnJournal.git --tag v0.1.0

if [ -d "/usr/local/bin" ]; then
    echo "[+] Creating system-wide symlinks in /usr/local/bin (may prompt for sudo password)..."
    sudo ln -sf "$HOME/.cargo/bin/pwnj" /usr/local/bin/pwnj
    sudo ln -sf "$HOME/.cargo/bin/pwnjournal" /usr/local/bin/pwnjournal
else
    echo "[!] /usr/local/bin not found. Skipping system-wide symlinks."
fi

echo "[+] Done! You can now run 'pwnj --help' to get started."
