# lazypath

Minimalist TUI and CLI Windows `PATH` and environment variable surgeon.

`lazypath` inspects `User` (`HKCU\Environment`) and `System` (`HKLM\...\Environment`) variables, expands `%VAR%` placeholders, scans every `PATH` directory for `.exe`, `.cmd`, `.bat`, and `.com` binaries, and pinpoints dead directories, duplicate entries, and shadowed executables.

## Quick Start

```powershell
# Launch interactive TUI
cargo run --release

# Run a one-shot PATH health and shadowing audit
cargo run --release -- --check

# Locate all matching executables in PATH priority order
cargo run --release -- --which python

# Export User and System environment variables to JSON
cargo run --release -- --export env-backup.json
```

## Keybindings

| Key | Action |
| :--- | :--- |
| `j` / `k` / `Up` / `Down` | Navigate items in the active pane |
| `Tab` / `h` / `l` | Switch focus between `Variables` and `PATH` table |
| `J` / `K` / `Alt+Up` / `Alt+Down` | Move selected `PATH` directory up or down in priority |
| `d` | Clean all `MISSING` and `DUP` directories from active `PATH` |
| `Enter` | Open modal listing all executables (`.exe`, `.cmd`, `.bat`) in directory |
| `a` | Append a new directory to active `PATH` |
| `x` / `Delete` | Remove selected directory from active `PATH` |
| `/` or `w` | Filter `PATH` entries by directory path or executable name |
| `b` | Export JSON snapshot backup (`lazypath-backup.json`) |
| `s` | Save modified `PATH` to Windows Registry and broadcast `WM_SETTINGCHANGE` |
| `E` | Relaunch with UAC Administrator elevation (for `System` scope edits) |
| `?` | Toggle keybinding help overlay |
| `q` / `Ctrl+C` | Quit |
