# lazypath

Minimalist TUI and CLI Windows `PATH` and environment variable auditor.

`lazypath` reads User (`HKCU\Environment`) and System (`HKLM\...\Environment`) variables directly from the Windows Registry via UTF-16 Win32 APIs, expands nested `%VAR%` placeholders, detects dead directories, duplicate entries, and shadowed executables, and lets you clean up or reorder your `PATH` without touching the legacy Windows dialog.

## Features

- **Shadowing & Conflict Detection** - Scans every `PATH` directory for executables (respecting `PATHEXT` priority and Windows Store App Execution Aliases in `WindowsApps`) and highlights which entries shadow-or are shadowed by-other directories.
- **One-Key Cleanup** - Prune all non-existent (`MISSING`) and duplicate (`DUP`) directories from User or System `PATH` at once with `d`.
- **Priority Reordering & Editing** - Move `PATH` entries up and down (`J`/`K` or `Alt+↑`/`↓`), append single or semicolon-delimited directories (`a`), or delete entries (`x`/`Delete`).
- **Executable Inspector** - Press `Enter` on any `PATH` directory to browse all discovered executables and see exact conflict/shadowing annotations.
- **Environment Variable Inspector** - Browse all User and System variables in the sidebar with live `%VAR%` expansion and automatic disk-existence checks for path-like values.
- **Live Search & Filter** - Filter `PATH` entries by raw path, expanded path, or executable name in real time (`/` or `w`), with `Esc` to revert.
- **Safe Registry Writes, Rollback & Backups** - Preserves `REG_EXPAND_SZ` and `REG_SZ` types, writes atomic pre-save backups (`%LOCALAPPDATA%\lazypath\lazypath-auto-backup.json`), rolls back partial changes on failure, and broadcasts `WM_SETTINGCHANGE` so running shells and Explorer update immediately.
- **Seamless UAC Elevation** - Press `E` to relaunch as Administrator via UAC; any unsaved in-memory `PATH` edits are automatically handed off and restored in the elevated session.
- **Headless CLI & CI Mode** - Run `--check` audits, resolve command precedence with `--which`, preview or apply snapshots with `--export` / `--import --dry-run`, and emit structured JSON (`--json`).

## Installation

Build and install from source with Cargo (Windows):

```sh
cargo install --path .
```

Or build a release binary directly:

```sh
cargo build --release
```

## Usage

Launch the interactive TUI:

```sh
lazypath
```

Run a non-interactive `PATH` health check (exits with code `1` if issues are found):

```sh
lazypath --check
```

Run a health check without failing the exit code, or inspect the current process `PATH` instead of the Registry:

```sh
lazypath --check --no-fail
lazypath --check --process-path
```

Find all executables matching a command across `PATH` in resolution order (`WINNER` vs `SHADOWED`):

```sh
lazypath --which python
lazypath --which git.exe
```

Output `--check`, `--which`, or `--import` results as structured JSON (`schema_version: 1`):

```sh
lazypath --check --json
lazypath --which python --json
```

Export and restore environment variable snapshots (with optional dry-run preview):

```sh
lazypath --export env-backup.json
lazypath --import env-backup.json --dry-run
lazypath --import env-backup.json --dry-run --json
lazypath --import env-backup.json
```

## TUI Keybindings

| Key | Action |
| :--- | :--- |
| `j` / `k` or `↓` / `↑` | Move selection down / up in the active pane |
| `Home` / `End` / `PgUp` / `PgDn` | Jump to first / last item or scroll by page |
| `Tab` or `h` / `l` or `←` / `→` | Switch focus between `Variables` sidebar and `Entries` pane |
| `J` / `K` or `Alt+↓` / `Alt+↑` | Move selected `PATH` entry down / up in priority order |
| `Enter` | Open Executable Inspector modal for the selected `PATH` directory |
| `a` | Append new directory (or `;`-separated directories) to `PATH` |
| `x` or `Delete` | Remove the selected entry from the active `PATH` |
| `d` | Auto-prune all `MISSING` and `DUP` entries in the active `PATH` |
| `/` or `w` | Filter entries by directory path or executable (`Enter` apply, `Esc` revert) |
| `r` | Clear directory cache and rescan `PATH` directories from disk |
| `s` | Save modified `PATH` to the Windows Registry and broadcast `WM_SETTINGCHANGE` |
| `b` | Export manual snapshot to `%LOCALAPPDATA%\lazypath\lazypath-backup.json` |
| `E` | Relaunch `lazypath` as Administrator (UAC), preserving unsaved edits |
| `?` | Toggle keybindings help modal |
| `Esc` | Clear active search filter or close open modal |
| `q` or `Ctrl+C` | Quit (prompts to save or discard if unsaved changes exist) |

## CLI Options

```text
Usage:
  lazypath [OPTIONS]

Options:
  -c, --check           Audit User and System PATH for missing dirs, duplicates, and shadowing
      --no-fail         Return exit code 0 from --check even when PATH issues are detected
      --process-path    Audit or search the current process PATH instead of the Registry
  -w, --which <BINARY>  Find all executables matching <BINARY> across PATH in priority order
  -j, --json            Print audit, which, or import results as structured JSON and exit
      --export <FILE>   Save a JSON snapshot of User and System environment variables
      --import <FILE>   Restore User environment variables from a JSON snapshot
  -n, --dry-run         Preview --import changes without writing to the Windows Registry
  -h, --help            Show this help message and exit
  -v, -V, --version     Show version information and exit
```

## Backups & Data Files

`lazypath` stores snapshots and temporary state files in `%LOCALAPPDATA%\lazypath\`:

- `lazypath-backup.json` - Manual backup created when pressing `b` in the TUI.
- `lazypath-auto-backup.json` - Automatic pre-save / pre-import backup created before any Registry modification (`s` or `--import`).
- `lazypath-pending-elevation.json` - Temporary handoff file used when elevating an unprivileged session with `E` (automatically deleted once resumed).

## Exit Codes

| Code | Meaning |
| :--- | :--- |
| `0` | Success (or `--check` completed with no issues / `--no-fail`) |
| `1` | `PATH` issues detected by `--check`, binary not found by `--which`, or runtime/Registry error |
| `2` | Invalid command-line arguments |

## License

MIT
