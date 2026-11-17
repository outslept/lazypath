# lazypath

minimalist tui and cli windows `path` and environment variable auditor.

`lazypath` inspects user and system environment variables directly from the windows registry, expands `%var%` placeholders, detects dead directories, duplicate entries, and shadowed executables, and lets you clean up or reorder your `path` without touching the legacy windows dialog.

## features

- **shadowing & conflict detection** — scans every `path` directory for `.exe`, `.cmd`, `.bat`, and `.com` binaries and highlights which entries shadow (or are shadowed by) others in priority order.
- **one-key cleanup** — prune all missing directories (`missing`) and duplicate entries (`dup`) from user or system `path` at once.
- **priority reordering** — move `path` entries up and down, append new directories, or delete entries interactively.
- **executable inspector** — press `enter` on any directory to browse its executables and see exact conflict annotations.
- **live search & filter** — filter `path` entries by directory substring or executable name in real time.
- **safe registry writes & backups** — writes `reg_expand_sz` / `reg_sz` values to `hkcu` and `hklm`, creates an automatic json backup (`lazypath-auto-backup.json`) before saving, and broadcasts `wm_settingchange`.
- **uac elevation** — relaunch directly from the tui with administrator privileges when editing the system `path`.
- **headless cli & json output** — run audits, resolve binary priority (`--which`), or export/import environment snapshots from scripts and ci.

## installation

build from source with cargo (windows):

```sh
cargo install --path .
```

or build a release binary directly:

```sh
cargo build --release
```

## usage

launch the interactive tui:

```sh
lazypath
```

run a non-interactive `path` audit in the terminal:

```sh
lazypath --check
```

find all executables matching a name across `path` in resolution order:

```sh
lazypath --which python
```

output audit or `--which` results as structured json:

```sh
lazypath --check --json
lazypath --which git --json
```

export and restore environment variable snapshots:

```sh
lazypath --export env-backup.json
lazypath --import env-backup.json
```

## tui keybindings

| key | action |
| :--- | :--- |
| `j` / `k` or `up` / `down` | navigate items in the active pane |
| `tab` or `h` / `l` | switch focus between variables sidebar and `path` table |
| `J` / `K` or `alt+down` / `alt+up` | move selected `path` entry priority down / up |
| `enter` | inspect executables inside the selected directory |
| `d` | prune all `missing` and `dup` entries in the active scope |
| `a` | append a new directory to the active `path` |
| `x` or `del` | remove the selected entry from the active `path` |
| `/` or `w` | filter `path` entries by directory path or `.exe` name |
| `esc` | clear active search filter or close modal |
| `b` | export a snapshot to `lazypath-backup.json` |
| `s` | save modified `path` to the windows registry and broadcast change |
| `E` | relaunch `lazypath` with uac administrator elevation |
| `?` | toggle keybindings help modal |
| `q` or `ctrl+c` | quit |

## cli options

```text
options:
  -c, --check           audit user and system path for missing dirs, duplicates, and shadowing
  -w, --which <binary>  find all executables matching <binary> across path in priority order
  -j, --json            print audit or which results as structured json and exit
      --export <file>   save a json snapshot of user and system environment variables
      --import <file>   restore user environment variables from a json snapshot
  -h, --help            show help message and exit
  -v, --version         show version information and exit
```

## license

mit
