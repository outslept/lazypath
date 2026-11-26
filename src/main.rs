//! Binary entry point for `lazypath`: dispatches between CLI subcommands
//! (`--check`, `--which`, `--export`, `--import`) and the interactive `ratatui` TUI.

use std::io::{self, Stdout};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Once;
use std::time::Duration;

use crossterm::event::{self, Event, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use serde::Serialize;

use lazypath::app::{App, LogLevel};
use lazypath::audit::{analyze_path_entries, summarize_audit, which_all};
use lazypath::cli::{CliOptions, help_text, parse_args};
use lazypath::expand::{normalize_path_key, split_path_value};
use lazypath::model::{AuditSummary, EnvScope, EnvVariable, PathEntry, PathStatus, SCHEMA_VERSION};
use lazypath::registry::{
    broadcast_environment_change, build_lookup_map, is_elevated, load_all_variables,
};
use lazypath::snapshot::{
    default_auto_backup_path, load_and_consume_pending_elevation_state, load_snapshot_file,
    plan_user_snapshot_import, restore_user_snapshot_with_baseline, save_snapshot_file,
};
use lazypath::ui::render;

/// Ensures the terminal-restoring panic hook is registered at most once per process.
static PANIC_HOOK_ONCE: Once = Once::new();

/// Structured JSON output payload for `lazypath --check --json`.
#[derive(Debug, Serialize)]
struct JsonAuditReport<'a> {
    schema_version: u32,
    source: &'static str,
    summary: &'a AuditSummary,
    entries: &'a [PathEntry],
}

/// Structured JSON output payload for `lazypath --import <FILE> [--dry-run] --json`.
#[derive(Debug, Serialize)]
struct JsonImportReport {
    schema_version: u32,
    dry_run: bool,
    source_path: String,
    backup_path: Option<String>,
    added: usize,
    updated: usize,
    unchanged: usize,
    total: usize,
}

/// RAII guard that manages raw terminal mode, the alternate screen buffer,
/// and a panic hook so the user's console is always restored on exit or unwind.
struct TerminalSession;

impl TerminalSession {
    fn enter() -> io::Result<Terminal<CrosstermBackend<Stdout>>> {
        PANIC_HOOK_ONCE.call_once(|| {
            let prev_hook = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |panic_info| {
                let _ = disable_raw_mode();
                let _ = execute!(io::stdout(), LeaveAlternateScreen);
                prev_hook(panic_info);
            }));
        });

        enable_raw_mode()?;
        let mut stdout = io::stdout();
        if let Err(err) = execute!(stdout, EnterAlternateScreen) {
            let _ = disable_raw_mode();
            return Err(err);
        }

        match Terminal::new(CrosstermBackend::new(stdout)) {
            Ok(terminal) => Ok(terminal),
            Err(err) => {
                let _ = disable_raw_mode();
                let _ = execute!(io::stdout(), LeaveAlternateScreen);
                Err(err)
            }
        }
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

fn main() -> ExitCode {
    let opts = match parse_args(std::env::args().skip(1)) {
        Ok(opts) => opts,
        Err(err) => {
            eprintln!("lazypath: {err}\nRun 'lazypath --help' for usage information.");
            return ExitCode::from(2);
        }
    };

    if opts.show_help {
        print!("{}", help_text());
        return ExitCode::SUCCESS;
    }

    if opts.show_version {
        println!("lazypath {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }

    if let Some(ref export_path) = opts.export_path {
        return run_export(export_path);
    }

    if let Some(ref import_path) = opts.import_path {
        return run_import(import_path, &opts);
    }

    if let Some(ref binary_query) = opts.which_binary {
        return run_which(binary_query, &opts);
    }

    if opts.check {
        return run_check(&opts);
    }

    match run_tui(&opts) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("lazypath: terminal error: {err}");
            ExitCode::from(1)
        }
    }
}

/// Runs the non-interactive `--check` audit and prints either a human-readable report or JSON.
///
/// Exits with code `1` when PATH issues are detected unless `--no-fail` was passed.
fn run_check(opts: &CliOptions) -> ExitCode {
    let (user_vars, sys_vars) = match load_all_variables() {
        Ok(vars) => vars,
        Err(err) => {
            eprintln!("lazypath: failed to read Windows Registry environment: {err}");
            return ExitCode::from(1);
        }
    };

    let process_override = if opts.process_path {
        Some(
            std::env::var_os("PATH")
                .map(|v| v.to_string_lossy().into_owned())
                .unwrap_or_default(),
        )
    } else {
        None
    };

    let entries = collect_combined_path_entries(&user_vars, &sys_vars, process_override.as_deref());
    let summary = summarize_audit(&entries);

    if opts.json {
        let report = JsonAuditReport {
            schema_version: SCHEMA_VERSION,
            source: if opts.process_path {
                "process"
            } else {
                "registry"
            },
            summary: &summary,
            entries: &entries,
        };
        match serde_json::to_string_pretty(&report) {
            Ok(json) => println!("{json}"),
            Err(err) => {
                eprintln!("lazypath: failed to serialize JSON audit report: {err}");
                return ExitCode::from(1);
            }
        }
    } else {
        print_human_audit_report(&entries, &summary, opts.process_path);
    }

    if summary.has_issues() && !opts.no_fail {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// Formats and prints the human-readable `--check` audit table and diagnostic summary.
fn print_human_audit_report(entries: &[PathEntry], summary: &AuditSummary, process_path: bool) {
    let source_label = if process_path {
        "Current Process PATH"
    } else {
        "Windows Registry (System → User)"
    };
    println!("lazypath audit — {source_label}");
    println!(
        "Entries: {} | Missing: {} | Duplicates: {} | Conflicts: {} | Shadowed: {} | Executables: {}\n",
        summary.total_entries,
        summary.missing_count,
        summary.duplicate_count,
        summary.conflict_entries,
        summary.shadowed_entries,
        summary.total_executables
    );

    for entry in entries {
        let status = entry.status();
        let badge = status.badge(entry.executables.len());
        println!(
            "#{:<2} [{:<6}] [{:<12}] {}",
            entry.index + 1,
            entry.scope.label(),
            badge,
            entry.expanded
        );
        if status != PathStatus::Ok
            && let Some(warning) = entry.headline_warning()
        {
            println!("      └─ {warning}");
        }
    }
}

/// Runs `--which <BINARY>` across all audited `PATH` entries and reports the winning binary
/// along with any shadowed installations.
fn run_which(query: &str, opts: &CliOptions) -> ExitCode {
    let (user_vars, sys_vars) = match load_all_variables() {
        Ok(vars) => vars,
        Err(err) => {
            eprintln!("lazypath: failed to read Windows Registry environment: {err}");
            return ExitCode::from(1);
        }
    };

    let process_override = if opts.process_path {
        Some(
            std::env::var_os("PATH")
                .map(|v| v.to_string_lossy().into_owned())
                .unwrap_or_default(),
        )
    } else {
        None
    };

    let entries = collect_combined_path_entries(&user_vars, &sys_vars, process_override.as_deref());
    let matches = which_all(&entries, query);

    if opts.json {
        match serde_json::to_string_pretty(&matches) {
            Ok(json) => println!("{json}"),
            Err(err) => {
                eprintln!("lazypath: failed to serialize JSON which output: {err}");
                return ExitCode::from(1);
            }
        }
        return if matches.is_empty() {
            ExitCode::from(1)
        } else {
            ExitCode::SUCCESS
        };
    }

    if matches.is_empty() {
        eprintln!("lazypath: '{query}' not found in any PATH directory.");
        return ExitCode::from(1);
    }

    for m in &matches {
        let tag = if m.is_winner { "WINNER  " } else { "SHADOWED" };
        println!(
            "[{tag}] #{:<2} ({:<6}) {}",
            m.entry_index + 1,
            m.scope.label(),
            m.full_path
        );
    }

    ExitCode::SUCCESS
}

/// Exports User and System Registry environment variables to a JSON snapshot file (`--export`).
fn run_export(path_str: &str) -> ExitCode {
    let (user_vars, sys_vars) = match load_all_variables() {
        Ok(vars) => vars,
        Err(err) => {
            eprintln!("lazypath: failed to read Windows Registry environment: {err}");
            return ExitCode::from(1);
        }
    };

    let path = Path::new(path_str);
    match save_snapshot_file(path, &user_vars, &sys_vars) {
        Ok(()) => {
            println!(
                "Exported {} User and {} System variables to '{}'.",
                user_vars.len(),
                sys_vars.len(),
                path.display()
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!(
                "lazypath: failed to export snapshot to '{}': {err}",
                path.display()
            );
            ExitCode::from(1)
        }
    }
}

/// Restores User environment variables from a JSON snapshot file (`--import`),
/// supporting `--dry-run`, `--json`, and mandatory pre-import backups.
fn run_import(path_str: &str, opts: &CliOptions) -> ExitCode {
    let path = Path::new(path_str);
    let snapshot = match load_snapshot_file(path) {
        Ok(snap) => snap,
        Err(err) => {
            eprintln!(
                "lazypath: failed to load snapshot '{}': {err}",
                path.display()
            );
            return ExitCode::from(1);
        }
    };

    let (current_user, current_sys) = match load_all_variables() {
        Ok(vars) => vars,
        Err(err) => {
            eprintln!("lazypath: failed to read current Windows Registry environment: {err}");
            return ExitCode::from(1);
        }
    };

    if opts.dry_run {
        let plan = plan_user_snapshot_import(&snapshot, &current_user);
        if opts.json {
            let report = JsonImportReport {
                schema_version: SCHEMA_VERSION,
                dry_run: true,
                source_path: path.display().to_string(),
                backup_path: None,
                added: plan.added,
                updated: plan.updated,
                unchanged: plan.unchanged,
                total: plan.total(),
            };
            match serde_json::to_string_pretty(&report) {
                Ok(json) => println!("{json}"),
                Err(err) => {
                    eprintln!("lazypath: failed to serialize dry-run JSON report: {err}");
                    return ExitCode::from(1);
                }
            }
        } else {
            println!(
                "Dry-run import from '{}': {} added, {} updated, {} unchanged (total: {} User variables).",
                path.display(),
                plan.added,
                plan.updated,
                plan.unchanged,
                plan.total()
            );
        }
        return ExitCode::SUCCESS;
    }

    // Write a mandatory pre-import backup of the current Registry state before mutating HKCU.
    let backup_path = default_auto_backup_path();
    if let Err(err) = save_snapshot_file(&backup_path, &current_user, &current_sys) {
        eprintln!(
            "lazypath: aborted import: failed to create pre-import backup at '{}': {err}",
            backup_path.display()
        );
        return ExitCode::from(1);
    }

    let summary = match restore_user_snapshot_with_baseline(&snapshot, &current_user) {
        Ok(s) => s,
        Err(err) => {
            eprintln!(
                "lazypath: import failed while writing Registry (backup saved at '{}'): {err}",
                backup_path.display()
            );
            return ExitCode::from(1);
        }
    };

    if let Err(err) = broadcast_environment_change() {
        eprintln!("lazypath: warning: WM_SETTINGCHANGE broadcast failed: {err}");
    }

    if opts.json {
        let report = JsonImportReport {
            schema_version: SCHEMA_VERSION,
            dry_run: false,
            source_path: path.display().to_string(),
            backup_path: Some(backup_path.display().to_string()),
            added: summary.added,
            updated: summary.updated,
            unchanged: summary.unchanged,
            total: summary.total(),
        };
        match serde_json::to_string_pretty(&report) {
            Ok(json) => println!("{json}"),
            Err(err) => {
                eprintln!("lazypath: failed to serialize import JSON report: {err}");
                return ExitCode::from(1);
            }
        }
    } else {
        println!(
            "Imported '{}' into HKCU\\Environment: {} added, {} updated, {} unchanged (pre-import backup at '{}').",
            path.display(),
            summary.added,
            summary.updated,
            summary.unchanged,
            backup_path.display()
        );
    }

    ExitCode::SUCCESS
}

/// Launches the interactive `ratatui` TUI session.
fn run_tui(opts: &CliOptions) -> io::Result<ExitCode> {
    let (user_vars, sys_vars) = match load_all_variables() {
        Ok(vars) => vars,
        Err(err) => {
            eprintln!("lazypath: failed to read Windows Registry environment: {err}");
            return Ok(ExitCode::from(1));
        }
    };

    let mut app = App::new(user_vars, sys_vars, is_elevated());

    if let Some(ref pending_path) = opts.resume_pending_path {
        match load_and_consume_pending_elevation_state(Path::new(pending_path)) {
            Ok(state) => app.apply_pending_elevation(state),
            Err(err) => app.log(
                LogLevel::Warn,
                format!("could not restore pending elevation edits: {err}"),
            ),
        }
    }

    let _session = TerminalSession::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;

    while !app.should_quit {
        terminal.draw(|frame| render(frame, &app))?;

        if event::poll(Duration::from_millis(100))?
            && let Event::Key(key_event) = event::read()?
            && key_event.kind == KeyEventKind::Press
        {
            app.on_key(key_event.code, key_event.modifiers);
        }
    }

    Ok(ExitCode::SUCCESS)
}

/// Builds the combined `PATH` entry list for CLI auditing (`--check` and `--which`).
///
/// When `process_path_override` is `None`, System `PATH` followed by User `PATH` from the
/// Registry is audited. When `Some(raw_process_path)` is provided (`--process-path`), the
/// process's effective `PATH` string is audited and each directory is attributed to
/// [`EnvScope::System`] if it matches a System `PATH` entry or [`EnvScope::User`] otherwise.
fn collect_combined_path_entries(
    user_vars: &[EnvVariable],
    sys_vars: &[EnvVariable],
    process_path_override: Option<&str>,
) -> Vec<PathEntry> {
    let lookup = build_lookup_map(user_vars, sys_vars);

    let sys_raw: Vec<String> = sys_vars
        .iter()
        .find(|v| v.is_path_var())
        .map(|v| split_path_value(&v.value))
        .unwrap_or_default();

    let raw_items: Vec<(String, EnvScope)> = if let Some(proc_path) = process_path_override {
        let sys_keys: std::collections::HashSet<String> =
            sys_raw.iter().map(|s| normalize_path_key(s)).collect();
        split_path_value(proc_path)
            .into_iter()
            .map(|dir| {
                let scope = if sys_keys.contains(&normalize_path_key(&dir)) {
                    EnvScope::System
                } else {
                    EnvScope::User
                };
                (dir, scope)
            })
            .collect()
    } else {
        let user_raw: Vec<String> = user_vars
            .iter()
            .find(|v| v.is_path_var())
            .map(|v| split_path_value(&v.value))
            .unwrap_or_default();

        let mut combined = Vec::with_capacity(sys_raw.len() + user_raw.len());
        combined.extend(sys_raw.into_iter().map(|p| (p, EnvScope::System)));
        combined.extend(user_raw.into_iter().map(|p| (p, EnvScope::User)));
        combined
    };

    analyze_path_entries(&raw_items, &lookup)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lazypath::model::RegValueKind;

    #[test]
    fn collects_registry_and_process_path_entries_with_scope_attribution() {
        let temp_dir = std::env::temp_dir().to_string_lossy().to_string();
        let user_vars = vec![EnvVariable::with_kind(
            "Path",
            r"C:\__lazypath_user_missing__",
            EnvScope::User,
            RegValueKind::ExpandSz,
        )];
        let sys_vars = vec![EnvVariable::with_kind(
            "Path",
            &temp_dir,
            EnvScope::System,
            RegValueKind::ExpandSz,
        )];

        let reg_entries = collect_combined_path_entries(&user_vars, &sys_vars, None);
        assert_eq!(reg_entries.len(), 2);
        assert_eq!(reg_entries[0].scope, EnvScope::System);
        assert!(reg_entries[0].exists);
        assert_eq!(reg_entries[1].scope, EnvScope::User);
        assert!(!reg_entries[1].exists);

        let custom_proc_path = format!(r"{temp_dir};C:\__lazypath_proc_only__");
        let proc_entries =
            collect_combined_path_entries(&user_vars, &sys_vars, Some(&custom_path_ref(&custom_proc_path)));
        assert_eq!(proc_entries.len(), 2);
        assert_eq!(proc_entries[0].scope, EnvScope::System);
        assert_eq!(proc_entries[1].scope, EnvScope::User);
    }

    fn custom_path_ref(s: &str) -> &str {
        s
    }

    #[test]
    fn serializes_json_audit_report_with_schema_version() {
        let summary = AuditSummary {
            total_entries: 1,
            missing_count: 1,
            duplicate_count: 0,
            conflict_entries: 0,
            shadowed_entries: 0,
            total_executables: 0,
        };
        let report = JsonAuditReport {
            schema_version: SCHEMA_VERSION,
            source: "registry",
            summary: &summary,
            entries: &[],
        };
        let json = serde_json::to_string(&report).expect("should serialize report");
        assert!(json.contains("\"schema_version\":1"));
        assert!(json.contains("\"source\":\"registry\""));
    }
}
