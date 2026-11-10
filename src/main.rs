use std::path::Path;
use std::process::ExitCode;

use serde::Serialize;

use lazypath::audit::{analyze_path_entries, summarize_audit, which_all};
use lazypath::cli::{help_text, parse_args, CliOptions};
use lazypath::expand::split_path_value;
use lazypath::model::{AuditSummary, EnvScope, EnvVariable, PathEntry};
use lazypath::registry::{broadcast_environment_change, build_lookup_map, load_all_variables};
use lazypath::snapshot::{load_snapshot_file, restore_user_snapshot, save_snapshot_file};

#[derive(Serialize)]
struct JsonAuditReport {
    summary: AuditSummary,
    entries: Vec<PathEntry>,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let opts = match parse_args(args) {
        Ok(opts) => opts,
        Err(err) => {
            eprintln!("error: {err}");
            eprintln!("hint: run 'lazypath --help' for usage.");
            return ExitCode::from(2);
        }
    };

    if opts.show_help {
        println!("{}", help_text());
        return ExitCode::SUCCESS;
    }

    if opts.show_version {
        println!("lazypath {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }

    if let Some(export_file) = &opts.export_path {
        return run_export(Path::new(export_file));
    }

    if let Some(import_file) = &opts.import_path {
        return run_import(Path::new(import_file));
    }

    if let Some(query) = &opts.which_binary {
        return run_which(query, opts.json);
    }

    if opts.check || opts.json {
        return run_check(&opts);
    }

    run_check(&opts)
}

fn collect_combined_path_entries() -> Vec<PathEntry> {
    let (user_vars, sys_vars) = load_all_variables();
    let lookup = build_lookup_map(&user_vars, &sys_vars);
    let mut raw_items: Vec<(String, EnvScope)> = Vec::new();

    append_scope_path(&sys_vars, EnvScope::System, &mut raw_items);
    append_scope_path(&user_vars, EnvScope::User, &mut raw_items);

    analyze_path_entries(&raw_items, &lookup)
}

fn append_scope_path(vars: &[EnvVariable], scope: EnvScope, out: &mut Vec<(String, EnvScope)>) {
    if let Some(path_var) = vars.iter().find(|v| v.is_path_var()) {
        for part in split_path_value(&path_var.value) {
            out.push((part, scope));
        }
    }
}

fn run_export(path: &Path) -> ExitCode {
    let (user_vars, sys_vars) = load_all_variables();
    match save_snapshot_file(path, &user_vars, &sys_vars) {
        Ok(()) => {
            println!("ok: exported environment snapshot to '{}'", path.display());
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(1)
        }
    }
}

fn run_import(path: &Path) -> ExitCode {
    let snapshot = match load_snapshot_file(path) {
        Ok(s) => s,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::from(1);
        }
    };

    match restore_user_snapshot(&snapshot) {
        Ok(count) => {
            broadcast_environment_change();
            println!(
                "ok: restored {count} User environment variables from '{}'",
                path.display()
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(1)
        }
    }
}

fn run_which(query: &str, as_json: bool) -> ExitCode {
    let entries = collect_combined_path_entries();
    let matches = which_all(&entries, query);

    if as_json {
        if let Ok(json) = serde_json::to_string_pretty(&matches) {
            println!("{json}");
            return ExitCode::SUCCESS;
        }
        return ExitCode::from(1);
    }

    if matches.is_empty() {
        eprintln!("warn: no executable matching '{query}' found in PATH");
        return ExitCode::from(1);
    }

    println!(
        "{:<10} {:<6} {:<8} {:<18} FULL PATH",
        "STATUS", "ORDER", "SCOPE", "BINARY"
    );
    for m in &matches {
        let role = if m.is_winner { "WINNER" } else { "SHADOWED" };
        println!(
            "{:<10} #{:<5} {:<8} {:<18} {}",
            role,
            m.entry_index + 1,
            m.scope.label(),
            m.binary,
            m.full_path
        );
    }

    ExitCode::SUCCESS
}

fn run_check(opts: &CliOptions) -> ExitCode {
    let entries = collect_combined_path_entries();
    let summary = summarize_audit(&entries);

    if opts.json {
        let report = JsonAuditReport { summary, entries };
        match serde_json::to_string_pretty(&report) {
            Ok(json) => {
                println!("{json}");
                return ExitCode::SUCCESS;
            }
            Err(err) => {
                eprintln!("error: {err}");
                return ExitCode::from(1);
            }
        }
    }

    println!(
        "PATH Audit Summary: {} entries | {} missing | {} duplicates | {} conflicts | {} shadowed | {} executables\n",
        summary.total_entries,
        summary.missing_count,
        summary.duplicate_count,
        summary.conflict_entries,
        summary.shadowed_entries,
        summary.total_executables
    );

    println!("{:<5} {:<8} {:<14} DIRECTORY", "#", "SCOPE", "STATUS");
    for entry in &entries {
        let badge = entry.status().badge(entry.executables.len());
        println!(
            "#{:<4} {:<8} {:<14} {}",
            entry.index + 1,
            entry.scope.label(),
            badge,
            entry.expanded
        );
        if let Some(warn) = entry.headline_warning() {
            println!("      -> warn: {warn}");
        }
    }

    ExitCode::SUCCESS
}
