//! Command-line argument parsing, validation, and usage help text.

/// Parsed command-line flags and options.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CliOptions {
    /// Print help text and exit.
    pub show_help: bool,
    /// Print version string and exit.
    pub show_version: bool,
    /// Run non-interactive `PATH` health check and exit.
    pub check: bool,
    /// Format output as pretty-printed JSON.
    pub json: bool,
    /// Exit with code 0 on `--check` even when missing, duplicate, or conflicting entries exist.
    pub no_fail: bool,
    /// Preview `--import` changes without modifying the Windows Registry.
    pub dry_run: bool,
    /// Inspect the current process `PATH` (`std::env::var_os("PATH")`) instead of the registry.
    pub process_path: bool,
    /// Search for all matching executables in `PATH` priority order.
    pub which_binary: Option<String>,
    /// Export environment variables snapshot to the given file path.
    pub export_path: Option<String>,
    /// Restore User environment variables from the given snapshot file path.
    pub import_path: Option<String>,
    /// Resume unsaved TUI edits from a pending state file after UAC elevation.
    pub resume_pending_path: Option<String>,
}

/// Parses command-line arguments (excluding `argv[0]`) into [`CliOptions`].
///
/// # Errors
///
/// Returns a descriptive error string if an unknown flag is encountered, if a flag
/// requiring a value (`--which`, `--export`, `--import`, `--resume-pending`) is missing,
/// empty, or followed immediately by another flag, or if mutually exclusive modes are combined.
pub fn parse_args<I>(args: I) -> Result<CliOptions, String>
where
    I: IntoIterator<Item = String>,
{
    let mut opts = CliOptions::default();
    let mut iter = args.into_iter().peekable();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-h" | "--help" | "help" => opts.show_help = true,
            "-v" | "-V" | "--version" => opts.show_version = true,
            "-c" | "--check" | "check" => opts.check = true,
            "-j" | "--json" => opts.json = true,
            "--no-fail" => opts.no_fail = true,
            "-n" | "--dry-run" => opts.dry_run = true,
            "--process-path" => opts.process_path = true,
            "-w" | "--which" | "which" => {
                let bin = require_non_empty_arg(
                    &mut iter,
                    "--which",
                    "missing <BINARY> argument for --which",
                    "binary query for --which cannot be empty",
                )?;
                opts.which_binary = Some(bin);
            }
            "--export" => {
                let path = require_non_empty_arg(
                    &mut iter,
                    "--export",
                    "missing <FILE> argument for --export",
                    "export file path cannot be empty",
                )?;
                opts.export_path = Some(path);
            }
            "--import" => {
                let path = require_non_empty_arg(
                    &mut iter,
                    "--import",
                    "missing <FILE> argument for --import",
                    "import file path cannot be empty",
                )?;
                opts.import_path = Some(path);
            }
            "--resume-pending" => {
                let path = require_non_empty_arg(
                    &mut iter,
                    "--resume-pending",
                    "missing <FILE> argument for --resume-pending",
                    "pending state file path cannot be empty",
                )?;
                opts.resume_pending_path = Some(path);
            }
            _ if arg.starts_with("--which=") => {
                let val = &arg["--which=".len()..];
                validate_inline_arg(val, "--which", "binary query for --which cannot be empty")?;
                opts.which_binary = Some(val.to_string());
            }
            _ if arg.starts_with("--export=") => {
                let val = &arg["--export=".len()..];
                validate_inline_arg(val, "--export", "export file path cannot be empty")?;
                opts.export_path = Some(val.to_string());
            }
            _ if arg.starts_with("--import=") => {
                let val = &arg["--import=".len()..];
                validate_inline_arg(val, "--import", "import file path cannot be empty")?;
                opts.import_path = Some(val.to_string());
            }
            _ if arg.starts_with("--resume-pending=") => {
                let val = &arg["--resume-pending=".len()..];
                validate_inline_arg(
                    val,
                    "--resume-pending",
                    "pending state file path cannot be empty",
                )?;
                opts.resume_pending_path = Some(val.to_string());
            }
            _ => {
                return Err(format!("unknown argument '{arg}'"));
            }
        }
    }

    validate_option_combinations(&mut opts)?;
    Ok(opts)
}

/// Extracts and validates the next argument token for a value-taking CLI flag,
/// rejecting missing values, blank strings, or subsequent option flags.
fn require_non_empty_arg(
    iter: &mut impl Iterator<Item = String>,
    flag_name: &str,
    missing_msg: &str,
    empty_msg: &str,
) -> Result<String, String> {
    let Some(val) = iter.next() else {
        return Err(missing_msg.to_string());
    };
    let trimmed = val.trim();
    if trimmed.is_empty() {
        return Err(empty_msg.to_string());
    }
    if trimmed.starts_with('-') {
        return Err(format!(
            "expected value for {flag_name}, but found flag '{trimmed}'"
        ));
    }
    Ok(val)
}

fn validate_inline_arg(val: &str, flag_name: &str, empty_msg: &str) -> Result<(), String> {
    let trimmed = val.trim();
    if trimmed.is_empty() {
        return Err(empty_msg.to_string());
    }
    if trimmed.starts_with('-') {
        return Err(format!(
            "expected value for {flag_name}, but found flag '{trimmed}'"
        ));
    }
    Ok(())
}

/// Validates that mutually exclusive CLI modes are not combined and applies default mode inference.
fn validate_option_combinations(opts: &mut CliOptions) -> Result<(), String> {
    if opts.show_help || opts.show_version {
        return Ok(());
    }

    let mode_count = usize::from(opts.check)
        + usize::from(opts.which_binary.is_some())
        + usize::from(opts.export_path.is_some())
        + usize::from(opts.import_path.is_some())
        + usize::from(opts.resume_pending_path.is_some());

    if mode_count > 1 {
        return Err(
            "conflicting options: --check, --which, --export, and --import cannot be combined"
                .to_string(),
        );
    }

    // Passing `--json` without an explicit mode defaults to `--check --json`.
    if opts.json
        && !opts.check
        && opts.which_binary.is_none()
        && opts.export_path.is_none()
        && opts.import_path.is_none()
    {
        opts.check = true;
    }

    if opts.dry_run && opts.import_path.is_none() {
        return Err("--dry-run can only be used together with --import <FILE>".to_string());
    }

    Ok(())
}

/// Returns the static CLI `--help` text.
#[must_use]
pub const fn help_text() -> &'static str {
    "\
lazypath - minimalist TUI and CLI Windows PATH and environment variable auditor

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

Examples:
  lazypath
  lazypath --check
  lazypath --check --json
  lazypath --which python
  lazypath --export env-backup.json
  lazypath --import env-backup.json --dry-run"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_which_and_json_flags_without_enabling_check() {
        let opts = parse_args([
            "--which".to_string(),
            "python".to_string(),
            "--json".to_string(),
        ])
        .unwrap();
        assert_eq!(opts.which_binary.as_deref(), Some("python"));
        assert!(opts.json);
        assert!(!opts.check);
    }

    #[test]
    fn standalone_json_flag_defaults_to_check_mode() {
        let opts = parse_args(["--json".to_string()]).unwrap();
        assert!(opts.json);
        assert!(opts.check);
    }

    #[test]
    fn parses_export_import_dry_run_and_inline_equals_syntax() {
        let export_opts = parse_args(["--export=snap.json".to_string()]).unwrap();
        assert_eq!(export_opts.export_path.as_deref(), Some("snap.json"));

        let import_opts = parse_args([
            "--import".to_string(),
            "snap.json".to_string(),
            "--dry-run".to_string(),
        ])
        .unwrap();
        assert_eq!(import_opts.import_path.as_deref(), Some("snap.json"));
        assert!(import_opts.dry_run);
    }

    #[test]
    fn rejects_unknown_incomplete_swallowed_flag_or_conflicting_modes() {
        assert!(parse_args(["--which".to_string()]).is_err());
        assert!(parse_args(["--which".to_string(), "--json".to_string()]).is_err());
        assert!(parse_args(["--export".to_string(), "--check".to_string()]).is_err());
        assert!(parse_args(["--export".to_string(), String::new()]).is_err());
        assert!(parse_args(["--bogus".to_string()]).is_err());
        assert!(parse_args([
            "--export".to_string(),
            "a.json".to_string(),
            "--import".to_string(),
            "b.json".to_string(),
        ])
        .is_err());
        assert!(parse_args(["--check".to_string(), "--dry-run".to_string()]).is_err());
    }
}
