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
    /// Search for all matching executables in `PATH` priority order.
    pub which_binary: Option<String>,
    /// Export environment variables snapshot to the given file path.
    pub export_path: Option<String>,
    /// Restore User environment variables from the given snapshot file path.
    pub import_path: Option<String>,
}

/// Parses command-line arguments (excluding `argv[0]`) into [`CliOptions`].
///
/// # Errors
///
/// Returns a descriptive error string if an unknown flag is encountered or if
/// a flag requiring a value (`--which`, `--export`, `--import`) is missing or empty.
pub fn parse_args<I>(args: I) -> Result<CliOptions, String>
where
    I: IntoIterator<Item = String>,
{
    let mut opts = CliOptions::default();
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-h" | "--help" | "help" => opts.show_help = true,
            "-v" | "--version" => opts.show_version = true,
            "-c" | "--check" | "check" => opts.check = true,
            "-j" | "--json" => {
                opts.json = true;
                opts.check = true;
            }
            "-w" | "--which" | "which" => {
                let bin = require_non_empty_arg(
                    &mut iter,
                    "missing <BINARY> argument for --which",
                    "binary query for --which cannot be empty",
                )?;
                opts.which_binary = Some(bin);
            }
            "--export" => {
                let path = require_non_empty_arg(
                    &mut iter,
                    "missing <FILE> argument for --export",
                    "export file path cannot be empty",
                )?;
                opts.export_path = Some(path);
            }
            "--import" => {
                let path = require_non_empty_arg(
                    &mut iter,
                    "missing <FILE> argument for --import",
                    "import file path cannot be empty",
                )?;
                opts.import_path = Some(path);
            }
            _ => {
                return Err(format!("unknown argument '{arg}'"));
            }
        }
    }
    Ok(opts)
}

/// Extracts and validates the next argument token for a value-taking CLI flag.
fn require_non_empty_arg(
    iter: &mut impl Iterator<Item = String>,
    missing_msg: &str,
    empty_msg: &str,
) -> Result<String, String> {
    let Some(val) = iter.next() else {
        return Err(missing_msg.to_string());
    };
    if val.trim().is_empty() {
        return Err(empty_msg.to_string());
    }
    Ok(val)
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
  -w, --which <BINARY>  Find all executables matching <BINARY> across PATH in priority order
  -j, --json            Print audit or which results as structured JSON and exit
      --export <FILE>   Save a JSON snapshot of User and System environment variables
      --import <FILE>   Restore User environment variables from a JSON snapshot
  -h, --help            Show this help message and exit
  -v, --version         Show version information and exit
Examples:
  lazypath
  lazypath --check
  lazypath --which python
  lazypath --check --json
  lazypath --export env-backup.json"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_which_and_json_flags() {
        let opts = parse_args([
            "--which".to_string(),
            "python".to_string(),
            "--json".to_string(),
        ])
        .unwrap();
        assert_eq!(opts.which_binary.as_deref(), Some("python"));
        assert!(opts.json);
    }

    #[test]
    fn parses_export_and_import_flags() {
        let opts = parse_args(["--export".to_string(), "snap.json".to_string()]).unwrap();
        assert_eq!(opts.export_path.as_deref(), Some("snap.json"));
    }

    #[test]
    fn rejects_unknown_or_incomplete_flags() {
        assert!(parse_args(["--which".to_string()]).is_err());
        assert!(parse_args(["--export".to_string(), String::new()]).is_err());
        assert!(parse_args(["--bogus".to_string()]).is_err());
    }
}
