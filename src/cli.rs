#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CliOptions {
    pub show_help: bool,
    pub show_version: bool,
    pub check: bool,
    pub json: bool,
    pub which_binary: Option<String>,
    pub export_path: Option<String>,
    pub import_path: Option<String>,
}

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
                let Some(bin) = iter.next() else {
                    return Err("missing <BINARY> argument for --which".to_string());
                };
                if bin.trim().is_empty() {
                    return Err("binary query for --which cannot be empty".to_string());
                }
                opts.which_binary = Some(bin);
            }
            "--export" => {
                let Some(path) = iter.next() else {
                    return Err("missing <FILE> argument for --export".to_string());
                };
                if path.trim().is_empty() {
                    return Err("export file path cannot be empty".to_string());
                }
                opts.export_path = Some(path);
            }
            "--import" => {
                let Some(path) = iter.next() else {
                    return Err("missing <FILE> argument for --import".to_string());
                };
                if path.trim().is_empty() {
                    return Err("import file path cannot be empty".to_string());
                }
                opts.import_path = Some(path);
            }
            _ => {
                return Err(format!("unknown argument '{arg}'"));
            }
        }
    }

    Ok(opts)
}

pub fn help_text() -> &'static str {
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
        assert!(parse_args(["--export".to_string(), "".to_string()]).is_err());
        assert!(parse_args(["--bogus".to_string()]).is_err());
    }
}
