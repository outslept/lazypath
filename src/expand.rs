//! Environment variable `%VAR%` expansion, Windows `PATH` splitting/joining, and path normalization.

use std::collections::HashMap;
use std::env;

/// Maximum number of expansion passes performed by [`expand_env_vars`] to resolve
/// nested `%VAR%` references (e.g., `%CARGO_HOME%\bin` -> `%USERPROFILE%\.cargo\bin`)
/// while guarding against self-referential cycles (`A=%B%`, `B=%A%`).
const MAX_EXPAND_PASSES: usize = 8;

/// Expands Windows-style `%VAR%` placeholders using `lookup` (keyed by uppercase name),
/// falling back to the current process environment (`std::env::var_os`).
///
/// Performs up to [`MAX_EXPAND_PASSES`] passes so nested variable definitions resolve
/// completely. Unresolved placeholders and literal `%` characters are left intact.
#[must_use]
pub fn expand_env_vars(input: &str, lookup: &HashMap<String, String>) -> String {
    let mut current = input.to_string();
    for _ in 0..MAX_EXPAND_PASSES {
        if !current.contains('%') {
            break;
        }
        let next = expand_single_pass(&current, lookup);
        if next == current {
            break;
        }
        current = next;
    }
    current
}

/// Performs a single left-to-right `%VAR%` expansion pass over `input`.
fn expand_single_pass(input: &str, lookup: &HashMap<String, String>) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars();

    while let Some(ch) = chars.next() {
        if ch != '%' {
            result.push(ch);
            continue;
        }

        let mut token = String::new();
        let mut closed = false;
        let mut aborted_by_delimiter = None;

        for next_ch in chars.by_ref() {
            if next_ch == '%' {
                closed = true;
                break;
            }
            // A valid environment variable reference inside a path cannot span across
            // path separators, entry delimiters, or assignment characters. Treating
            // such characters as abort points prevents a stray literal `%` in one
            // directory name from swallowing the opening `%` of a later `%VAR%`.
            if matches!(next_ch, '\\' | '/' | ';' | '=' | '\r' | '\n' | '\0') {
                aborted_by_delimiter = Some(next_ch);
                break;
            }
            token.push(next_ch);
        }

        if let Some(delim) = aborted_by_delimiter {
            result.push('%');
            result.push_str(&token);
            result.push(delim);
        } else if closed {
            if token.is_empty() {
                result.push_str("%%");
            } else if let Some(val) = resolve_token(&token, lookup) {
                result.push_str(&val);
            } else {
                result.push('%');
                result.push_str(&token);
                result.push('%');
            }
        } else {
            result.push('%');
            result.push_str(&token);
        }
    }

    result
}

/// Resolves a variable name against `lookup` (using uppercase key matching) or the process environment.
fn resolve_token(token: &str, lookup: &HashMap<String, String>) -> Option<String> {
    let upper = token.to_uppercase();
    if let Some(val) = lookup.get(&upper) {
        return Some(val.clone());
    }
    if let Some(val) = lookup.get(&token.to_ascii_uppercase()) {
        return Some(val.clone());
    }
    env::var_os(token).map(|os| os.to_string_lossy().into_owned())
}

/// Normalizes a Windows directory path for case-insensitive duplicate detection.
///
/// Strips surrounding whitespace and quotes, converts forward slashes to backslashes,
/// collapses redundant internal backslashes (preserving leading UNC `\\`), removes
/// trailing backslashes (except on drive roots such as `C:\`), and applies full
/// Unicode lowercasing so non-ASCII paths (`C:\Пользователи` vs `c:\пользователи`) match.
#[must_use]
pub fn normalize_path_key(path: &str) -> String {
    let unquoted = strip_outer_quotes_and_trim(path);
    if unquoted.is_empty() {
        return String::new();
    }

    let slash_normalized = unquoted.replace('/', r"\");
    let is_unc = slash_normalized.starts_with(r"\\");

    let mut collapsed = String::with_capacity(slash_normalized.len());
    if is_unc {
        collapsed.push_str(r"\\");
    }

    let body = if is_unc {
        slash_normalized.trim_start_matches('\\')
    } else {
        slash_normalized.as_str()
    };

    let mut prev_backslash = false;
    for ch in body.chars() {
        if ch == '\\' {
            if !prev_backslash {
                collapsed.push('\\');
            }
            prev_backslash = true;
        } else {
            collapsed.push(ch);
            prev_backslash = false;
        }
    }

    let trimmed = collapsed.trim_end_matches('\\');
    if trimmed.is_empty() {
        return collapsed.to_lowercase();
    }

    // Preserve the root backslash on drive specifications (`C:\` vs relative `C:`).
    if is_drive_designator(trimmed) && collapsed.ends_with('\\') {
        let mut root = trimmed.to_lowercase();
        root.push('\\');
        return root;
    }

    trimmed.to_lowercase()
}

/// Returns `true` if `s` is a two-character Windows drive designator such as `"C:"`.
fn is_drive_designator(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

/// Splits a semicolon-delimited Windows `PATH` string into cleaned, non-empty directory entries.
///
/// Semicolons enclosed in double quotes (e.g., `"C:\Music ; Audio"`) are preserved as part of
/// the directory path rather than treated as entry separators.
#[must_use]
pub fn split_path_value(raw_path: &str) -> Vec<String> {
    let mut entries = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for ch in raw_path.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
            }
            ';' if !in_quotes => {
                let cleaned = current.trim();
                if !cleaned.is_empty() {
                    entries.push(cleaned.to_string());
                }
                current.clear();
            }
            _ => {
                current.push(ch);
            }
        }
    }

    let tail = current.trim();
    if !tail.is_empty() {
        entries.push(tail.to_string());
    }

    entries
}

/// Joins a slice of directory entries into a semicolon-delimited Windows `PATH` string.
///
/// Entries containing literal semicolons (`;`) are automatically wrapped in double quotes
/// so Windows and [`split_path_value`] preserve them as single directories.
#[must_use]
pub fn join_path_entries(entries: &[String]) -> String {
    let mut formatted = Vec::with_capacity(entries.len());
    for entry in entries {
        let cleaned = strip_outer_quotes_and_trim(entry).replace('"', "");
        let trimmed = cleaned.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.contains(';') {
            formatted.push(format!("\"{trimmed}\""));
        } else {
            formatted.push(trimmed.to_string());
        }
    }
    formatted.join(";")
}

/// Strips outer whitespace and matching or stray surrounding double quotes.
fn strip_outer_quotes_and_trim(s: &str) -> &str {
    s.trim().trim_matches('"').trim()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_percent_placeholders_case_insensitively_and_recursively() {
        let mut map = HashMap::new();
        map.insert("USERPROFILE".to_string(), r"C:\Users\Alice".to_string());
        map.insert(
            "CARGO_HOME".to_string(),
            r"%userprofile%\.cargo".to_string(),
        );
        map.insert("RUST_BIN".to_string(), r"%CARGO_HOME%\bin".to_string());

        let expanded = expand_env_vars(r"%rust_bin%;%UNKNOWN%", &map);
        assert_eq!(expanded, r"C:\Users\Alice\.cargo\bin;%UNKNOWN%");
    }

    #[test]
    fn guards_against_cyclic_variable_references() {
        let mut map = HashMap::new();
        map.insert("LOOP_A".to_string(), r"%LOOP_B%\bin".to_string());
        map.insert("LOOP_B".to_string(), r"%LOOP_A%\sub".to_string());

        let expanded = expand_env_vars(r"%LOOP_A%", &map);
        assert!(!expanded.is_empty());
    }

    #[test]
    fn stray_percent_does_not_corrupt_subsequent_placeholders() {
        let mut map = HashMap::new();
        map.insert("USERPROFILE".to_string(), r"C:\Users\Alice".to_string());

        let expanded = expand_env_vars(r"C:\100%\Tools;%USERPROFILE%\bin", &map);
        assert_eq!(expanded, r"C:\100%\Tools;C:\Users\Alice\bin");
    }

    #[test]
    fn normalizes_windows_paths_including_unicode_root_and_redundant_slashes() {
        assert_eq!(
            normalize_path_key(r#" "C:/Users/Alice//.cargo\bin\" "#),
            r"c:\users\alice\.cargo\bin"
        );
        assert_eq!(
            normalize_path_key(r"C:\Users\Alice\.cargo\bin"),
            r"c:\users\alice\.cargo\bin"
        );
        // Unicode Cyrillic case-folding
        assert_eq!(
            normalize_path_key(r"C:\Пользователи\Аня\AppData\"),
            normalize_path_key(r"c:\пользователи\аня\appdata")
        );
        // Drive root vs drive-relative
        assert_eq!(normalize_path_key(r"C:\"), r"c:\");
        assert_eq!(normalize_path_key(r"C:"), r"c:");
        // UNC paths keep leading double backslash
        assert_eq!(
            normalize_path_key(r"\\Fileserver\Shared\\Tools\"),
            r"\\fileserver\shared\tools"
        );
    }

    #[test]
    fn splits_and_joins_semicolon_path_lists_preserving_quoted_semicolons() {
        let raw = r#"C:\Windows\System32; "C:\Music ; Audio\bin" ; ; "C:\Users\Me\.cargo\bin"; C:\Git\cmd"#;
        let parts = split_path_value(raw);
        assert_eq!(
            parts,
            vec![
                r"C:\Windows\System32",
                r"C:\Music ; Audio\bin",
                r"C:\Users\Me\.cargo\bin",
                r"C:\Git\cmd",
            ]
        );
        let joined = join_path_entries(&parts);
        assert_eq!(
            joined,
            r#"C:\Windows\System32;"C:\Music ; Audio\bin";C:\Users\Me\.cargo\bin;C:\Git\cmd"#
        );
        // Round-trip stability
        assert_eq!(split_path_value(&joined), parts);
    }
}
