use std::collections::HashMap;

/// Expands Windows-style `%VAR%` placeholders using `lookup` (keyed by uppercase name),
/// falling back to the current process environment. Unresolved placeholders are left intact.
#[must_use]
pub fn expand_env_vars(input: &str, lookup: &HashMap<String, String>) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars();
    while let Some(ch) = chars.next() {
        if ch == '%' {
            let mut token = String::new();
            let mut closed = false;
            for next_ch in chars.by_ref() {
                if next_ch == '%' {
                    closed = true;
                    break;
                }
                token.push(next_ch);
            }
            if closed && !token.is_empty() {
                let key = token.to_ascii_uppercase();
                if let Some(val) = lookup.get(&key) {
                    result.push_str(val);
                } else if let Ok(env_val) = std::env::var(&token) {
                    result.push_str(&env_val);
                } else {
                    result.push('%');
                    result.push_str(&token);
                    result.push('%');
                }
            } else {
                result.push('%');
                result.push_str(&token);
            }
        } else {
            result.push(ch);
        }
    }
    result
}

/// Normalizes a Windows directory path for case-insensitive duplicate detection.
///
/// Strips surrounding whitespace and quotes, converts forward slashes to backslashes,
/// removes trailing backslashes, and lowercases ASCII characters.
#[must_use]
pub fn normalize_path_key(path: &str) -> String {
    let replaced = path.trim().trim_matches('"').replace('/', r"\");
    let trimmed = replaced.trim_end_matches('\\');
    if trimmed.is_empty() {
        replaced.to_ascii_lowercase()
    } else {
        trimmed.to_ascii_lowercase()
    }
}

/// Splits a semicolon-delimited `PATH` string into cleaned, non-empty directory entries.
#[must_use]
pub fn split_path_value(raw_path: &str) -> Vec<String> {
    raw_path
        .split(';')
        .map(|part| part.trim().trim_matches('"').to_string())
        .filter(|part| !part.is_empty())
        .collect()
}

/// Joins a slice of directory entries into a semicolon-delimited Windows `PATH` string.
#[must_use]
pub fn join_path_entries(entries: &[String]) -> String {
    entries
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(";")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_percent_placeholders_case_insensitively() {
        let mut map = HashMap::new();
        map.insert("USERPROFILE".to_string(), r"C:\Users\Alice".to_string());
        map.insert(
            "CARGO_HOME".to_string(),
            r"C:\Users\Alice\.cargo".to_string(),
        );
        let expanded = expand_env_vars(r"%userprofile%\bin;%CARGO_HOME%\bin;%UNKNOWN%", &map);
        assert_eq!(
            expanded,
            r"C:\Users\Alice\bin;C:\Users\Alice\.cargo\bin;%UNKNOWN%"
        );
    }

    #[test]
    fn normalizes_windows_paths_for_dedup() {
        assert_eq!(
            normalize_path_key(r#" "C:/Users/Alice/.cargo/bin\" "#),
            r"c:\users\alice\.cargo\bin"
        );
        assert_eq!(
            normalize_path_key(r"C:\Users\Alice\.cargo\bin"),
            r"c:\users\alice\.cargo\bin"
        );
    }

    #[test]
    fn splits_and_joins_semicolon_path_lists() {
        let raw = r#"C:\Windows\System32; "C:\Users\Me\.cargo\bin" ; ; C:\Git\cmd"#;
        let parts = split_path_value(raw);
        assert_eq!(
            parts,
            vec![
                r"C:\Windows\System32",
                r"C:\Users\Me\.cargo\bin",
                r"C:\Git\cmd"
            ]
        );
        assert_eq!(
            join_path_entries(&parts),
            r"C:\Windows\System32;C:\Users\Me\.cargo\bin;C:\Git\cmd"
        );
    }
}
