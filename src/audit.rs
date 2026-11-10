use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use crate::expand::{expand_env_vars, normalize_path_key};
use crate::model::{EnvScope, PathEntry};

const EXECUTABLE_EXTENSIONS: [&str; 4] = ["exe", "cmd", "bat", "com"];

pub fn is_executable_filename(name: &str) -> bool {
    let Some((_, ext)) = name.rsplit_once('.') else {
        return false;
    };
    EXECUTABLE_EXTENSIONS
        .iter()
        .any(|candidate| ext.eq_ignore_ascii_case(candidate))
}

pub fn scan_directory_executables(dir_path: &Path) -> Vec<String> {
    let Ok(read_dir) = fs::read_dir(dir_path) else {
        return Vec::new();
    };

    let mut names = Vec::new();
    for entry in read_dir.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_file() && !file_type.is_symlink() {
            continue;
        }
        let file_name = entry.file_name().to_string_lossy().to_string();
        if is_executable_filename(&file_name) {
            names.push(file_name);
        }
    }

    names.sort_by_key(|n| n.to_ascii_lowercase());
    names.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
    names
}

pub fn build_base_entries(
    raw_items: &[(String, EnvScope)],
    lookup: &HashMap<String, String>,
) -> Vec<PathEntry> {
    let mut seen_dirs = HashSet::new();
    let mut entries = Vec::with_capacity(raw_items.len());

    for (index, (raw, scope)) in raw_items.iter().enumerate() {
        let expanded = expand_env_vars(raw, lookup);
        let norm_key = normalize_path_key(&expanded);
        let is_duplicate = !norm_key.is_empty() && !seen_dirs.insert(norm_key);
        let dir_path = Path::new(&expanded);
        let exists = dir_path.is_dir();
        let executables = if exists && !is_duplicate {
            scan_directory_executables(dir_path)
        } else {
            Vec::new()
        };

        entries.push(PathEntry {
            index,
            raw: raw.clone(),
            expanded,
            scope: *scope,
            exists,
            is_duplicate,
            executables,
            shadows: Vec::new(),
            shadowed_by: Vec::new(),
        });
    }

    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_windows_executable_extensions() {
        assert!(is_executable_filename("python.exe"));
        assert!(is_executable_filename("npm.CMD"));
        assert!(is_executable_filename("gradlew.bat"));
        assert!(!is_executable_filename("readme.md"));
        assert!(!is_executable_filename("lib.dll"));
    }

    #[test]
    fn detects_missing_and_duplicate_directories() {
        let temp_dir = std::env::temp_dir().to_string_lossy().to_string();
        let raw_items = vec![
            (temp_dir.clone(), EnvScope::User),
            (temp_dir, EnvScope::System),
            (
                r"C:\__lazypath_nonexistent_dir_12345__".to_string(),
                EnvScope::User,
            ),
        ];
        let entries = build_base_entries(&raw_items, &HashMap::new());
        assert_eq!(entries.len(), 3);
        assert!(entries[0].exists);
        assert!(!entries[0].is_duplicate);
        assert!(entries[1].is_duplicate);
        assert!(!entries[2].exists);
    }
}
