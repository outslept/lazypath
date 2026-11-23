use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use serde::Serialize;

use crate::expand::{expand_env_vars, normalize_path_key};
use crate::model::{AuditSummary, EnvScope, PathEntry, PathStatus, ShadowTarget};

/// Standard Windows command processor executable extensions.
const EXECUTABLE_EXTENSIONS: [&str; 4] = ["exe", "cmd", "bat", "com"];

/// A single executable match returned by [`which_all`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WhichMatch {
    /// Executable filename (e.g., `python.exe`).
    pub binary: String,
    /// Full resolved path on disk.
    pub full_path: String,
    /// Zero-based index of the containing `PATH` directory.
    pub entry_index: usize,
    /// Originating scope ([`EnvScope::User`] or [`EnvScope::System`]).
    pub scope: EnvScope,
    /// `true` if this is the first matching binary of that filename in `PATH` order.
    pub is_winner: bool,
}

/// Internal record of a shadowing conflict between an earlier and a later `PATH` entry.
struct DiscoveredConflict {
    winner_idx: usize,
    shadowed_idx: usize,
    binary: String,
}

/// Returns `true` if `name` ends with a standard Windows executable extension
/// (`.exe`, `.cmd`, `.bat`, `.com`), ignoring ASCII case.
#[must_use]
pub fn is_executable_filename(name: &str) -> bool {
    let Some((_, ext)) = name.rsplit_once('.') else {
        return false;
    };
    EXECUTABLE_EXTENSIONS
        .iter()
        .any(|candidate| ext.eq_ignore_ascii_case(candidate))
}

/// Scans `dir_path` (non-recursively) and returns a sorted, case-insensitively deduplicated
/// list of executable filenames.
#[must_use]
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

/// Expands variables, detects duplicates, checks disk existence, and scans executables
/// for each raw `(directory, scope)` pair without computing the shadow graph yet.
#[must_use]
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

/// Populates [`PathEntry::shadows`] and [`PathEntry::shadowed_by`] across `entries`
/// based on top-to-bottom `PATH` priority order.
pub fn populate_shadow_graph(entries: &mut [PathEntry]) {
    for entry in entries.iter_mut() {
        entry.shadows.clear();
        entry.shadowed_by.clear();
    }
    let mut winners: HashMap<String, usize> = HashMap::new();
    let mut discovered_conflicts: Vec<DiscoveredConflict> = Vec::new();
    for entry in entries.iter() {
        if !entry.exists || entry.is_duplicate {
            continue;
        }
        for exe in &entry.executables {
            let key = exe.to_ascii_lowercase();
            if let Some(&winner_idx) = winners.get(&key) {
                discovered_conflicts.push(DiscoveredConflict {
                    winner_idx,
                    shadowed_idx: entry.index,
                    binary: exe.clone(),
                });
            } else {
                winners.insert(key, entry.index);
            }
        }
    }
    for conflict in discovered_conflicts {
        let Some(winner_dir) = entries.get(conflict.winner_idx).map(|e| e.expanded.clone()) else {
            continue;
        };
        let Some(shadowed_dir) = entries
            .get(conflict.shadowed_idx)
            .map(|e| e.expanded.clone())
        else {
            continue;
        };
        if let Some(winner_entry) = entries.get_mut(conflict.winner_idx) {
            winner_entry.shadows.push(ShadowTarget {
                binary: conflict.binary.clone(),
                other_index: conflict.shadowed_idx,
                other_dir: shadowed_dir,
            });
        }
        if let Some(shadowed_entry) = entries.get_mut(conflict.shadowed_idx) {
            shadowed_entry.shadowed_by.push(ShadowTarget {
                binary: conflict.binary,
                other_index: conflict.winner_idx,
                other_dir: winner_dir,
            });
        }
    }
}

/// Performs a full audit of `raw_items`, returning [`PathEntry`] records with shadow graphs populated.
#[must_use]
pub fn analyze_path_entries(
    raw_items: &[(String, EnvScope)],
    lookup: &HashMap<String, String>,
) -> Vec<PathEntry> {
    let mut entries = build_base_entries(raw_items, lookup);
    populate_shadow_graph(&mut entries);
    entries
}

/// Computes aggregate [`AuditSummary`] counts from audited [`PathEntry`] records.
#[must_use]
pub fn summarize_audit(entries: &[PathEntry]) -> AuditSummary {
    let mut summary = AuditSummary {
        total_entries: entries.len(),
        ..AuditSummary::default()
    };
    for entry in entries {
        summary.total_executables += entry.executables.len();
        match entry.status() {
            PathStatus::Missing => summary.missing_count += 1,
            PathStatus::Duplicate => summary.duplicate_count += 1,
            PathStatus::Conflict => summary.conflict_entries += 1,
            PathStatus::Shadowed => summary.shadowed_entries += 1,
            PathStatus::Ok => {}
        }
    }
    summary
}

/// Finds all executables matching `query` across `entries` in `PATH` resolution order.
///
/// If `query` includes an extension (contains `.`), matches the exact filename
/// case-insensitively; otherwise matches either the exact stem or substring.
#[must_use]
pub fn which_all(entries: &[PathEntry], query: &str) -> Vec<WhichMatch> {
    let q = query.trim().to_ascii_lowercase();
    if q.is_empty() {
        return Vec::new();
    }
    let has_ext = q.contains('.');
    let mut matches = Vec::new();
    let mut seen_winners = HashSet::new();
    for entry in entries {
        if !entry.exists || entry.is_duplicate {
            continue;
        }
        for exe in &entry.executables {
            let lower_exe = exe.to_ascii_lowercase();
            let stem = lower_exe
                .rsplit_once('.')
                .map_or(lower_exe.as_str(), |(s, _)| s);
            let matched = if has_ext {
                lower_exe == q
            } else {
                stem == q || lower_exe.contains(&q)
            };
            if matched {
                let is_winner = seen_winners.insert(lower_exe);
                let full_path = Path::new(&entry.expanded)
                    .join(exe)
                    .to_string_lossy()
                    .to_string();
                matches.push(WhichMatch {
                    binary: exe.clone(),
                    full_path,
                    entry_index: entry.index,
                    scope: entry.scope,
                    is_winner,
                });
            }
        }
    }
    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_shadowed_binaries_and_resolves_which_priority() {
        let mut entries = vec![
            PathEntry {
                index: 0,
                raw: r"C:\Python39".to_string(),
                expanded: r"C:\Python39".to_string(),
                scope: EnvScope::User,
                exists: true,
                is_duplicate: false,
                executables: vec!["python.exe".to_string(), "pip.exe".to_string()],
                shadows: Vec::new(),
                shadowed_by: Vec::new(),
            },
            PathEntry {
                index: 1,
                raw: r"C:\Python312".to_string(),
                expanded: r"C:\Python312".to_string(),
                scope: EnvScope::System,
                exists: true,
                is_duplicate: false,
                executables: vec!["python.exe".to_string()],
                shadows: Vec::new(),
                shadowed_by: Vec::new(),
            },
        ];
        populate_shadow_graph(&mut entries);
        assert_eq!(entries[0].status(), PathStatus::Conflict);
        assert_eq!(entries[1].status(), PathStatus::Shadowed);
        let summary = summarize_audit(&entries);
        assert_eq!(summary.conflict_entries, 1);
        assert_eq!(summary.shadowed_entries, 1);
        let found = which_all(&entries, "python");
        assert_eq!(found.len(), 2);
        assert!(found[0].is_winner);
        assert_eq!(found[0].entry_index, 0);
        assert!(!found[1].is_winner);
        assert_eq!(found[1].entry_index, 1);
    }
}
