use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use serde::Serialize;

use crate::expand::{expand_env_vars, normalize_path_key};
use crate::model::{AuditSummary, EnvScope, PathEntry, PathStatus, ShadowTarget};

const EXECUTABLE_EXTENSIONS: [&str; 4] = ["exe", "cmd", "bat", "com"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WhichMatch {
    pub binary: String,
    pub full_path: String,
    pub entry_index: usize,
    pub scope: EnvScope,
    pub is_winner: bool,
}

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

pub fn populate_shadow_graph(entries: &mut [PathEntry]) {
    for entry in entries.iter_mut() {
        entry.shadows.clear();
        entry.shadowed_by.clear();
    }

    let mut winners: HashMap<String, (usize, String)> = HashMap::new();
    let mut discovered_conflicts: Vec<(usize, usize, String, String, String)> = Vec::new();

    for entry in entries.iter() {
        if !entry.exists || entry.is_duplicate {
            continue;
        }
        for exe in &entry.executables {
            let key = exe.to_ascii_lowercase();
            if let Some((winner_idx, winner_dir)) = winners.get(&key) {
                discovered_conflicts.push((
                    *winner_idx,
                    entry.index,
                    exe.clone(),
                    winner_dir.clone(),
                    entry.expanded.clone(),
                ));
            } else {
                winners.insert(key, (entry.index, entry.expanded.clone()));
            }
        }
    }

    for (winner_idx, shadowed_idx, binary, winner_dir, shadowed_dir) in discovered_conflicts {
        if let Some(winner_entry) = entries.get_mut(winner_idx) {
            winner_entry.shadows.push(ShadowTarget {
                binary: binary.clone(),
                other_index: shadowed_idx,
                other_dir: shadowed_dir,
            });
        }
        if let Some(shadowed_entry) = entries.get_mut(shadowed_idx) {
            shadowed_entry.shadowed_by.push(ShadowTarget {
                binary,
                other_index: winner_idx,
                other_dir: winner_dir,
            });
        }
    }
}

pub fn analyze_path_entries(
    raw_items: &[(String, EnvScope)],
    lookup: &HashMap<String, String>,
) -> Vec<PathEntry> {
    let mut entries = build_base_entries(raw_items, lookup);
    populate_shadow_graph(&mut entries);
    entries
}

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
                .map(|(s, _)| s)
                .unwrap_or(&lower_exe);

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
