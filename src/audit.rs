//! Filesystem directory scanning, binary shadowing graph construction, and `which` resolution.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use serde::Serialize;

use crate::expand::{expand_env_vars, normalize_path_key};
use crate::model::{AuditSummary, EnvScope, PathEntry, PathStatus, ShadowTarget};

/// Default Windows command processor executable extensions in `PATHEXT` priority order.
const DEFAULT_EXECUTABLE_EXTENSIONS: [&str; 4] = ["com", "exe", "bat", "cmd"];

/// In-memory cache of scanned directories mapping normalized path keys to `(exists, executables)`.
///
/// Prevents repeated `fs::read_dir` syscalls when navigating the TUI sidebar or reordering entries.
#[derive(Debug, Clone, Default)]
pub struct DirScanCache {
    entries: HashMap<String, (bool, Vec<String>)>,
}

impl DirScanCache {
    /// Creates an empty directory scan cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Clears all cached directory scan results, forcing subsequent audits to re-read the disk.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Returns `(exists, executables)` for `expanded_dir`, reading from the filesystem only
    /// if the normalized directory key is not yet cached.
    pub fn get_or_scan(&mut self, expanded_dir: &str, pathext: &[String]) -> (bool, Vec<String>) {
        let key = normalize_path_key(expanded_dir);
        if key.is_empty() {
            return (false, Vec::new());
        }
        if let Some(cached) = self.entries.get(&key) {
            return cached.clone();
        }
        let dir_path = Path::new(expanded_dir);
        let exists = dir_path.is_dir();
        let executables = if exists {
            scan_directory_executables_with_exts(dir_path, pathext)
        } else {
            Vec::new()
        };
        let result = (exists, executables);
        self.entries.insert(key, result.clone());
        result
    }
}

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
    /// `true` if this is the winning executable invoked when running the command in `PATH` order.
    pub is_winner: bool,
}

/// Internal record of a shadowing conflict between an earlier and a later slice position.
struct DiscoveredConflict {
    winner_pos: usize,
    shadowed_pos: usize,
    binary: String,
}

/// Parses a semicolon-delimited `PATHEXT` value (e.g., `".COM;.EXE;.BAT;.CMD"`) into lowercase
/// extension strings without leading dots. Falls back to [`DEFAULT_EXECUTABLE_EXTENSIONS`] if empty.
#[must_use]
pub fn parse_pathext(raw: &str) -> Vec<String> {
    let mut exts = Vec::new();
    for part in raw.split(';') {
        let cleaned = part.trim().trim_start_matches('.').to_ascii_lowercase();
        if !cleaned.is_empty() && !exts.contains(&cleaned) {
            exts.push(cleaned);
        }
    }
    if exts.is_empty() {
        DEFAULT_EXECUTABLE_EXTENSIONS
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    } else {
        exts
    }
}

/// Resolves the active `PATHEXT` extension list from `lookup` or the current process environment.
#[must_use]
pub fn resolve_pathext(lookup: &HashMap<String, String>) -> Vec<String> {
    if let Some(val) = lookup.get("PATHEXT") {
        return parse_pathext(val);
    }
    if let Some(os_val) = std::env::var_os("PATHEXT") {
        return parse_pathext(&os_val.to_string_lossy());
    }
    DEFAULT_EXECUTABLE_EXTENSIONS
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

/// Returns `true` if `name` ends with a standard Windows executable extension
/// (`.com`, `.exe`, `.bat`, `.cmd`), ignoring ASCII case.
#[must_use]
pub fn is_executable_filename(name: &str) -> bool {
    let Some((_, ext)) = name.rsplit_once('.') else {
        return false;
    };
    DEFAULT_EXECUTABLE_EXTENSIONS
        .iter()
        .any(|candidate| ext.eq_ignore_ascii_case(candidate))
}

/// Returns `true` if `name` ends with any extension in `pathext` (case-insensitive).
#[must_use]
pub fn is_executable_with_exts(name: &str, pathext: &[String]) -> bool {
    let Some((_, ext)) = name.rsplit_once('.') else {
        return false;
    };
    pathext
        .iter()
        .any(|candidate| ext.eq_ignore_ascii_case(candidate))
}

/// Scans `dir_path` (non-recursively) using the default Windows executable extensions
/// and returns a sorted, case-insensitively deduplicated list of executable filenames.
#[must_use]
pub fn scan_directory_executables(dir_path: &Path) -> Vec<String> {
    let default_exts: Vec<String> = DEFAULT_EXECUTABLE_EXTENSIONS
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    scan_directory_executables_with_exts(dir_path, &default_exts)
}

/// Scans `dir_path` (non-recursively) for files matching `pathext`, including NTFS App Execution
/// Aliases (`IO_REPARSE_TAG_APPEXECLINK` inside `%LOCALAPPDATA%\Microsoft\WindowsApps`).
#[must_use]
pub fn scan_directory_executables_with_exts(dir_path: &Path, pathext: &[String]) -> Vec<String> {
    let Ok(read_dir) = fs::read_dir(dir_path) else {
        return Vec::new();
    };
    let mut names = Vec::new();
    for entry in read_dir.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        // Skip directories and symlinks/junctions pointing to directories, but allow regular
        // files, file symlinks, and Windows Store App Execution Alias reparse points
        // (`IO_REPARSE_TAG_APPEXECLINK`), for which `file_type.is_file()` is `false` on Windows.
        if file_type.is_dir() || (file_type.is_symlink() && entry.path().is_dir()) {
            continue;
        }
        let file_name = entry.file_name().to_string_lossy().into_owned();
        if is_executable_with_exts(&file_name, pathext) {
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
    let mut cache = DirScanCache::new();
    build_base_entries_cached(raw_items, lookup, &mut cache)
}

/// Cached variant of [`build_base_entries`] that reuses filesystem scans from `cache`.
#[must_use]
pub fn build_base_entries_cached(
    raw_items: &[(String, EnvScope)],
    lookup: &HashMap<String, String>,
    cache: &mut DirScanCache,
) -> Vec<PathEntry> {
    let pathext = resolve_pathext(lookup);
    let mut seen_dirs = HashSet::new();
    let mut entries = Vec::with_capacity(raw_items.len());

    for (index, (raw, scope)) in raw_items.iter().enumerate() {
        let expanded = expand_env_vars(raw, lookup);
        let norm_key = normalize_path_key(&expanded);
        let is_duplicate = !norm_key.is_empty() && !seen_dirs.insert(norm_key);
        let (exists, executables) = cache.get_or_scan(&expanded, &pathext);

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
///
/// Uses slice enumeration rather than assuming `entry.index` equals the slice offset, so it
/// remains safe even on filtered or re-indexed slices.
pub fn populate_shadow_graph(entries: &mut [PathEntry]) {
    for entry in entries.iter_mut() {
        entry.shadows.clear();
        entry.shadowed_by.clear();
    }

    let mut winners: HashMap<String, usize> = HashMap::new();
    let mut discovered_conflicts: Vec<DiscoveredConflict> = Vec::new();

    for (pos, entry) in entries.iter().enumerate() {
        if !entry.exists || entry.is_duplicate {
            continue;
        }
        for exe in &entry.executables {
            let key = exe.to_lowercase();
            if let Some(&winner_pos) = winners.get(&key) {
                if winner_pos != pos {
                    discovered_conflicts.push(DiscoveredConflict {
                        winner_pos,
                        shadowed_pos: pos,
                        binary: exe.clone(),
                    });
                }
            } else {
                winners.insert(key, pos);
            }
        }
    }

    for conflict in discovered_conflicts {
        let winner_index = entries[conflict.winner_pos].index;
        let winner_dir = entries[conflict.winner_pos].expanded.clone();
        let shadowed_index = entries[conflict.shadowed_pos].index;
        let shadowed_dir = entries[conflict.shadowed_pos].expanded.clone();

        entries[conflict.winner_pos].shadows.push(ShadowTarget {
            binary: conflict.binary.clone(),
            other_index: shadowed_index,
            other_dir: shadowed_dir,
        });
        entries[conflict.shadowed_pos]
            .shadowed_by
            .push(ShadowTarget {
                binary: conflict.binary,
                other_index: winner_index,
                other_dir: winner_dir,
            });
    }
}

/// Performs a full audit of `raw_items`, returning [`PathEntry`] records with shadow graphs populated.
#[must_use]
pub fn analyze_path_entries(
    raw_items: &[(String, EnvScope)],
    lookup: &HashMap<String, String>,
) -> Vec<PathEntry> {
    let mut cache = DirScanCache::new();
    analyze_path_entries_cached(raw_items, lookup, &mut cache)
}

/// Performs a full audit of `raw_items` using `cache` to avoid redundant directory scans.
#[must_use]
pub fn analyze_path_entries_cached(
    raw_items: &[(String, EnvScope)],
    lookup: &HashMap<String, String>,
    cache: &mut DirScanCache,
) -> Vec<PathEntry> {
    let mut entries = build_base_entries_cached(raw_items, lookup, cache);
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
        if entry.exists && !entry.is_duplicate {
            summary.total_executables += entry.executables.len();
        }
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
/// * If `query` includes a recognized executable extension (e.g., `python.exe`), matches that
///   exact filename case-insensitively.
/// * If `query` does not include an extension (e.g., `python`), prefers exact stem matches
///   ordered by `PATHEXT` priority within each directory (`com` > `exe` > `bat` > `cmd`),
///   marking only the single highest-priority match for that command stem as `is_winner = true`.
///   Falls back to substring matching only when no exact stem match exists anywhere in `PATH`.
#[must_use]
pub fn which_all(entries: &[PathEntry], query: &str) -> Vec<WhichMatch> {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return Vec::new();
    }

    let pathext: Vec<String> = DEFAULT_EXECUTABLE_EXTENSIONS
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let has_explicit_ext = q.rsplit_once('.').is_some_and(|(stem, ext)| {
        !stem.is_empty() && pathext.iter().any(|cand| cand.eq_ignore_ascii_case(ext))
    });

    if has_explicit_ext {
        return collect_which_matches(entries, &q, &pathext, MatchMode::ExactFilename);
    }

    let exact_stem_matches = collect_which_matches(entries, &q, &pathext, MatchMode::ExactStem);
    if !exact_stem_matches.is_empty() {
        return exact_stem_matches;
    }

    collect_which_matches(entries, &q, &pathext, MatchMode::Substring)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MatchMode {
    ExactFilename,
    ExactStem,
    Substring,
}

fn collect_which_matches(
    entries: &[PathEntry],
    q: &str,
    pathext: &[String],
    mode: MatchMode,
) -> Vec<WhichMatch> {
    let mut matches = Vec::new();
    let mut seen_winner_keys = HashSet::new();

    for entry in entries {
        if !entry.exists || entry.is_duplicate {
            continue;
        }

        // Sort matching executables in this directory by PATHEXT priority so `.exe` beats `.cmd`
        // inside the same directory, matching Windows command processor behavior.
        let mut dir_candidates: Vec<&String> = entry
            .executables
            .iter()
            .filter(|exe| {
                let lower_exe = exe.to_lowercase();
                let stem = lower_exe
                    .rsplit_once('.')
                    .map_or(lower_exe.as_str(), |(s, _)| s);
                match mode {
                    MatchMode::ExactFilename => lower_exe == q,
                    MatchMode::ExactStem => stem == q,
                    MatchMode::Substring => lower_exe.contains(q),
                }
            })
            .collect();

        dir_candidates.sort_by_key(|exe| pathext_rank(exe, pathext));

        for exe in dir_candidates {
            let lower_exe = exe.to_lowercase();
            let stem = lower_exe
                .rsplit_once('.')
                .map_or(lower_exe.as_str(), |(s, _)| s)
                .to_string();

            let winner_key = match mode {
                MatchMode::ExactFilename => lower_exe,
                MatchMode::ExactStem | MatchMode::Substring => stem,
            };
            let is_winner = seen_winner_keys.insert(winner_key);
            let full_path = Path::new(&entry.expanded)
                .join(exe)
                .to_string_lossy()
                .into_owned();

            matches.push(WhichMatch {
                binary: exe.clone(),
                full_path,
                entry_index: entry.index,
                scope: entry.scope,
                is_winner,
            });
        }
    }

    matches
}

fn pathext_rank(filename: &str, pathext: &[String]) -> usize {
    let Some((_, ext)) = filename.rsplit_once('.') else {
        return pathext.len();
    };
    pathext
        .iter()
        .position(|cand| cand.eq_ignore_ascii_case(ext))
        .unwrap_or(pathext.len())
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

    #[test]
    fn which_all_marks_single_winner_across_extensions_and_avoids_substring_noise() {
        let entries = vec![
            PathEntry {
                index: 0,
                raw: r"C:\Dir1".to_string(),
                expanded: r"C:\Dir1".to_string(),
                scope: EnvScope::System,
                exists: true,
                is_duplicate: false,
                executables: vec![
                    "py.cmd".to_string(),
                    "py.exe".to_string(),
                    "copy.exe".to_string(),
                ],
                shadows: Vec::new(),
                shadowed_by: Vec::new(),
            },
            PathEntry {
                index: 1,
                raw: r"C:\Dir2".to_string(),
                expanded: r"C:\Dir2".to_string(),
                scope: EnvScope::User,
                exists: true,
                is_duplicate: false,
                executables: vec!["py.exe".to_string()],
                shadows: Vec::new(),
                shadowed_by: Vec::new(),
            },
        ];

        // Searching "py" should match exact stem `py` (.exe and .cmd), excluding `copy.exe`,
        // and within Dir1 `py.exe` beats `py.cmd` per PATHEXT priority.
        let found = which_all(&entries, "py");
        assert_eq!(found.len(), 3);
        assert_eq!(found[0].binary, "py.exe");
        assert!(found[0].is_winner);
        assert_eq!(found[1].binary, "py.cmd");
        assert!(!found[1].is_winner);
        assert_eq!(found[2].binary, "py.exe");
        assert!(!found[2].is_winner);
    }

    #[test]
    fn populate_shadow_graph_handles_non_contiguous_entry_indices() {
        let mut entries = vec![
            PathEntry {
                index: 5,
                raw: r"C:\First".to_string(),
                expanded: r"C:\First".to_string(),
                scope: EnvScope::System,
                exists: true,
                is_duplicate: false,
                executables: vec!["git.exe".to_string()],
                shadows: Vec::new(),
                shadowed_by: Vec::new(),
            },
            PathEntry {
                index: 12,
                raw: r"C:\Second".to_string(),
                expanded: r"C:\Second".to_string(),
                scope: EnvScope::User,
                exists: true,
                is_duplicate: false,
                executables: vec!["git.exe".to_string()],
                shadows: Vec::new(),
                shadowed_by: Vec::new(),
            },
        ];

        populate_shadow_graph(&mut entries);
        assert_eq!(entries[0].shadows[0].other_index, 12);
        assert_eq!(entries[1].shadowed_by[0].other_index, 5);
    }

    #[test]
    fn parses_custom_pathext_and_falls_back_on_empty() {
        let exts = parse_pathext(".COM;.EXE;.BAT;.CMD;.PY");
        assert_eq!(exts, vec!["com", "exe", "bat", "cmd", "py"]);
        assert!(is_executable_with_exts("script.py", &exts));
        assert!(!is_executable_with_exts("readme.txt", &exts));

        let fallback = parse_pathext("  ;  ");
        assert_eq!(fallback, vec!["com", "exe", "bat", "cmd"]);
    }
}
