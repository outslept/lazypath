use serde::{Deserialize, Serialize};

/// Target registry hive scope for an environment variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnvScope {
    /// Per-user environment stored in `HKCU\Environment`.
    User,
    /// Machine-wide environment stored in `HKLM\...\Environment`.
    System,
}

impl EnvScope {
    /// Returns the human-readable scope name for UI and CLI output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::User => "User",
            Self::System => "System",
        }
    }

    /// Returns the Windows Registry key path for this scope.
    #[must_use]
    pub const fn registry_key(self) -> &'static str {
        match self {
            Self::User => r"HKCU\Environment",
            Self::System => r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        }
    }
}

/// A single Windows environment variable loaded from or destined for the registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvVariable {
    /// Variable identifier (e.g., `Path`, `JAVA_HOME`).
    pub name: String,
    /// Unexpanded raw value stored in the registry.
    pub value: String,
    /// Owning registry scope ([`EnvScope::User`] or [`EnvScope::System`]).
    pub scope: EnvScope,
    /// Whether the variable has unsaved in-memory modifications.
    pub modified: bool,
}

impl EnvVariable {
    /// Returns `true` if this variable represents `PATH` (case-insensitive on Windows).
    #[must_use]
    pub fn is_path_var(&self) -> bool {
        self.name.eq_ignore_ascii_case("PATH")
    }
}

/// Health classification for an individual directory entry in `PATH`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathStatus {
    /// Directory exists, is unique, and has no binary shadowing conflicts.
    Ok,
    /// Directory contains executables that shadow identically named binaries later in `PATH`.
    Conflict,
    /// Directory contains executables shadowed by an earlier `PATH` entry.
    Shadowed,
    /// Directory appears more than once in `PATH`.
    Duplicate,
    /// Directory does not exist on disk.
    Missing,
}

impl PathStatus {
    /// Formats a short status badge for CLI tables and TUI rows.
    #[must_use]
    pub fn badge(self, exe_count: usize) -> String {
        match self {
            Self::Ok => format!("OK, {exe_count} exe"),
            Self::Conflict => "CONFLICT".to_string(),
            Self::Shadowed => "SHADOWED".to_string(),
            Self::Duplicate => "DUP".to_string(),
            Self::Missing => "MISSING".to_string(),
        }
    }
}

/// Describes a binary shadowing relationship between two `PATH` directories.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowTarget {
    /// Executable file name (e.g., `python.exe`).
    pub binary: String,
    /// Zero-based index of the other `PATH` entry involved in the conflict.
    pub other_index: usize,
    /// Expanded directory path of the other `PATH` entry.
    pub other_dir: String,
}

/// An audited directory entry within `PATH`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathEntry {
    /// Zero-based position in the audited `PATH` list.
    pub index: usize,
    /// Unexpanded directory string as stored in the registry.
    pub raw: String,
    /// Directory string with `%VAR%` placeholders expanded.
    pub expanded: String,
    /// Originating registry scope.
    pub scope: EnvScope,
    /// Whether the expanded directory currently exists on disk.
    pub exists: bool,
    /// Whether an equivalent normalized path appeared earlier in the list.
    pub is_duplicate: bool,
    /// Sorted list of executable filenames discovered inside this directory.
    pub executables: Vec<String>,
    /// Binaries in later `PATH` entries shadowed by this directory.
    pub shadows: Vec<ShadowTarget>,
    /// Binaries in this directory shadowed by earlier `PATH` entries.
    pub shadowed_by: Vec<ShadowTarget>,
}

impl PathEntry {
    /// Computes the highest-priority [`PathStatus`] for this entry.
    #[must_use]
    pub fn status(&self) -> PathStatus {
        if !self.exists {
            PathStatus::Missing
        } else if self.is_duplicate {
            PathStatus::Duplicate
        } else if !self.shadows.is_empty() {
            PathStatus::Conflict
        } else if !self.shadowed_by.is_empty() {
            PathStatus::Shadowed
        } else {
            PathStatus::Ok
        }
    }

    /// Returns `true` if this entry is safe to prune automatically (missing or duplicate).
    #[must_use]
    pub const fn is_removable_junk(&self) -> bool {
        !self.exists || self.is_duplicate
    }

    /// Returns a human-readable diagnostic explaining the primary issue with this entry, if any.
    #[must_use]
    pub fn headline_warning(&self) -> Option<String> {
        if !self.exists {
            return Some(format!(
                "Directory '{}' does not exist on disk",
                self.expanded
            ));
        }
        if self.is_duplicate {
            return Some(format!(
                "Duplicate of an earlier PATH entry ('{}')",
                self.expanded
            ));
        }
        if let Some(first) = self.shadows.first() {
            let extra = self.shadows.len().saturating_sub(1);
            let suffix = if extra > 0 {
                format!(" (+{extra} more)")
            } else {
                String::new()
            };
            return Some(format!(
                "{} in #{} shadows #{} ({}){suffix}",
                first.binary,
                self.index + 1,
                first.other_index + 1,
                first.other_dir
            ));
        }
        if let Some(first) = self.shadowed_by.first() {
            let extra = self.shadowed_by.len().saturating_sub(1);
            let suffix = if extra > 0 {
                format!(" (+{extra} more)")
            } else {
                String::new()
            };
            return Some(format!(
                "{} in #{} is shadowed by #{} ({}){suffix}",
                first.binary,
                self.index + 1,
                first.other_index + 1,
                first.other_dir
            ));
        }
        None
    }
}

/// Aggregate statistics across all audited `PATH` entries.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AuditSummary {
    /// Total number of directory entries inspected.
    pub total_entries: usize,
    /// Number of entries whose directories do not exist on disk.
    pub missing_count: usize,
    /// Number of duplicate directory entries.
    pub duplicate_count: usize,
    /// Number of entries that shadow at least one later binary.
    pub conflict_entries: usize,
    /// Number of entries whose binaries are shadowed by earlier entries.
    pub shadowed_entries: usize,
    /// Total number of executables discovered across all existing, non-duplicate entries.
    pub total_executables: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_path_variable_case_insensitively() {
        let v = EnvVariable {
            name: "Path".to_string(),
            value: r"C:\Windows\System32".to_string(),
            scope: EnvScope::System,
            modified: false,
        };
        assert!(v.is_path_var());
        assert_eq!(v.scope.label(), "System");
    }

    #[test]
    fn resolves_entry_status_and_warning_priority() {
        let mut entry = PathEntry {
            index: 1,
            raw: r"C:\Python39".to_string(),
            expanded: r"C:\Python39".to_string(),
            scope: EnvScope::User,
            exists: true,
            is_duplicate: false,
            executables: vec!["python.exe".to_string()],
            shadows: vec![ShadowTarget {
                binary: "python.exe".to_string(),
                other_index: 3,
                other_dir: r"C:\Python312".to_string(),
            }],
            shadowed_by: Vec::new(),
        };
        assert_eq!(entry.status(), PathStatus::Conflict);
        assert!(entry
            .headline_warning()
            .unwrap()
            .contains("python.exe in #2 shadows #4"));
        entry.exists = false;
        assert_eq!(entry.status(), PathStatus::Missing);
        assert!(entry.is_removable_junk());
    }
}
