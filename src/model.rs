//! Core domain types for Windows environment variables, registry scopes, and `PATH` auditing.

use serde::{Deserialize, Serialize};

/// Current JSON schema version for exported snapshots and structured CLI reports.
pub const SCHEMA_VERSION: u32 = 1;

/// Maximum length (in UTF-16 code units) permitted for a Windows Registry value name.
const MAX_VALUE_NAME_UTF16_LEN: usize = 16_383;

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

    /// Returns the full Windows Registry key path for this scope (used in CLI diagnostics and `reg.exe`).
    #[must_use]
    pub const fn registry_key(self) -> &'static str {
        match self {
            Self::User => r"HKCU\Environment",
            Self::System => r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        }
    }

    /// Returns the registry subkey path relative to its root hive (`HKEY_CURRENT_USER` or `HKEY_LOCAL_MACHINE`).
    #[must_use]
    pub const fn registry_subkey(self) -> &'static str {
        match self {
            Self::User => "Environment",
            Self::System => r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        }
    }
}

/// Windows Registry string value type for an environment variable.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum RegValueKind {
    /// Fixed literal string (`REG_SZ`). Does not expand `%VAR%` placeholders.
    #[default]
    Sz,
    /// Expandable string (`REG_EXPAND_SZ`) whose `%VAR%` placeholders are expanded by Windows.
    ExpandSz,
}

impl RegValueKind {
    /// Returns the canonical `reg.exe` / Win32 type identifier (`REG_SZ` or `REG_EXPAND_SZ`).
    #[must_use]
    pub const fn reg_type_name(self) -> &'static str {
        match self {
            Self::Sz => "REG_SZ",
            Self::ExpandSz => "REG_EXPAND_SZ",
        }
    }

    /// Infers an appropriate default registry value type when creating a new variable
    /// or loading legacy data without an explicit type tag.
    #[must_use]
    pub fn infer(name: &str, value: &str) -> Self {
        if name.eq_ignore_ascii_case("PATH") || value.contains('%') {
            Self::ExpandSz
        } else {
            Self::Sz
        }
    }
}

/// Validates a Windows environment variable name before writing or importing into the registry.
///
/// # Errors
///
/// Returns a descriptive error string if `name` is empty, contains NUL (`\0`) or `=`,
/// or exceeds the Windows Registry value name limit (16,383 UTF-16 code units).
pub fn validate_variable_name(name: &str) -> Result<(), String> {
    if name.trim().is_empty() {
        return Err("environment variable name cannot be empty".to_string());
    }
    if name.contains('\0') {
        return Err(format!(
            "environment variable name '{name}' contains an invalid NUL character"
        ));
    }
    if name.contains('=') {
        return Err(format!(
            "environment variable name '{name}' cannot contain '='"
        ));
    }
    let utf16_len = name.encode_utf16().count();
    if utf16_len > MAX_VALUE_NAME_UTF16_LEN {
        return Err(format!(
            "environment variable name exceeds maximum length ({utf16_len} > {MAX_VALUE_NAME_UTF16_LEN})"
        ));
    }
    Ok(())
}

/// A single Windows environment variable loaded from or destined for the registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvVariable {
    /// Variable identifier (e.g., `Path`, `JAVA_HOME`).
    pub name: String,
    /// Unexpanded raw value stored in the registry.
    pub value: String,
    /// Owning registry scope ([`EnvScope::User`] or [`EnvScope::System`]).
    pub scope: EnvScope,
    /// Underlying Windows Registry string type (`REG_SZ` vs `REG_EXPAND_SZ`).
    #[serde(default)]
    pub kind: RegValueKind,
    /// Whether the variable has unsaved in-memory modifications.
    #[serde(default)]
    pub modified: bool,
}

impl EnvVariable {
    /// Constructs a new [`EnvVariable`] and automatically infers its [`RegValueKind`].
    #[must_use]
    pub fn new(name: impl Into<String>, value: impl Into<String>, scope: EnvScope) -> Self {
        let name = name.into();
        let value = value.into();
        let kind = RegValueKind::infer(&name, &value);
        Self {
            name,
            value,
            scope,
            kind,
            modified: false,
        }
    }

    /// Constructs a new [`EnvVariable`] with an explicit [`RegValueKind`].
    #[must_use]
    pub fn with_kind(
        name: impl Into<String>,
        value: impl Into<String>,
        scope: EnvScope,
        kind: RegValueKind,
    ) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            scope,
            kind,
            modified: false,
        }
    }

    /// Returns `true` if this variable represents `PATH` (case-insensitive on Windows).
    #[must_use]
    pub fn is_path_var(&self) -> bool {
        self.name.eq_ignore_ascii_case("PATH")
    }

    /// Returns the registry value type that should be used when persisting this variable.
    ///
    /// `PATH` is always stored as `REG_EXPAND_SZ` so `%VAR%` directory entries are expanded by
    /// Windows; all other variables preserve their recorded [`RegValueKind`].
    #[must_use]
    pub fn effective_kind(&self) -> RegValueKind {
        if self.is_path_var() {
            RegValueKind::ExpandSz
        } else {
            self.kind
        }
    }
}

/// Health classification for an individual directory entry in `PATH`.
///
/// When an entry exhibits multiple conditions simultaneously, [`PathEntry::status`]
/// resolves them in strict severity order:
/// `Missing` > `Duplicate` > `Conflict` > `Shadowed` > `Ok`.
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
    ///
    /// Precedence order:
    /// 1. [`PathStatus::Missing`] (`!self.exists`)
    /// 2. [`PathStatus::Duplicate`] (`self.is_duplicate`)
    /// 3. [`PathStatus::Conflict`] (`!self.shadows.is_empty()`)
    /// 4. [`PathStatus::Shadowed`] (`!self.shadowed_by.is_empty()`)
    /// 5. [`PathStatus::Ok`]
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
    ///
    /// If an entry both shadows later entries and has binaries shadowed by earlier entries,
    /// both facts are surfaced in the message.
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
            let extra_suffix = if extra > 0 {
                format!(" (+{extra} more)")
            } else {
                String::new()
            };
            let shadowed_suffix = if self.shadowed_by.is_empty() {
                String::new()
            } else {
                format!("; also {} shadowed by earlier", self.shadowed_by.len())
            };
            return Some(format!(
                "{} in #{} shadows #{} ({}){extra_suffix}{shadowed_suffix}",
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

impl AuditSummary {
    /// Returns `true` if the audit detected any missing directories, duplicates, or binary shadowing conflicts.
    #[must_use]
    pub const fn has_issues(&self) -> bool {
        self.missing_count > 0
            || self.duplicate_count > 0
            || self.conflict_entries > 0
            || self.shadowed_entries > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_path_variable_case_insensitively_and_preserves_kind() {
        let v = EnvVariable::new("Path", r"C:\Windows\System32", EnvScope::System);
        assert!(v.is_path_var());
        assert_eq!(v.kind, RegValueKind::ExpandSz);
        assert_eq!(v.effective_kind(), RegValueKind::ExpandSz);
        assert_eq!(v.scope.label(), "System");
        assert_eq!(
            v.scope.registry_subkey(),
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
        );

        let literal_percent =
            EnvVariable::with_kind("LITERAL_PCT", "100%", EnvScope::User, RegValueKind::Sz);
        assert_eq!(literal_percent.effective_kind(), RegValueKind::Sz);
        assert_eq!(literal_percent.kind.reg_type_name(), "REG_SZ");
    }

    #[test]
    fn validates_environment_variable_names() {
        assert!(validate_variable_name("JAVA_HOME").is_ok());
        assert!(validate_variable_name("Path").is_ok());
        assert!(validate_variable_name("").is_err());
        assert!(validate_variable_name("   ").is_err());
        assert!(validate_variable_name("BAD=NAME").is_err());
        assert!(validate_variable_name("BAD\0NAME").is_err());
        let too_long = "A".repeat(MAX_VALUE_NAME_UTF16_LEN + 1);
        assert!(validate_variable_name(&too_long).is_err());
    }

    #[test]
    fn deserializes_legacy_and_strict_env_variable_json() {
        let legacy_json = r#"{
            "name": "JAVA_HOME",
            "value": "C:\\jdk",
            "scope": "user"
        }"#;
        let parsed: EnvVariable = serde_json::from_str(legacy_json).unwrap();
        assert_eq!(parsed.kind, RegValueKind::Sz);
        assert!(!parsed.modified);

        let unknown_field_json = r#"{
            "name": "JAVA_HOME",
            "value": "C:\\jdk",
            "scope": "user",
            "bogus": 123
        }"#;
        assert!(serde_json::from_str::<EnvVariable>(unknown_field_json).is_err());
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
            shadowed_by: vec![ShadowTarget {
                binary: "pip.exe".to_string(),
                other_index: 0,
                other_dir: r"C:\Scripts".to_string(),
            }],
        };
        assert_eq!(entry.status(), PathStatus::Conflict);
        let warning = entry.headline_warning().unwrap();
        assert!(warning.contains("python.exe in #2 shadows #4"));
        assert!(warning.contains("also 1 shadowed by earlier"));

        entry.exists = false;
        assert_eq!(entry.status(), PathStatus::Missing);
        assert!(entry.is_removable_junk());
    }

    #[test]
    fn reports_audit_summary_issue_detection() {
        let mut summary = AuditSummary {
            total_entries: 5,
            total_executables: 42,
            ..AuditSummary::default()
        };
        assert!(!summary.has_issues());
        summary.missing_count = 1;
        assert!(summary.has_issues());
    }
}
