use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnvScope {
    User,
    System,
}

impl EnvScope {
    pub fn label(self) -> &'static str {
        match self {
            Self::User => "User",
            Self::System => "System",
        }
    }

    pub fn registry_key(self) -> &'static str {
        match self {
            Self::User => r"HKCU\Environment",
            Self::System => r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvVariable {
    pub name: String,
    pub value: String,
    pub scope: EnvScope,
    pub modified: bool,
}

impl EnvVariable {
    pub fn is_path_var(&self) -> bool {
        self.name.eq_ignore_ascii_case("PATH")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathStatus {
    Ok,
    Conflict,
    Shadowed,
    Duplicate,
    Missing,
}

impl PathStatus {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowTarget {
    pub binary: String,
    pub other_index: usize,
    pub other_dir: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathEntry {
    pub index: usize,
    pub raw: String,
    pub expanded: String,
    pub scope: EnvScope,
    pub exists: bool,
    pub is_duplicate: bool,
    pub executables: Vec<String>,
    pub shadows: Vec<ShadowTarget>,
    pub shadowed_by: Vec<ShadowTarget>,
}

impl PathEntry {
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

    pub fn is_removable_junk(&self) -> bool {
        !self.exists || self.is_duplicate
    }

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

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AuditSummary {
    pub total_entries: usize,
    pub missing_count: usize,
    pub duplicate_count: usize,
    pub conflict_entries: usize,
    pub shadowed_entries: usize,
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
