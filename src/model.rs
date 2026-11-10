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
    fn formats_status_badges() {
        assert_eq!(PathStatus::Ok.badge(14), "OK, 14 exe");
        assert_eq!(PathStatus::Conflict.badge(3), "CONFLICT");
        assert_eq!(PathStatus::Missing.badge(0), "MISSING");
    }
}
