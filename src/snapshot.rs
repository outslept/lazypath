use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::model::{EnvScope, EnvVariable};
use crate::registry::write_scope_variable;

/// Point-in-time backup of User and System environment variables.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvSnapshot {
    /// UNIX timestamp (in seconds) when the snapshot was created.
    pub created_unix_secs: u64,
    /// Captured `HKCU\Environment` variables.
    pub user: Vec<EnvVariable>,
    /// Captured `HKLM\...\Environment` variables.
    pub system: Vec<EnvVariable>,
}

/// Creates an in-memory [`EnvSnapshot`] stamped with the current UNIX time.
#[must_use]
pub fn create_snapshot(user: &[EnvVariable], system: &[EnvVariable]) -> EnvSnapshot {
    let created_unix_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    EnvSnapshot {
        created_unix_secs,
        user: user.to_vec(),
        system: system.to_vec(),
    }
}

/// Serializes `user` and `system` environment variables to a pretty-printed JSON file at `path`.
///
/// # Errors
///
/// Returns an error if serialization fails or the file cannot be written to disk.
pub fn save_snapshot_file(path: &Path, user: &[EnvVariable], system: &[EnvVariable]) -> Result<()> {
    let snapshot = create_snapshot(user, system);
    let json =
        serde_json::to_string_pretty(&snapshot).context("failed to serialize snapshot to JSON")?;
    fs::write(path, json)
        .with_context(|| format!("failed to write snapshot file '{}'", path.display()))?;
    Ok(())
}

/// Reads and deserializes an [`EnvSnapshot`] from a JSON file at `path`.
///
/// # Errors
///
/// Returns an error if the file cannot be read or contains invalid snapshot JSON.
pub fn load_snapshot_file(path: &Path) -> Result<EnvSnapshot> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read snapshot file '{}'", path.display()))?;
    let snapshot: EnvSnapshot =
        serde_json::from_str(&raw).context("failed to parse snapshot JSON")?;
    Ok(snapshot)
}

/// Writes all [`EnvScope::User`] variables from `snapshot` back to the Windows Registry.
///
/// Returns the number of restored variables.
///
/// # Errors
///
/// Returns an error if any registry write fails.
pub fn restore_user_snapshot(snapshot: &EnvSnapshot) -> Result<usize> {
    let mut restored = 0;
    for var in &snapshot.user {
        if var.scope == EnvScope::User {
            write_scope_variable(EnvScope::User, &var.name, &var.value)?;
            restored += 1;
        }
    }
    Ok(restored)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_environment_snapshot_json() {
        let user = vec![EnvVariable {
            name: "Path".to_string(),
            value: r"C:\Users\Me\.cargo\bin".to_string(),
            scope: EnvScope::User,
            modified: false,
        }];
        let sys = vec![EnvVariable {
            name: "JAVA_HOME".to_string(),
            value: r"C:\Java\jdk-21".to_string(),
            scope: EnvScope::System,
            modified: false,
        }];
        let temp_file = std::env::temp_dir().join("lazypath_test_snapshot.json");
        save_snapshot_file(&temp_file, &user, &sys).expect("save snapshot");
        let loaded = load_snapshot_file(&temp_file).expect("load snapshot");
        let _ = fs::remove_file(&temp_file);
        assert_eq!(loaded.user, user);
        assert_eq!(loaded.system, sys);
    }
}
