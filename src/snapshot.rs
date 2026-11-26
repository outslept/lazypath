//! Environment variable JSON snapshots, atomic disk persistence, import diff/rollback,
//! and pending state handoff across UAC elevation.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::model::{validate_variable_name, EnvScope, EnvVariable, SCHEMA_VERSION};
use crate::registry::{
    delete_scope_variable, read_scope_variables, write_scope_variable_with_kind,
};

/// Monotonic counter used to guarantee unique temporary filenames during atomic writes and tests.
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

/// Application subdirectory name inside `%LOCALAPPDATA%`.
const APP_DATA_DIR_NAME: &str = "lazypath";
/// Default filename used when the user triggers a manual backup (`b`).
pub const MANUAL_BACKUP_FILENAME: &str = "lazypath-backup.json";
/// Filename written automatically before applying registry modifications (`s` or `--import`).
pub const AUTO_BACKUP_FILENAME: &str = "lazypath-auto-backup.json";
/// Filename used to transfer unsaved TUI edits into an elevated Administrator instance (`E`).
pub const PENDING_ELEVATION_FILENAME: &str = "lazypath-pending-elevation.json";

const fn default_schema_version() -> u32 {
    SCHEMA_VERSION
}

/// Point-in-time backup of User and System environment variables.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvSnapshot {
    /// Schema version of the snapshot format.
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    /// UNIX timestamp (in seconds) when the snapshot was created.
    pub created_unix_secs: u64,
    /// Captured `HKCU\Environment` variables.
    pub user: Vec<EnvVariable>,
    /// Captured `HKLM\...\Environment` variables.
    pub system: Vec<EnvVariable>,
}

/// Summary of changes that will be (or were) applied when importing User variables from a snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct SnapshotImportSummary {
    /// Number of new User variables not currently present in `HKCU\Environment`.
    pub added: usize,
    /// Number of existing User variables whose value or registry type will change.
    pub updated: usize,
    /// Number of User variables in the snapshot that already match the registry identically.
    pub unchanged: usize,
}

impl SnapshotImportSummary {
    /// Total number of User variables evaluated in the snapshot.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.added + self.updated + self.unchanged
    }

    /// Number of variables requiring an actual registry write (`added + updated`).
    #[must_use]
    pub const fn changed(&self) -> usize {
        self.added + self.updated
    }
}

/// Unsaved TUI state serialized before relaunching with UAC Administrator elevation (`E`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingElevationState {
    /// Schema version of the pending state payload.
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    /// UNIX timestamp (in seconds) when the pending state was saved.
    pub created_unix_secs: u64,
    /// Pending User `PATH` entries.
    pub user_path_raw: Vec<String>,
    /// Pending System `PATH` entries.
    pub system_path_raw: Vec<String>,
    /// Whether `user_path_raw` had unsaved modifications.
    pub user_path_dirty: bool,
    /// Whether `system_path_raw` had unsaved modifications.
    pub system_path_dirty: bool,
    /// Selected sidebar index at the time of elevation.
    pub selected_sidebar: usize,
    /// Selected entry index at the time of elevation.
    pub selected_entry: usize,
}

/// Returns the per-user application data directory (`%LOCALAPPDATA%\lazypath`),
/// falling back to the system temporary directory if `LOCALAPPDATA` is unset.
#[must_use]
pub fn default_backup_dir() -> PathBuf {
    if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
        let base = PathBuf::from(local_app_data);
        if !base.as_os_str().is_empty() {
            return base.join(APP_DATA_DIR_NAME);
        }
    }
    std::env::temp_dir().join(APP_DATA_DIR_NAME)
}

/// Returns the default path for manual backups (`%LOCALAPPDATA%\lazypath\lazypath-backup.json`).
#[must_use]
pub fn default_manual_backup_path() -> PathBuf {
    default_backup_dir().join(MANUAL_BACKUP_FILENAME)
}

/// Returns the default path for automatic pre-save backups (`%LOCALAPPDATA%\lazypath\lazypath-auto-backup.json`).
#[must_use]
pub fn default_auto_backup_path() -> PathBuf {
    default_backup_dir().join(AUTO_BACKUP_FILENAME)
}

/// Returns the default path for UAC elevation state handoff (`%LOCALAPPDATA%\lazypath\lazypath-pending-elevation.json`).
#[must_use]
pub fn default_pending_elevation_path() -> PathBuf {
    default_backup_dir().join(PENDING_ELEVATION_FILENAME)
}

/// Creates an in-memory [`EnvSnapshot`] stamped with the current UNIX time and [`SCHEMA_VERSION`].
#[must_use]
pub fn create_snapshot(user: &[EnvVariable], system: &[EnvVariable]) -> EnvSnapshot {
    EnvSnapshot {
        schema_version: SCHEMA_VERSION,
        created_unix_secs: current_unix_secs(),
        user: user.to_vec(),
        system: system.to_vec(),
    }
}

/// Serializes `user` and `system` environment variables to a pretty-printed JSON file at `path`
/// using an atomic write-and-rename strategy.
///
/// # Errors
///
/// Returns an error if serialization fails, the parent directory cannot be created, or the
/// atomic file write/rename fails.
pub fn save_snapshot_file(path: &Path, user: &[EnvVariable], system: &[EnvVariable]) -> Result<()> {
    let snapshot = create_snapshot(user, system);
    let json =
        serde_json::to_string_pretty(&snapshot).context("failed to serialize snapshot to JSON")?;
    write_atomic_bytes(path, json.as_bytes())
        .with_context(|| format!("failed to write snapshot file '{}'", path.display()))
}

/// Reads, deserializes, and validates an [`EnvSnapshot`] from a JSON file at `path`.
///
/// # Errors
///
/// Returns an error if the file cannot be read, contains invalid JSON or unknown fields,
/// carries an unsupported `schema_version`, or contains invalid variable names or mismatched scopes.
pub fn load_snapshot_file(path: &Path) -> Result<EnvSnapshot> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read snapshot file '{}'", path.display()))?;
    let snapshot: EnvSnapshot =
        serde_json::from_str(&raw).context("failed to parse snapshot JSON")?;
    validate_snapshot(&snapshot)?;
    Ok(snapshot)
}

/// Validates schema version, variable names, and scope invariants on a loaded [`EnvSnapshot`].
///
/// # Errors
///
/// Returns an error if the schema version is unsupported or any variable entry is malformed.
pub fn validate_snapshot(snapshot: &EnvSnapshot) -> Result<()> {
    if snapshot.schema_version == 0 || snapshot.schema_version > SCHEMA_VERSION {
        bail!(
            "unsupported snapshot schema_version {} (expected 1..={SCHEMA_VERSION})",
            snapshot.schema_version
        );
    }
    for var in &snapshot.user {
        if let Err(msg) = validate_variable_name(&var.name) {
            bail!("invalid User variable in snapshot: {msg}");
        }
        if var.scope != EnvScope::User {
            bail!(
                "variable '{}' in snapshot 'user' list has mismatched scope '{}'",
                var.name,
                var.scope.label()
            );
        }
    }
    for var in &snapshot.system {
        if let Err(msg) = validate_variable_name(&var.name) {
            bail!("invalid System variable in snapshot: {msg}");
        }
        if var.scope != EnvScope::System {
            bail!(
                "variable '{}' in snapshot 'system' list has mismatched scope '{}'",
                var.name,
                var.scope.label()
            );
        }
    }
    Ok(())
}

/// Computes a dry-run diff summary comparing `snapshot.user` against `current_user`.
#[must_use]
pub fn plan_user_snapshot_import(
    snapshot: &EnvSnapshot,
    current_user: &[EnvVariable],
) -> SnapshotImportSummary {
    let existing: HashMap<String, &EnvVariable> = current_user
        .iter()
        .map(|v| (v.name.to_uppercase(), v))
        .collect();

    let mut summary = SnapshotImportSummary::default();
    for var in &snapshot.user {
        if var.scope != EnvScope::User {
            continue;
        }
        let key = var.name.to_uppercase();
        match existing.get(&key) {
            None => summary.added += 1,
            Some(curr) => {
                if curr.value == var.value && curr.effective_kind() == var.effective_kind() {
                    summary.unchanged += 1;
                } else {
                    summary.updated += 1;
                }
            }
        }
    }
    summary
}

/// Writes all [`EnvScope::User`] variables from `snapshot` back to the Windows Registry,
/// preserving each variable's [`RegValueKind`](crate::model::RegValueKind) and rolling back
/// partial writes if an error occurs mid-import.
///
/// Returns the number of variables processed from `snapshot.user`.
///
/// # Errors
///
/// Returns an error if validation fails or any registry write fails.
pub fn restore_user_snapshot(snapshot: &EnvSnapshot) -> Result<usize> {
    validate_snapshot(snapshot)?;
    let current_user = read_scope_variables(EnvScope::User).unwrap_or_default();
    let summary = restore_user_snapshot_with_baseline(snapshot, &current_user)?;
    Ok(summary.total())
}

/// Restores [`EnvScope::User`] variables from `snapshot` using `current_user` as a rollback
/// baseline. If any registry write fails, previously modified or added variables are reverted.
///
/// # Errors
///
/// Returns an error if snapshot validation fails or a registry write fails (including rollback status).
pub fn restore_user_snapshot_with_baseline(
    snapshot: &EnvSnapshot,
    current_user: &[EnvVariable],
) -> Result<SnapshotImportSummary> {
    validate_snapshot(snapshot)?;
    let summary = plan_user_snapshot_import(snapshot, current_user);

    let baseline_map: HashMap<String, &EnvVariable> = current_user
        .iter()
        .map(|v| (v.name.to_uppercase(), v))
        .collect();

    let mut applied_names: Vec<String> = Vec::with_capacity(snapshot.user.len());

    for var in &snapshot.user {
        if var.scope != EnvScope::User {
            continue;
        }
        if let Err(write_err) = write_scope_variable_with_kind(
            EnvScope::User,
            &var.name,
            &var.value,
            var.effective_kind(),
        ) {
            let rollback_err = rollback_user_writes(&applied_names, &baseline_map);
            if let Some(rb_msg) = rollback_err {
                bail!(
                    "failed to restore User variable '{}': {write_err} (rollback also encountered errors: {rb_msg})",
                    var.name
                );
            }
            bail!(
                "failed to restore User variable '{}': {write_err} (all previous writes rolled back cleanly)",
                var.name
            );
        }
        applied_names.push(var.name.clone());
    }

    Ok(summary)
}

/// Reverts variables written during a failed batch import back to their state in `baseline_map`.
fn rollback_user_writes(
    applied_names: &[String],
    baseline_map: &HashMap<String, &EnvVariable>,
) -> Option<String> {
    let mut errors = Vec::new();
    for name in applied_names.iter().rev() {
        let key = name.to_uppercase();
        let res = if let Some(prev) = baseline_map.get(&key) {
            write_scope_variable_with_kind(
                EnvScope::User,
                &prev.name,
                &prev.value,
                prev.effective_kind(),
            )
        } else {
            delete_scope_variable(EnvScope::User, name)
        };
        if let Err(err) = res {
            errors.push(format!("{name}: {err}"));
        }
    }
    if errors.is_empty() {
        None
    } else {
        Some(errors.join("; "))
    }
}

/// Atomically writes `state` to `path` so an elevated child process can resume unsaved TUI edits.
///
/// # Errors
///
/// Returns an error if serialization or atomic file writing fails.
pub fn save_pending_elevation_state(path: &Path, state: &PendingElevationState) -> Result<()> {
    let json = serde_json::to_string_pretty(state)
        .context("failed to serialize pending elevation state")?;
    write_atomic_bytes(path, json.as_bytes()).with_context(|| {
        format!(
            "failed to write pending elevation file '{}'",
            path.display()
        )
    })
}

/// Loads and validates a [`PendingElevationState`] from `path`, then removes the file on success.
///
/// # Errors
///
/// Returns an error if the file cannot be read, fails JSON deserialization, or has an invalid schema version.
pub fn load_and_consume_pending_elevation_state(path: &Path) -> Result<PendingElevationState> {
    let raw = fs::read_to_string(path).with_context(|| {
        format!(
            "failed to read pending elevation state from '{}'",
            path.display()
        )
    })?;
    let state: PendingElevationState =
        serde_json::from_str(&raw).context("failed to parse pending elevation JSON")?;
    if state.schema_version == 0 || state.schema_version > SCHEMA_VERSION {
        bail!(
            "unsupported pending elevation schema_version {}",
            state.schema_version
        );
    }
    let _ = fs::remove_file(path);
    Ok(state)
}

/// Writes `bytes` to `path` atomically by creating a sibling temporary file, flushing via
/// `sync_all`, and renaming over `path`.
fn write_atomic_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory '{}'", parent.display()))?;
        }
    }

    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "snapshot.json".to_string());
    let seq = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let tmp_name = format!(".{file_name}.{}.{seq}.tmp", std::process::id());
    let tmp_path = path.with_file_name(tmp_name);

    let write_result = (|| -> Result<()> {
        let mut file = File::create(&tmp_path)
            .with_context(|| format!("failed to create temporary file '{}'", tmp_path.display()))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    })();

    if let Err(err) = write_result {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }

    if let Err(err) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        bail!(
            "failed to atomically rename '{}' to '{}': {err}",
            tmp_path.display(),
            path.display()
        );
    }

    Ok(())
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::RegValueKind;

    fn unique_test_path(prefix: &str) -> PathBuf {
        let seq = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("{prefix}_{}_{seq}.json", std::process::id()))
    }

    #[test]
    fn roundtrips_environment_snapshot_json_atomically() {
        let user = vec![EnvVariable::with_kind(
            "Path",
            r"C:\Users\Me\.cargo\bin",
            EnvScope::User,
            RegValueKind::ExpandSz,
        )];
        let sys = vec![EnvVariable::with_kind(
            "JAVA_HOME",
            r"C:\Java\jdk-21",
            EnvScope::System,
            RegValueKind::Sz,
        )];
        let temp_file = unique_test_path("lazypath_test_snapshot");
        save_snapshot_file(&temp_file, &user, &sys).expect("save snapshot");
        let loaded = load_snapshot_file(&temp_file).expect("load snapshot");
        let _ = fs::remove_file(&temp_file);

        assert_eq!(loaded.schema_version, SCHEMA_VERSION);
        assert_eq!(loaded.user, user);
        assert_eq!(loaded.system, sys);
    }

    #[test]
    fn rejects_invalid_snapshot_schema_or_mismatched_scope() {
        let bad_scope = EnvSnapshot {
            schema_version: SCHEMA_VERSION,
            created_unix_secs: 100,
            user: vec![EnvVariable::new("FOO", "bar", EnvScope::System)],
            system: Vec::new(),
        };
        assert!(validate_snapshot(&bad_scope).is_err());

        let bad_version = EnvSnapshot {
            schema_version: 999,
            created_unix_secs: 100,
            user: Vec::new(),
            system: Vec::new(),
        };
        assert!(validate_snapshot(&bad_version).is_err());
    }

    #[test]
    fn computes_accurate_user_snapshot_import_diff() {
        let current = vec![
            EnvVariable::with_kind("UNCHANGED", "1", EnvScope::User, RegValueKind::Sz),
            EnvVariable::with_kind("UPDATED_VAL", "old", EnvScope::User, RegValueKind::Sz),
        ];
        let snapshot = EnvSnapshot {
            schema_version: SCHEMA_VERSION,
            created_unix_secs: 123,
            user: vec![
                EnvVariable::with_kind("UNCHANGED", "1", EnvScope::User, RegValueKind::Sz),
                EnvVariable::with_kind("UPDATED_VAL", "new", EnvScope::User, RegValueKind::Sz),
                EnvVariable::with_kind("ADDED_VAR", "hello", EnvScope::User, RegValueKind::Sz),
            ],
            system: Vec::new(),
        };

        let plan = plan_user_snapshot_import(&snapshot, &current);
        assert_eq!(plan.unchanged, 1);
        assert_eq!(plan.updated, 1);
        assert_eq!(plan.added, 1);
        assert_eq!(plan.changed(), 2);
        assert_eq!(plan.total(), 3);
    }

    #[test]
    fn roundtrips_and_consumes_pending_elevation_state() {
        let path = unique_test_path("lazypath_test_pending");
        let state = PendingElevationState {
            schema_version: SCHEMA_VERSION,
            created_unix_secs: current_unix_secs(),
            user_path_raw: vec![r"C:\UserBin".to_string()],
            system_path_raw: vec![r"C:\SysBin".to_string()],
            user_path_dirty: true,
            system_path_dirty: true,
            selected_sidebar: 1,
            selected_entry: 0,
        };
        save_pending_elevation_state(&path, &state).unwrap();
        assert!(path.exists());
        let loaded = load_and_consume_pending_elevation_state(&path).unwrap();
        assert_eq!(loaded, state);
        assert!(!path.exists());
    }
}
