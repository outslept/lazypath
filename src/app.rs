//! Interactive TUI application state, keybinding dispatch, and `PATH` editing actions.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crossterm::event::{KeyCode, KeyModifiers};

use crate::audit::{analyze_path_entries_cached, summarize_audit, DirScanCache};
use crate::expand::{join_path_entries, split_path_value};
use crate::model::{AuditSummary, EnvScope, EnvVariable, PathEntry, RegValueKind, SCHEMA_VERSION};
use crate::registry::{
    broadcast_environment_change, build_lookup_map, delete_scope_variable, relaunch_elevated,
    relaunch_elevated_with_args, write_scope_variable_with_kind,
};
use crate::snapshot::{
    default_auto_backup_path, default_manual_backup_path, default_pending_elevation_path,
    save_pending_elevation_state, save_snapshot_file, PendingElevationState,
};

/// Number of rows jumped when pressing `PageUp` or `PageDown`.
const PAGE_SCROLL_STEP: usize = 10;

/// Which split pane currently holds keyboard focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pane {
    /// Left sidebar listing `PATH` views and environment variables.
    Variables,
    /// Right main table or variable inspector.
    Entries,
}

/// Severity level for the footer status bar message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    /// Operation completed successfully.
    Ok,
    /// Neutral informational message.
    Info,
    /// Non-fatal warning or user hint.
    Warn,
    /// Operation failed.
    Err,
}

impl LogLevel {
    /// Short badge label rendered in the footer status line.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Err => "err",
        }
    }
}

/// Footer status bar entry.
#[derive(Debug, Clone)]
pub struct StatusLog {
    /// Severity level determining badge color.
    pub level: LogLevel,
    /// Human-readable status text.
    pub message: String,
}

/// Selectable item in the left `Variables` pane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SidebarItem {
    /// User `PATH` (`HKCU\Environment`).
    PathUser,
    /// System `PATH` (`HKLM\...\Environment`).
    PathSystem,
    /// Combined effective `PATH` (System followed by User).
    PathCombined,
    /// Non-`PATH` environment variable.
    Variable {
        /// Owning registry scope.
        scope: EnvScope,
        /// Variable name.
        name: String,
    },
}

impl SidebarItem {
    /// Formats the sidebar label shown in the variables list and table title.
    #[must_use]
    pub fn display_label(&self) -> String {
        match self {
            Self::PathUser => "PATH (User)".to_string(),
            Self::PathSystem => "PATH (System)".to_string(),
            Self::PathCombined => "PATH (Combined)".to_string(),
            Self::Variable { scope, name } => format!("{name} ({})", scope.label()),
        }
    }

    /// Returns `true` if this sidebar item represents a non-`PATH` environment variable.
    #[must_use]
    pub const fn is_variable(&self) -> bool {
        matches!(self, Self::Variable { .. })
    }
}

/// Active modal overlay dialog, if any.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Modal {
    /// No modal overlay is open.
    #[default]
    None,
    /// Scrollable popup listing executables inside the selected `PATH` directory.
    ExeInspector {
        /// Expanded directory path being inspected.
        dir: String,
        /// Pairs of `(executable_name, optional_shadow_note)`.
        executables: Vec<(String, Option<String>)>,
        /// Currently highlighted executable index.
        scroll: usize,
    },
    /// Interactive search filter input dialog.
    Filter {
        /// Current text input buffer.
        buffer: String,
        /// Previous committed query restored if the user cancels with `Esc`.
        original_query: String,
    },
    /// Dialog for appending a new directory to the active `PATH`.
    AddEntry {
        /// Current text input buffer.
        buffer: String,
    },
    /// Confirmation dialog shown when pressing `q` with unsaved `PATH` edits.
    ConfirmQuit,
    /// Keybindings help popup.
    Help,
}

/// Complete state of the `lazypath` TUI application.
pub struct App {
    /// Loaded User environment variables (updated in-memory as `PATH` edits occur).
    pub user_vars: Vec<EnvVariable>,
    /// Loaded System environment variables (updated in-memory as `PATH` edits occur).
    pub system_vars: Vec<EnvVariable>,
    /// Last persisted User environment variables in the Registry (used for pre-save backups and rollback).
    pub saved_user_vars: Vec<EnvVariable>,
    /// Last persisted System environment variables in the Registry (used for pre-save backups and rollback).
    pub saved_system_vars: Vec<EnvVariable>,
    /// Merged uppercase environment lookup map for `%VAR%` expansion.
    pub lookup: HashMap<String, String>,
    /// Editable list of raw User `PATH` directories.
    pub user_path_raw: Vec<String>,
    /// Editable list of raw System `PATH` directories.
    pub system_path_raw: Vec<String>,
    /// Whether `user_path_raw` has unsaved edits.
    pub user_path_dirty: bool,
    /// Whether `system_path_raw` has unsaved edits.
    pub system_path_dirty: bool,
    /// Items displayed in the left sidebar.
    pub sidebar_items: Vec<SidebarItem>,
    /// Selected index in `sidebar_items`.
    pub selected_sidebar: usize,
    /// Selected row index in `visible_entries()`.
    pub selected_entry: usize,
    /// Currently focused pane.
    pub active_pane: Pane,
    /// Audited `PATH` entries for the currently selected sidebar item.
    pub audited_entries: Vec<PathEntry>,
    /// Summary metrics for `audited_entries`.
    pub summary: AuditSummary,
    /// Cache of directory executable scans to keep UI navigation non-blocking.
    pub scan_cache: DirScanCache,
    /// Active case-insensitive search query.
    pub filter_query: String,
    /// Active modal dialog state.
    pub modal: Modal,
    /// Whether the process is running elevated as Administrator.
    pub is_admin: bool,
    /// Latest status message shown in the footer.
    pub status_log: StatusLog,
    /// Set to `true` when the user requests application exit.
    pub should_quit: bool,
}

impl App {
    /// Initializes the TUI state and runs the initial `PATH` audit.
    #[must_use]
    pub fn new(user_vars: Vec<EnvVariable>, system_vars: Vec<EnvVariable>, is_admin: bool) -> Self {
        let lookup = build_lookup_map(&user_vars, &system_vars);
        let user_path_raw = extract_path_list(&user_vars);
        let system_path_raw = extract_path_list(&system_vars);
        let sidebar_items = build_sidebar_items(&user_vars, &system_vars);
        let saved_user_vars = user_vars.clone();
        let saved_system_vars = system_vars.clone();

        let mut app = Self {
            user_vars,
            system_vars,
            saved_user_vars,
            saved_system_vars,
            lookup,
            user_path_raw,
            system_path_raw,
            user_path_dirty: false,
            system_path_dirty: false,
            sidebar_items,
            selected_sidebar: 0,
            selected_entry: 0,
            active_pane: Pane::Entries,
            audited_entries: Vec::new(),
            summary: AuditSummary::default(),
            scan_cache: DirScanCache::new(),
            filter_query: String::new(),
            modal: Modal::None,
            is_admin,
            status_log: StatusLog {
                level: LogLevel::Info,
                message: "loaded Windows environment variables".to_string(),
            },
            should_quit: false,
        };
        app.rebuild_audit();
        let summary = &app.summary;
        app.log(
            LogLevel::Info,
            format!(
                "audited {} entries ({} missing, {} dup, {} conflicts)",
                summary.total_entries,
                summary.missing_count,
                summary.duplicate_count,
                summary.conflict_entries
            ),
        );
        app
    }

    /// Restores unsaved edits handed off from an unprivileged session via `--resume-pending`.
    pub fn apply_pending_elevation(&mut self, state: PendingElevationState) {
        self.user_path_raw = state.user_path_raw;
        self.system_path_raw = state.system_path_raw;
        self.user_path_dirty = state.user_path_dirty;
        self.system_path_dirty = state.system_path_dirty;
        if state.selected_sidebar < self.sidebar_items.len() {
            self.selected_sidebar = state.selected_sidebar;
        }
        self.selected_entry = state.selected_entry;
        self.rebuild_audit();
        self.log(
            LogLevel::Ok,
            "restored unsaved PATH edits in elevated Administrator session (press 's' to save)",
        );
    }

    /// Updates the footer status bar with a new message.
    pub fn log(&mut self, level: LogLevel, message: impl Into<String>) {
        self.status_log = StatusLog {
            level,
            message: message.into(),
        };
    }

    /// Returns `true` if either User or System `PATH` has unsaved changes.
    #[must_use]
    pub const fn has_unsaved_changes(&self) -> bool {
        self.user_path_dirty || self.system_path_dirty
    }

    /// Returns the currently highlighted [`SidebarItem`].
    #[must_use]
    pub fn current_sidebar(&self) -> &SidebarItem {
        self.sidebar_items
            .get(self.selected_sidebar)
            .unwrap_or(&SidebarItem::PathUser)
    }

    /// Returns the editable [`EnvScope`] if the user is viewing User or System `PATH` directly.
    #[must_use]
    pub fn editable_scope(&self) -> Option<EnvScope> {
        match self.current_sidebar() {
            SidebarItem::PathUser => Some(EnvScope::User),
            SidebarItem::PathSystem => Some(EnvScope::System),
            SidebarItem::PathCombined | SidebarItem::Variable { .. } => None,
        }
    }

    /// Returns the target [`EnvScope`] used when appending a new directory (`a`),
    /// defaulting to [`EnvScope::User`] when viewing `PATH (Combined)` or a variable.
    #[must_use]
    pub fn target_add_scope(&self) -> EnvScope {
        self.editable_scope().unwrap_or(EnvScope::User)
    }

    /// Synchronizes the joined `Path` variable strings inside `user_vars` and `system_vars`
    /// from `user_path_raw` and `system_path_raw`, creating the variable record if it did not
    /// initially exist, and refreshes `lookup`.
    pub fn sync_path_vars_from_lists(&mut self) {
        let user_joined = join_path_entries(&self.user_path_raw);
        if let Some(v) = self.user_vars.iter_mut().find(|v| v.is_path_var()) {
            v.value = user_joined;
            v.modified = self.user_path_dirty;
        } else if !user_joined.is_empty() || self.user_path_dirty {
            let mut var =
                EnvVariable::with_kind("Path", user_joined, EnvScope::User, RegValueKind::ExpandSz);
            var.modified = self.user_path_dirty;
            self.user_vars.insert(0, var);
        }

        let sys_joined = join_path_entries(&self.system_path_raw);
        if let Some(v) = self.system_vars.iter_mut().find(|v| v.is_path_var()) {
            v.value = sys_joined;
            v.modified = self.system_path_dirty;
        } else if !sys_joined.is_empty() || self.system_path_dirty {
            let mut var = EnvVariable::with_kind(
                "Path",
                sys_joined,
                EnvScope::System,
                RegValueKind::ExpandSz,
            );
            var.modified = self.system_path_dirty;
            self.system_vars.insert(0, var);
        }

        self.lookup = build_lookup_map(&self.user_vars, &self.system_vars);
    }

    /// Recomputes `audited_entries` and `summary` for the currently active sidebar view
    /// using cached directory scans.
    pub fn rebuild_audit(&mut self) {
        self.sync_path_vars_from_lists();
        let raw_items: Vec<(String, EnvScope)> = match self.current_sidebar() {
            SidebarItem::PathUser => self
                .user_path_raw
                .iter()
                .map(|p| (p.clone(), EnvScope::User))
                .collect(),
            SidebarItem::PathSystem => self
                .system_path_raw
                .iter()
                .map(|p| (p.clone(), EnvScope::System))
                .collect(),
            SidebarItem::PathCombined | SidebarItem::Variable { .. } => {
                let mut combined =
                    Vec::with_capacity(self.system_path_raw.len() + self.user_path_raw.len());
                combined.extend(
                    self.system_path_raw
                        .iter()
                        .map(|p| (p.clone(), EnvScope::System)),
                );
                combined.extend(
                    self.user_path_raw
                        .iter()
                        .map(|p| (p.clone(), EnvScope::User)),
                );
                combined
            }
        };
        self.audited_entries =
            analyze_path_entries_cached(&raw_items, &self.lookup, &mut self.scan_cache);
        self.summary = summarize_audit(&self.audited_entries);
        self.clamp_entry_selection();
    }

    /// Clears the directory scan cache and performs a fresh disk audit (`r`).
    pub fn refresh_audit(&mut self) {
        self.scan_cache.clear();
        self.rebuild_audit();
        self.log(
            LogLevel::Ok,
            format!(
                "rescanned {} PATH directories from disk ({} missing, {} dup, {} conflicts)",
                self.summary.total_entries,
                self.summary.missing_count,
                self.summary.duplicate_count,
                self.summary.conflict_entries
            ),
        );
    }

    /// Returns audited `PATH` entries matching the active `filter_query`.
    #[must_use]
    pub fn visible_entries(&self) -> Vec<&PathEntry> {
        let q = self.filter_query.trim();
        if q.is_empty() {
            return self.audited_entries.iter().collect();
        }
        self.audited_entries
            .iter()
            .filter(|e| {
                contains_case_insensitive(&e.expanded, q)
                    || contains_case_insensitive(&e.raw, q)
                    || e.executables
                        .iter()
                        .any(|exe| contains_case_insensitive(exe, q))
            })
            .collect()
    }

    /// Returns the currently selected [`PathEntry`] in the visible table, if any.
    #[must_use]
    pub fn selected_path_entry(&self) -> Option<&PathEntry> {
        let visible = self.visible_entries();
        visible.get(self.selected_entry).copied()
    }

    /// Returns the currently selected non-`PATH` [`EnvVariable`] when a variable item
    /// is highlighted in the sidebar.
    #[must_use]
    pub fn selected_variable(&self) -> Option<&EnvVariable> {
        let SidebarItem::Variable { scope, name } = self.current_sidebar() else {
            return None;
        };
        let list = match scope {
            EnvScope::User => &self.user_vars,
            EnvScope::System => &self.system_vars,
        };
        list.iter().find(|v| &v.name == name)
    }

    /// Ensures `selected_entry` stays within the bounds of `visible_entries()`.
    pub fn clamp_entry_selection(&mut self) {
        let len = self.visible_entries().len();
        if len == 0 {
            self.selected_entry = 0;
        } else if self.selected_entry >= len {
            self.selected_entry = len - 1;
        }
    }

    /// Moves selection down in the currently active pane (wrapping around).
    pub fn move_next(&mut self) {
        match self.active_pane {
            Pane::Variables => {
                if !self.sidebar_items.is_empty() {
                    let prev_was_var = self.current_sidebar().is_variable();
                    self.selected_sidebar = (self.selected_sidebar + 1) % self.sidebar_items.len();
                    self.selected_entry = 0;
                    if !prev_was_var || !self.current_sidebar().is_variable() {
                        self.rebuild_audit();
                    }
                }
            }
            Pane::Entries => {
                let len = self.visible_entries().len();
                if len > 0 {
                    self.selected_entry = (self.selected_entry + 1) % len;
                }
            }
        }
    }

    /// Moves selection up in the currently active pane (wrapping around).
    pub fn move_prev(&mut self) {
        match self.active_pane {
            Pane::Variables => {
                if !self.sidebar_items.is_empty() {
                    let prev_was_var = self.current_sidebar().is_variable();
                    self.selected_sidebar = if self.selected_sidebar == 0 {
                        self.sidebar_items.len() - 1
                    } else {
                        self.selected_sidebar - 1
                    };
                    self.selected_entry = 0;
                    if !prev_was_var || !self.current_sidebar().is_variable() {
                        self.rebuild_audit();
                    }
                }
            }
            Pane::Entries => {
                let len = self.visible_entries().len();
                if len > 0 {
                    self.selected_entry = if self.selected_entry == 0 {
                        len - 1
                    } else {
                        self.selected_entry - 1
                    };
                }
            }
        }
    }

    /// Jumps to the first item in the currently active pane (`Home`).
    pub fn move_first(&mut self) {
        match self.active_pane {
            Pane::Variables => {
                if !self.sidebar_items.is_empty() && self.selected_sidebar != 0 {
                    let prev_was_var = self.current_sidebar().is_variable();
                    self.selected_sidebar = 0;
                    self.selected_entry = 0;
                    if !prev_was_var || !self.current_sidebar().is_variable() {
                        self.rebuild_audit();
                    }
                }
            }
            Pane::Entries => {
                self.selected_entry = 0;
            }
        }
    }

    /// Jumps to the last item in the currently active pane (`End`).
    pub fn move_last(&mut self) {
        match self.active_pane {
            Pane::Variables => {
                if !self.sidebar_items.is_empty() {
                    let prev_was_var = self.current_sidebar().is_variable();
                    self.selected_sidebar = self.sidebar_items.len() - 1;
                    self.selected_entry = 0;
                    if !prev_was_var || !self.current_sidebar().is_variable() {
                        self.rebuild_audit();
                    }
                }
            }
            Pane::Entries => {
                let len = self.visible_entries().len();
                if len > 0 {
                    self.selected_entry = len - 1;
                }
            }
        }
    }

    /// Moves selection down by [`PAGE_SCROLL_STEP`] in the currently active pane (`PageDown`).
    pub fn move_page_down(&mut self) {
        match self.active_pane {
            Pane::Variables => {
                if !self.sidebar_items.is_empty() {
                    let prev_was_var = self.current_sidebar().is_variable();
                    self.selected_sidebar = (self.selected_sidebar + PAGE_SCROLL_STEP)
                        .min(self.sidebar_items.len() - 1);
                    self.selected_entry = 0;
                    if !prev_was_var || !self.current_sidebar().is_variable() {
                        self.rebuild_audit();
                    }
                }
            }
            Pane::Entries => {
                let len = self.visible_entries().len();
                if len > 0 {
                    self.selected_entry = (self.selected_entry + PAGE_SCROLL_STEP).min(len - 1);
                }
            }
        }
    }

    /// Moves selection up by [`PAGE_SCROLL_STEP`] in the currently active pane (`PageUp`).
    pub fn move_page_up(&mut self) {
        match self.active_pane {
            Pane::Variables => {
                if !self.sidebar_items.is_empty() {
                    let prev_was_var = self.current_sidebar().is_variable();
                    self.selected_sidebar = self.selected_sidebar.saturating_sub(PAGE_SCROLL_STEP);
                    self.selected_entry = 0;
                    if !prev_was_var || !self.current_sidebar().is_variable() {
                        self.rebuild_audit();
                    }
                }
            }
            Pane::Entries => {
                self.selected_entry = self.selected_entry.saturating_sub(PAGE_SCROLL_STEP);
            }
        }
    }

    /// Switches keyboard focus between the `Variables` sidebar and `Entries` table.
    pub const fn toggle_pane(&mut self) {
        self.active_pane = match self.active_pane {
            Pane::Variables => Pane::Entries,
            Pane::Entries => Pane::Variables,
        };
    }

    /// Moves the selected `PATH` entry one position higher in priority.
    pub fn move_entry_up(&mut self) {
        if !self.filter_query.is_empty() {
            self.log(LogLevel::Warn, "clear search filter before reordering PATH");
            return;
        }
        let Some(scope) = self.editable_scope() else {
            self.log(
                LogLevel::Warn,
                "select PATH (User) or PATH (System) to reorder entries",
            );
            return;
        };
        if self.selected_entry == 0 {
            return;
        }
        let idx = self.selected_entry;
        let list = self.scope_list_mut(scope);
        if idx < list.len() {
            list.swap(idx - 1, idx);
            self.mark_scope_dirty(scope);
            self.selected_entry -= 1;
            self.rebuild_audit();
            self.log(
                LogLevel::Ok,
                format!("moved entry up to #{idx} (press 's' to save)"),
            );
        }
    }

    /// Moves the selected `PATH` entry one position lower in priority.
    pub fn move_entry_down(&mut self) {
        if !self.filter_query.is_empty() {
            self.log(LogLevel::Warn, "clear search filter before reordering PATH");
            return;
        }
        let Some(scope) = self.editable_scope() else {
            self.log(
                LogLevel::Warn,
                "select PATH (User) or PATH (System) to reorder entries",
            );
            return;
        };
        let idx = self.selected_entry;
        let len = self.scope_list_mut(scope).len();
        if idx + 1 < len {
            self.scope_list_mut(scope).swap(idx, idx + 1);
            self.mark_scope_dirty(scope);
            self.selected_entry += 1;
            self.rebuild_audit();
            self.log(
                LogLevel::Ok,
                format!("moved entry down to #{} (press 's' to save)", idx + 2),
            );
        }
    }

    /// Removes all missing and duplicate entries from the currently selected editable `PATH`.
    pub fn prune_invalid_entries(&mut self) {
        if !self.filter_query.is_empty() {
            self.log(
                LogLevel::Warn,
                "clear search filter before pruning dead entries",
            );
            return;
        }
        let Some(scope) = self.editable_scope() else {
            self.log(
                LogLevel::Warn,
                "select PATH (User) or PATH (System) to prune dead entries",
            );
            return;
        };
        let remove_indices: Vec<usize> = self
            .audited_entries
            .iter()
            .filter(|e| e.is_removable_junk())
            .map(|e| e.index)
            .collect();
        if remove_indices.is_empty() {
            self.log(
                LogLevel::Info,
                format!("no missing or duplicate entries in {} PATH", scope.label()),
            );
            return;
        }
        let removed_count = remove_indices.len();
        let list = self.scope_list_mut(scope);
        for &idx in remove_indices.iter().rev() {
            if idx < list.len() {
                list.remove(idx);
            }
        }
        self.mark_scope_dirty(scope);
        self.rebuild_audit();
        self.log(
            LogLevel::Ok,
            format!(
                "pruned {removed_count} dead/duplicate entries from {} PATH (press 's' to save)",
                scope.label()
            ),
        );
    }

    /// Deletes the currently highlighted entry from the active editable `PATH`.
    pub fn delete_selected_entry(&mut self) {
        let Some(scope) = self.editable_scope() else {
            self.log(
                LogLevel::Warn,
                "select PATH (User) or PATH (System) to remove an entry",
            );
            return;
        };
        let Some(entry_idx) = self.selected_path_entry().map(|e| e.index) else {
            return;
        };
        let list = self.scope_list_mut(scope);
        if entry_idx < list.len() {
            let removed = list.remove(entry_idx);
            self.mark_scope_dirty(scope);
            self.rebuild_audit();
            self.log(
                LogLevel::Ok,
                format!(
                    "removed '{removed}' from {} PATH (press 's' to save)",
                    scope.label()
                ),
            );
        }
    }

    /// Appends one or more directory entries to the active editable `PATH` (defaulting to User `PATH`).
    ///
    /// Automatically splits semicolon-delimited input (respecting quoted semicolons) so pasting
    /// multiple directories does not create a single malformed entry.
    pub fn add_path_entry(&mut self, raw_dir: &str) {
        let parts = split_path_value(raw_dir);
        if parts.is_empty() {
            self.log(LogLevel::Warn, "directory path cannot be empty");
            return;
        }
        let scope = self.target_add_scope();
        let count = parts.len();
        let first = parts[0].clone();
        self.scope_list_mut(scope).extend(parts);
        self.mark_scope_dirty(scope);
        self.rebuild_audit();
        if count == 1 {
            self.log(
                LogLevel::Ok,
                format!(
                    "appended '{first}' to {} PATH (press 's' to save)",
                    scope.label()
                ),
            );
        } else {
            self.log(
                LogLevel::Ok,
                format!(
                    "appended {count} directories to {} PATH (press 's' to save)",
                    scope.label()
                ),
            );
        }
    }

    /// Opens the executable inspector modal for the currently selected `PATH` directory.
    pub fn open_exe_inspector(&mut self) {
        let Some(entry) = self.selected_path_entry() else {
            self.log(LogLevel::Warn, "no PATH directory selected");
            return;
        };
        if !entry.exists {
            self.log(LogLevel::Warn, "directory does not exist on disk");
            return;
        }
        if entry.executables.is_empty() {
            self.log(LogLevel::Info, "directory contains 0 executables");
            return;
        }
        let dir = entry.expanded.clone();
        let mut annotated = Vec::with_capacity(entry.executables.len());
        for exe in &entry.executables {
            let note = if let Some(s) = entry
                .shadows
                .iter()
                .find(|t| t.binary.eq_ignore_ascii_case(exe))
            {
                Some(format!("shadows #{} ({})", s.other_index + 1, s.other_dir))
            } else {
                entry
                    .shadowed_by
                    .iter()
                    .find(|t| t.binary.eq_ignore_ascii_case(exe))
                    .map(|s| format!("shadowed by #{} ({})", s.other_index + 1, s.other_dir))
            };
            annotated.push((exe.clone(), note));
        }
        self.modal = Modal::ExeInspector {
            dir,
            executables: annotated,
            scroll: 0,
        };
    }

    /// Exports a JSON snapshot of User and System environment variables to
    /// `%LOCALAPPDATA%\lazypath\lazypath-backup.json`.
    pub fn export_snapshot_backup(&mut self) {
        self.sync_path_vars_from_lists();
        let path = default_manual_backup_path();
        match save_snapshot_file(&path, &self.user_vars, &self.system_vars) {
            Ok(()) => {
                self.log(
                    LogLevel::Ok,
                    format!("saved environment snapshot to '{}'", path.display()),
                );
            }
            Err(err) => {
                self.log(LogLevel::Err, format!("snapshot failed: {err}"));
            }
        }
    }

    /// Persists modified User and/or System `PATH` lists to the Windows Registry
    /// after writing a mandatory pre-save backup of the prior Registry state, rolling
    /// back User `PATH` if a subsequent System `PATH` write fails, and broadcasting
    /// `WM_SETTINGCHANGE`.
    pub fn save_changes_to_registry(&mut self) {
        if !self.has_unsaved_changes() {
            self.log(LogLevel::Info, "no unsaved PATH modifications");
            return;
        }
        if self.system_path_dirty && !self.is_admin {
            self.log(
                LogLevel::Err,
                "Administrator privileges required to save System PATH (press 'E' to elevate with edits)",
            );
            return;
        }

        // 1. Write mandatory pre-save backup of the LAST PERSISTED registry state before mutating.
        let backup_path = default_auto_backup_path();
        if let Err(err) =
            save_snapshot_file(&backup_path, &self.saved_user_vars, &self.saved_system_vars)
        {
            self.log(
                LogLevel::Err,
                format!(
                    "aborted save: failed to create pre-save backup at '{}': {err}",
                    backup_path.display()
                ),
            );
            return;
        }

        let prev_user_path = self
            .saved_user_vars
            .iter()
            .find(|v| v.is_path_var())
            .cloned();

        let mut wrote_user = false;
        if self.user_path_dirty {
            let val = join_path_entries(&self.user_path_raw);
            if let Err(err) =
                write_scope_variable_with_kind(EnvScope::User, "Path", &val, RegValueKind::ExpandSz)
            {
                self.log(LogLevel::Err, format!("failed to save User PATH: {err}"));
                return;
            }
            wrote_user = true;
        }

        if self.system_path_dirty {
            let val = join_path_entries(&self.system_path_raw);
            if let Err(err) = write_scope_variable_with_kind(
                EnvScope::System,
                "Path",
                &val,
                RegValueKind::ExpandSz,
            ) {
                if wrote_user {
                    let rb_res = match &prev_user_path {
                        Some(old_var) => write_scope_variable_with_kind(
                            EnvScope::User,
                            &old_var.name,
                            &old_var.value,
                            old_var.effective_kind(),
                        ),
                        None => delete_scope_variable(EnvScope::User, "Path"),
                    };
                    match rb_res {
                        Ok(()) => {
                            self.log(
                                LogLevel::Err,
                                format!(
                                    "failed to save System PATH: {err} (User PATH rolled back cleanly)"
                                ),
                            );
                        }
                        Err(rb_err) => {
                            self.log(
                                LogLevel::Err,
                                format!(
                                    "failed to save System PATH: {err} (User PATH rollback also failed: {rb_err}; backup at '{}')",
                                    backup_path.display()
                                ),
                            );
                        }
                    }
                } else {
                    self.log(LogLevel::Err, format!("failed to save System PATH: {err}"));
                }
                return;
            }
        }

        self.user_path_dirty = false;
        self.system_path_dirty = false;
        self.sync_path_vars_from_lists();
        self.saved_user_vars = self.user_vars.clone();
        self.saved_system_vars = self.system_vars.clone();
        self.rebuild_audit();

        match broadcast_environment_change() {
            Ok(()) => {
                self.log(
                    LogLevel::Ok,
                    "saved PATH to Windows Registry and broadcasted WM_SETTINGCHANGE",
                );
            }
            Err(err) => {
                self.log(
                    LogLevel::Warn,
                    format!("saved PATH to Registry, but WM_SETTINGCHANGE broadcast failed: {err}"),
                );
            }
        }
    }

    /// Relaunches `lazypath` with UAC Administrator privileges (`E`), serializing and forwarding
    /// any unsaved `PATH` edits so they are preserved in the elevated session.
    pub fn elevate_session(&mut self) {
        if self.is_admin {
            self.log(
                LogLevel::Info,
                "already running with Administrator privileges",
            );
            return;
        }

        if !self.has_unsaved_changes() {
            match relaunch_elevated() {
                Ok(()) => self.should_quit = true,
                Err(err) => self.log(LogLevel::Err, format!("elevation failed: {err}")),
            }
            return;
        }

        let pending_path = default_pending_elevation_path();
        let created_unix_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let state = PendingElevationState {
            schema_version: SCHEMA_VERSION,
            created_unix_secs,
            user_path_raw: self.user_path_raw.clone(),
            system_path_raw: self.system_path_raw.clone(),
            user_path_dirty: self.user_path_dirty,
            system_path_dirty: self.system_path_dirty,
            selected_sidebar: self.selected_sidebar,
            selected_entry: self.selected_entry,
        };

        if let Err(err) = save_pending_elevation_state(&pending_path, &state) {
            self.log(
                LogLevel::Err,
                format!("cannot elevate: failed to save pending edits: {err}"),
            );
            return;
        }

        let args = vec![
            "--resume-pending".to_string(),
            pending_path.to_string_lossy().into_owned(),
        ];
        match relaunch_elevated_with_args(&args) {
            Ok(()) => {
                self.should_quit = true;
            }
            Err(err) => {
                let _ = std::fs::remove_file(&pending_path);
                self.log(LogLevel::Err, format!("elevation failed: {err}"));
            }
        }
    }

    /// Handles a single keyboard press event in either normal mode or the active modal.
    pub fn on_key(&mut self, key: KeyCode, modifiers: KeyModifiers) {
        if modifiers.contains(KeyModifiers::CONTROL) && key == KeyCode::Char('c') {
            self.should_quit = true;
            return;
        }
        match std::mem::take(&mut self.modal) {
            Modal::None => self.on_normal_key(key, modifiers),
            Modal::ExeInspector {
                dir,
                executables,
                mut scroll,
            } => match key {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {}
                KeyCode::Down | KeyCode::Char('j') => {
                    if scroll + 1 < executables.len() {
                        scroll += 1;
                    }
                    self.modal = Modal::ExeInspector {
                        dir,
                        executables,
                        scroll,
                    };
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    scroll = scroll.saturating_sub(1);
                    self.modal = Modal::ExeInspector {
                        dir,
                        executables,
                        scroll,
                    };
                }
                KeyCode::PageDown => {
                    if !executables.is_empty() {
                        scroll = (scroll + PAGE_SCROLL_STEP).min(executables.len() - 1);
                    }
                    self.modal = Modal::ExeInspector {
                        dir,
                        executables,
                        scroll,
                    };
                }
                KeyCode::PageUp => {
                    scroll = scroll.saturating_sub(PAGE_SCROLL_STEP);
                    self.modal = Modal::ExeInspector {
                        dir,
                        executables,
                        scroll,
                    };
                }
                KeyCode::Home => {
                    scroll = 0;
                    self.modal = Modal::ExeInspector {
                        dir,
                        executables,
                        scroll,
                    };
                }
                KeyCode::End => {
                    if !executables.is_empty() {
                        scroll = executables.len() - 1;
                    }
                    self.modal = Modal::ExeInspector {
                        dir,
                        executables,
                        scroll,
                    };
                }
                _ => {
                    self.modal = Modal::ExeInspector {
                        dir,
                        executables,
                        scroll,
                    };
                }
            },
            Modal::Filter {
                buffer,
                original_query,
            } => self.on_filter_key(key, buffer, original_query),
            Modal::AddEntry { buffer } => self.on_add_entry_key(key, buffer),
            Modal::ConfirmQuit => match key {
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Char('q') | KeyCode::Enter => {
                    self.should_quit = true;
                }
                KeyCode::Char('s') | KeyCode::Char('S') => {
                    self.save_changes_to_registry();
                    if !self.has_unsaved_changes() {
                        self.should_quit = true;
                    }
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    self.log(LogLevel::Info, "quit canceled; unsaved edits preserved");
                }
                _ => {
                    self.modal = Modal::ConfirmQuit;
                }
            },
            Modal::Help => {
                if !matches!(
                    key,
                    KeyCode::Esc | KeyCode::Enter | KeyCode::Char('?') | KeyCode::Char('q')
                ) {
                    self.modal = Modal::Help;
                }
            }
        }
    }

    fn on_normal_key(&mut self, key: KeyCode, modifiers: KeyModifiers) {
        if modifiers.contains(KeyModifiers::ALT) {
            match key {
                KeyCode::Up => {
                    self.move_entry_up();
                    return;
                }
                KeyCode::Down => {
                    self.move_entry_down();
                    return;
                }
                _ => {}
            }
        }
        match key {
            KeyCode::Char('q') => {
                if self.has_unsaved_changes() {
                    self.modal = Modal::ConfirmQuit;
                } else {
                    self.should_quit = true;
                }
            }
            KeyCode::Esc => {
                if !self.filter_query.is_empty() {
                    self.filter_query.clear();
                    self.clamp_entry_selection();
                    self.log(LogLevel::Info, "search filter cleared");
                }
            }
            KeyCode::Down | KeyCode::Char('j') => self.move_next(),
            KeyCode::Up | KeyCode::Char('k') => self.move_prev(),
            KeyCode::Home => self.move_first(),
            KeyCode::End => self.move_last(),
            KeyCode::PageDown => self.move_page_down(),
            KeyCode::PageUp => self.move_page_up(),
            KeyCode::Char('J') => self.move_entry_down(),
            KeyCode::Char('K') => self.move_entry_up(),
            KeyCode::Tab
            | KeyCode::Left
            | KeyCode::Right
            | KeyCode::Char('h')
            | KeyCode::Char('l') => self.toggle_pane(),
            KeyCode::Enter => self.open_exe_inspector(),
            KeyCode::Char('d') => self.prune_invalid_entries(),
            KeyCode::Char('x') | KeyCode::Delete => self.delete_selected_entry(),
            KeyCode::Char('a') => {
                self.modal = Modal::AddEntry {
                    buffer: String::new(),
                };
            }
            KeyCode::Char('/') | KeyCode::Char('w') => {
                self.modal = Modal::Filter {
                    buffer: self.filter_query.clone(),
                    original_query: self.filter_query.clone(),
                };
            }
            KeyCode::Char('r') => self.refresh_audit(),
            KeyCode::Char('b') => self.export_snapshot_backup(),
            KeyCode::Char('s') => self.save_changes_to_registry(),
            KeyCode::Char('E') => self.elevate_session(),
            KeyCode::Char('?') => self.modal = Modal::Help,
            _ => {}
        }
    }

    fn on_filter_key(&mut self, key: KeyCode, mut buffer: String, original_query: String) {
        match key {
            KeyCode::Esc => {
                self.filter_query = original_query;
                self.clamp_entry_selection();
                self.log(LogLevel::Info, "search filter edit canceled");
            }
            KeyCode::Enter => {
                self.filter_query = buffer.trim().to_string();
                self.clamp_entry_selection();
                if self.filter_query.is_empty() {
                    self.log(LogLevel::Info, "search filter cleared");
                } else {
                    let q = self.filter_query.clone();
                    self.log(LogLevel::Info, format!("filtered entries by '{q}'"));
                }
            }
            KeyCode::Backspace => {
                buffer.pop();
                self.filter_query = buffer.trim().to_string();
                self.clamp_entry_selection();
                self.modal = Modal::Filter {
                    buffer,
                    original_query,
                };
            }
            KeyCode::Char(c) => {
                buffer.push(c);
                self.filter_query = buffer.trim().to_string();
                self.clamp_entry_selection();
                self.modal = Modal::Filter {
                    buffer,
                    original_query,
                };
            }
            _ => {
                self.modal = Modal::Filter {
                    buffer,
                    original_query,
                };
            }
        }
    }

    fn on_add_entry_key(&mut self, key: KeyCode, mut buffer: String) {
        match key {
            KeyCode::Esc => {}
            KeyCode::Enter => {
                self.add_path_entry(&buffer);
            }
            KeyCode::Backspace => {
                buffer.pop();
                self.modal = Modal::AddEntry { buffer };
            }
            KeyCode::Char(c) => {
                buffer.push(c);
                self.modal = Modal::AddEntry { buffer };
            }
            _ => {
                self.modal = Modal::AddEntry { buffer };
            }
        }
    }

    const fn scope_list_mut(&mut self, scope: EnvScope) -> &mut Vec<String> {
        match scope {
            EnvScope::User => &mut self.user_path_raw,
            EnvScope::System => &mut self.system_path_raw,
        }
    }

    const fn mark_scope_dirty(&mut self, scope: EnvScope) {
        match scope {
            EnvScope::User => self.user_path_dirty = true,
            EnvScope::System => self.system_path_dirty = true,
        }
    }
}

/// Checks whether `haystack` contains `needle` case-insensitively.
///
/// Uses a zero-allocation byte window scan when both strings are pure ASCII and falls back
/// to full Unicode `.to_lowercase()` folding when either string contains non-ASCII characters.
fn contains_case_insensitive(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.is_ascii() && needle.is_ascii() {
        return haystack
            .as_bytes()
            .windows(needle.len())
            .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()));
    }
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

fn extract_path_list(vars: &[EnvVariable]) -> Vec<String> {
    vars.iter()
        .find(|v| v.is_path_var())
        .map(|v| split_path_value(&v.value))
        .unwrap_or_default()
}

fn build_sidebar_items(user_vars: &[EnvVariable], system_vars: &[EnvVariable]) -> Vec<SidebarItem> {
    let mut items = vec![
        SidebarItem::PathUser,
        SidebarItem::PathSystem,
        SidebarItem::PathCombined,
    ];
    for v in user_vars {
        if !v.is_path_var() {
            items.push(SidebarItem::Variable {
                scope: EnvScope::User,
                name: v.name.clone(),
            });
        }
    }
    for v in system_vars {
        if !v.is_path_var() {
            items.push(SidebarItem::Variable {
                scope: EnvScope::System,
                name: v.name.clone(),
            });
        }
    }
    items
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_vars() -> (Vec<EnvVariable>, Vec<EnvVariable>) {
        let temp = std::env::temp_dir().to_string_lossy().to_string();
        let user = vec![EnvVariable::with_kind(
            "Path",
            format!(r"{temp};C:\__missing_dir_lazypath__"),
            EnvScope::User,
            RegValueKind::ExpandSz,
        )];
        let sys = vec![EnvVariable::with_kind(
            "Path",
            temp,
            EnvScope::System,
            RegValueKind::ExpandSz,
        )];
        (user, sys)
    }

    #[test]
    fn handles_add_entry_and_filter_modals_including_esc_revert() {
        let (u, s) = sample_vars();
        let mut app = App::new(u, s, false);
        app.on_key(KeyCode::Char('a'), KeyModifiers::NONE);
        app.on_key(KeyCode::Char('C'), KeyModifiers::NONE);
        app.on_key(KeyCode::Char(':'), KeyModifiers::NONE);
        app.on_key(KeyCode::Char('\\'), KeyModifiers::NONE);
        app.on_key(KeyCode::Char('T'), KeyModifiers::NONE);
        app.on_key(KeyCode::Enter, KeyModifiers::NONE);
        assert_eq!(app.user_path_raw.len(), 3);

        // Apply filter via Enter
        app.on_key(KeyCode::Char('/'), KeyModifiers::NONE);
        app.on_key(KeyCode::Char('m'), KeyModifiers::NONE);
        app.on_key(KeyCode::Char('i'), KeyModifiers::NONE);
        app.on_key(KeyCode::Char('s'), KeyModifiers::NONE);
        app.on_key(KeyCode::Enter, KeyModifiers::NONE);
        assert_eq!(app.filter_query, "mis");
        assert_eq!(app.visible_entries().len(), 1);

        // Re-open filter, type extra chars, then press Esc -> reverts to "mis"
        app.on_key(KeyCode::Char('/'), KeyModifiers::NONE);
        app.on_key(KeyCode::Char('z'), KeyModifiers::NONE);
        app.on_key(KeyCode::Char('z'), KeyModifiers::NONE);
        assert_eq!(app.filter_query, "miszz");
        app.on_key(KeyCode::Esc, KeyModifiers::NONE);
        assert_eq!(app.filter_query, "mis");
    }

    #[test]
    fn prompts_before_quitting_with_unsaved_changes() {
        let (u, s) = sample_vars();
        let mut app = App::new(u, s, false);
        app.add_path_entry(r"C:\NewTools;C:\OtherTools");
        assert_eq!(app.user_path_raw.len(), 4);
        assert!(app.has_unsaved_changes());

        // Pressing 'q' opens ConfirmQuit instead of exiting immediately
        app.on_key(KeyCode::Char('q'), KeyModifiers::NONE);
        assert!(!app.should_quit);
        assert_eq!(app.modal, Modal::ConfirmQuit);

        // Pressing 'n' cancels quit
        app.on_key(KeyCode::Char('n'), KeyModifiers::NONE);
        assert!(!app.should_quit);
        assert_eq!(app.modal, Modal::None);

        // Pressing 'q' then 'y' confirms quit
        app.on_key(KeyCode::Char('q'), KeyModifiers::NONE);
        app.on_key(KeyCode::Char('y'), KeyModifiers::NONE);
        assert!(app.should_quit);
    }

    #[test]
    fn blocks_prune_when_filter_is_active_and_supports_unicode_search() {
        let (u, s) = sample_vars();
        let mut app = App::new(u, s, false);
        app.add_path_entry(r"C:\Пользователи\Аня\bin");
        app.filter_query = "аня".to_string();
        assert_eq!(app.visible_entries().len(), 1);

        let len_before = app.user_path_raw.len();
        app.prune_invalid_entries();
        assert_eq!(app.user_path_raw.len(), len_before);
        assert_eq!(app.status_log.level, LogLevel::Warn);
    }
}
