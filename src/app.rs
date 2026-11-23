//! Interactive TUI application state, keybinding dispatch, and `PATH` editing actions.

use std::collections::HashMap;
use std::path::Path;

use crossterm::event::{KeyCode, KeyModifiers};

use crate::audit::{analyze_path_entries, summarize_audit};
use crate::expand::{join_path_entries, split_path_value};
use crate::model::{AuditSummary, EnvScope, EnvVariable, PathEntry};
use crate::registry::{
    broadcast_environment_change, build_lookup_map, relaunch_elevated, write_scope_variable,
};
use crate::snapshot::save_snapshot_file;

/// Default filename used when the user triggers a manual backup (`b`).
const MANUAL_BACKUP_FILENAME: &str = "lazypath-backup.json";

/// Filename written automatically before applying registry modifications (`s`).
const AUTO_BACKUP_FILENAME: &str = "lazypath-auto-backup.json";

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
    },
    /// Dialog for appending a new directory to the active `PATH`.
    AddEntry {
        /// Current text input buffer.
        buffer: String,
    },
    /// Keybindings help popup.
    Help,
}

/// Complete state of the `lazypath` TUI application.
pub struct App {
    /// Loaded User environment variables.
    pub user_vars: Vec<EnvVariable>,
    /// Loaded System environment variables.
    pub system_vars: Vec<EnvVariable>,
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
        let mut app = Self {
            user_vars,
            system_vars,
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

    /// Synchronizes the joined `Path` variable strings inside `user_vars` and `system_vars`
    /// from `user_path_raw` and `system_path_raw`.
    pub fn sync_path_vars_from_lists(&mut self) {
        let user_joined = join_path_entries(&self.user_path_raw);
        if let Some(v) = self.user_vars.iter_mut().find(|v| v.is_path_var()) {
            v.value = user_joined;
            v.modified = self.user_path_dirty;
        }
        let sys_joined = join_path_entries(&self.system_path_raw);
        if let Some(v) = self.system_vars.iter_mut().find(|v| v.is_path_var()) {
            v.value = sys_joined;
            v.modified = self.system_path_dirty;
        }
    }

    /// Recomputes `audited_entries` and `summary` for the currently active sidebar view.
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
        self.audited_entries = analyze_path_entries(&raw_items, &self.lookup);
        self.summary = summarize_audit(&self.audited_entries);
        self.clamp_entry_selection();
    }

    /// Returns audited `PATH` entries matching the active `filter_query` without
    /// allocating temporary lowercased strings.
    #[must_use]
    pub fn visible_entries(&self) -> Vec<&PathEntry> {
        let q = self.filter_query.trim();
        if q.is_empty() {
            return self.audited_entries.iter().collect();
        }
        self.audited_entries
            .iter()
            .filter(|e| {
                contains_ascii_case_insensitive(&e.expanded, q)
                    || contains_ascii_case_insensitive(&e.raw, q)
                    || e.executables
                        .iter()
                        .any(|exe| contains_ascii_case_insensitive(exe, q))
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
                    self.selected_sidebar = (self.selected_sidebar + 1) % self.sidebar_items.len();
                    self.selected_entry = 0;
                    self.rebuild_audit();
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
                    self.selected_sidebar = if self.selected_sidebar == 0 {
                        self.sidebar_items.len() - 1
                    } else {
                        self.selected_sidebar - 1
                    };
                    self.selected_entry = 0;
                    self.rebuild_audit();
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

    /// Appends a new directory entry to the active editable `PATH` (defaulting to User `PATH`).
    pub fn add_path_entry(&mut self, raw_dir: &str) {
        let trimmed = raw_dir.trim().trim_matches('"');
        if trimmed.is_empty() {
            self.log(LogLevel::Warn, "directory path cannot be empty");
            return;
        }
        let scope = self.editable_scope().unwrap_or(EnvScope::User);
        self.scope_list_mut(scope).push(trimmed.to_string());
        self.mark_scope_dirty(scope);
        self.rebuild_audit();
        self.log(
            LogLevel::Ok,
            format!(
                "appended '{trimmed}' to {} PATH (press 's' to save)",
                scope.label()
            ),
        );
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

    /// Exports a JSON snapshot of User and System environment variables to `lazypath-backup.json`.
    pub fn export_snapshot_backup(&mut self) {
        self.sync_path_vars_from_lists();
        let path = Path::new(MANUAL_BACKUP_FILENAME);
        match save_snapshot_file(path, &self.user_vars, &self.system_vars) {
            Ok(()) => {
                self.log(
                    LogLevel::Ok,
                    format!("saved environment snapshot to '{MANUAL_BACKUP_FILENAME}'"),
                );
            }
            Err(err) => {
                self.log(LogLevel::Err, format!("snapshot failed: {err}"));
            }
        }
    }

    /// Persists modified User and/or System `PATH` lists to the Windows Registry
    /// and broadcasts `WM_SETTINGCHANGE`.
    pub fn save_changes_to_registry(&mut self) {
        if !self.has_unsaved_changes() {
            self.log(LogLevel::Info, "no unsaved PATH modifications");
            return;
        }
        if self.system_path_dirty && !self.is_admin {
            self.log(
                LogLevel::Err,
                "Administrator privileges required to save System PATH (press 'E' to elevate)",
            );
            return;
        }
        self.sync_path_vars_from_lists();
        let backup_path = Path::new(AUTO_BACKUP_FILENAME);
        let _ = save_snapshot_file(backup_path, &self.user_vars, &self.system_vars);
        if self.user_path_dirty {
            let val = join_path_entries(&self.user_path_raw);
            if let Err(err) = write_scope_variable(EnvScope::User, "Path", &val) {
                self.log(LogLevel::Err, format!("failed to save User PATH: {err}"));
                return;
            }
            self.user_path_dirty = false;
        }
        if self.system_path_dirty {
            let val = join_path_entries(&self.system_path_raw);
            if let Err(err) = write_scope_variable(EnvScope::System, "Path", &val) {
                self.log(LogLevel::Err, format!("failed to save System PATH: {err}"));
                return;
            }
            self.system_path_dirty = false;
        }
        broadcast_environment_change();
        self.rebuild_audit();
        self.log(
            LogLevel::Ok,
            "saved PATH to Windows Registry and broadcasted WM_SETTINGCHANGE",
        );
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
                _ => {
                    self.modal = Modal::ExeInspector {
                        dir,
                        executables,
                        scroll,
                    };
                }
            },
            Modal::Filter { buffer } => self.on_filter_key(key, buffer),
            Modal::AddEntry { buffer } => self.on_add_entry_key(key, buffer),
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
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Esc => {
                if !self.filter_query.is_empty() {
                    self.filter_query.clear();
                    self.clamp_entry_selection();
                    self.log(LogLevel::Info, "search filter cleared");
                }
            }
            KeyCode::Down | KeyCode::Char('j') => self.move_next(),
            KeyCode::Up | KeyCode::Char('k') => self.move_prev(),
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
                };
            }
            KeyCode::Char('b') => self.export_snapshot_backup(),
            KeyCode::Char('s') => self.save_changes_to_registry(),
            KeyCode::Char('E') => match relaunch_elevated() {
                Ok(()) => self.should_quit = true,
                Err(err) => self.log(LogLevel::Err, format!("elevation failed: {err}")),
            },
            KeyCode::Char('?') => self.modal = Modal::Help,
            _ => {}
        }
    }

    fn on_filter_key(&mut self, key: KeyCode, mut buffer: String) {
        match key {
            KeyCode::Esc => {}
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
                self.modal = Modal::Filter { buffer };
            }
            KeyCode::Char(c) => {
                buffer.push(c);
                self.filter_query = buffer.trim().to_string();
                self.clamp_entry_selection();
                self.modal = Modal::Filter { buffer };
            }
            _ => {
                self.modal = Modal::Filter { buffer };
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

/// Checks whether `haystack` contains `needle` using ASCII case-insensitive comparison
/// without heap-allocating lowercased copies.
fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
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
        let user = vec![EnvVariable {
            name: "Path".to_string(),
            value: format!(r"{temp};C:\__missing_dir_lazypath__"),
            scope: EnvScope::User,
            modified: false,
        }];
        let sys = vec![EnvVariable {
            name: "Path".to_string(),
            value: temp,
            scope: EnvScope::System,
            modified: false,
        }];
        (user, sys)
    }

    #[test]
    fn handles_add_entry_and_filter_modals_via_keys() {
        let (u, s) = sample_vars();
        let mut app = App::new(u, s, false);
        app.on_key(KeyCode::Char('a'), KeyModifiers::NONE);
        app.on_key(KeyCode::Char('C'), KeyModifiers::NONE);
        app.on_key(KeyCode::Char(':'), KeyModifiers::NONE);
        app.on_key(KeyCode::Char('\\'), KeyModifiers::NONE);
        app.on_key(KeyCode::Char('T'), KeyModifiers::NONE);
        app.on_key(KeyCode::Enter, KeyModifiers::NONE);
        assert_eq!(app.user_path_raw.len(), 3);
        app.on_key(KeyCode::Char('/'), KeyModifiers::NONE);
        app.on_key(KeyCode::Char('m'), KeyModifiers::NONE);
        app.on_key(KeyCode::Char('i'), KeyModifiers::NONE);
        app.on_key(KeyCode::Char('s'), KeyModifiers::NONE);
        app.on_key(KeyCode::Enter, KeyModifiers::NONE);
        assert_eq!(app.visible_entries().len(), 1);
    }
}
