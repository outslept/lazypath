use std::collections::HashMap;

use crate::audit::{analyze_path_entries, summarize_audit};
use crate::expand::split_path_value;
use crate::model::{AuditSummary, EnvScope, EnvVariable, PathEntry};
use crate::registry::build_lookup_map;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pane {
    Variables,
    Entries,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Ok,
    Info,
    Warn,
    Err,
}

impl LogLevel {
    pub fn tag(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Err => "err",
        }
    }
}

#[derive(Debug, Clone)]
pub struct StatusLog {
    pub level: LogLevel,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SidebarItem {
    PathUser,
    PathSystem,
    PathCombined,
    Variable { scope: EnvScope, name: String },
}

impl SidebarItem {
    pub fn display_label(&self) -> String {
        match self {
            Self::PathUser => "PATH (User)".to_string(),
            Self::PathSystem => "PATH (System)".to_string(),
            Self::PathCombined => "PATH (Combined)".to_string(),
            Self::Variable { scope, name } => format!("{name} ({})", scope.label()),
        }
    }
}

pub struct App {
    pub user_vars: Vec<EnvVariable>,
    pub system_vars: Vec<EnvVariable>,
    pub lookup: HashMap<String, String>,
    pub user_path_raw: Vec<String>,
    pub system_path_raw: Vec<String>,
    pub user_path_dirty: bool,
    pub system_path_dirty: bool,
    pub sidebar_items: Vec<SidebarItem>,
    pub selected_sidebar: usize,
    pub selected_entry: usize,
    pub active_pane: Pane,
    pub audited_entries: Vec<PathEntry>,
    pub summary: AuditSummary,
    pub filter_query: String,
    pub is_admin: bool,
    pub status_log: StatusLog,
    pub should_quit: bool,
}

impl App {
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

    pub fn log(&mut self, level: LogLevel, message: impl Into<String>) {
        self.status_log = StatusLog {
            level,
            message: message.into(),
        };
    }

    pub fn current_sidebar(&self) -> &SidebarItem {
        self.sidebar_items
            .get(self.selected_sidebar)
            .unwrap_or(&SidebarItem::PathUser)
    }

    pub fn editable_scope(&self) -> Option<EnvScope> {
        match self.current_sidebar() {
            SidebarItem::PathUser => Some(EnvScope::User),
            SidebarItem::PathSystem => Some(EnvScope::System),
            SidebarItem::PathCombined | SidebarItem::Variable { .. } => None,
        }
    }

    pub fn rebuild_audit(&mut self) {
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
                let mut combined: Vec<(String, EnvScope)> = self
                    .system_path_raw
                    .iter()
                    .map(|p| (p.clone(), EnvScope::System))
                    .collect();
                for p in &self.user_path_raw {
                    combined.push((p.clone(), EnvScope::User));
                }
                combined
            }
        };

        self.audited_entries = analyze_path_entries(&raw_items, &self.lookup);
        self.summary = summarize_audit(&self.audited_entries);
        self.clamp_entry_selection();
    }

    pub fn visible_entries(&self) -> Vec<&PathEntry> {
        let q = self.filter_query.trim().to_ascii_lowercase();
        if q.is_empty() {
            return self.audited_entries.iter().collect();
        }
        self.audited_entries
            .iter()
            .filter(|e| {
                e.expanded.to_ascii_lowercase().contains(&q)
                    || e.raw.to_ascii_lowercase().contains(&q)
                    || e.executables
                        .iter()
                        .any(|exe| exe.to_ascii_lowercase().contains(&q))
            })
            .collect()
    }

    pub fn selected_path_entry(&self) -> Option<&PathEntry> {
        let visible = self.visible_entries();
        visible.get(self.selected_entry).copied()
    }

    pub fn clamp_entry_selection(&mut self) {
        let len = self.visible_entries().len();
        if len == 0 {
            self.selected_entry = 0;
        } else if self.selected_entry >= len {
            self.selected_entry = len - 1;
        }
    }

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

    pub fn toggle_pane(&mut self) {
        self.active_pane = match self.active_pane {
            Pane::Variables => Pane::Entries,
            Pane::Entries => Pane::Variables,
        };
    }
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
        let user = vec![
            EnvVariable {
                name: "Path".to_string(),
                value: format!(r"{temp};C:\__missing_dir_lazypath__"),
                scope: EnvScope::User,
                modified: false,
            },
            EnvVariable {
                name: "CARGO_HOME".to_string(),
                value: temp.clone(),
                scope: EnvScope::User,
                modified: false,
            },
        ];
        let sys = vec![EnvVariable {
            name: "Path".to_string(),
            value: temp,
            scope: EnvScope::System,
            modified: false,
        }];
        (user, sys)
    }

    #[test]
    fn initializes_sidebar_and_audits_selected_scope() {
        let (u, s) = sample_vars();
        let mut app = App::new(u, s, false);
        assert_eq!(app.current_sidebar(), &SidebarItem::PathUser);
        assert_eq!(app.audited_entries.len(), 2);
        assert_eq!(app.summary.missing_count, 1);

        app.active_pane = Pane::Variables;
        app.move_next();
        assert_eq!(app.current_sidebar(), &SidebarItem::PathSystem);
        assert_eq!(app.audited_entries.len(), 1);
    }
}
