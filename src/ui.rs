//! Terminal UI rendering using `ratatui`.
//!
//! Designed with a clean, low-noise aesthetic inspired by `lazygit`:
//! clear pane borders, semantic color badges, a bottom inspector bar,
//! and lightweight modal overlays.
use std::path::Path;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap,
};
use ratatui::Frame;

use crate::app::{App, LogLevel, Modal, Pane, SidebarItem};
use crate::expand::{expand_env_vars, split_path_value};
use crate::model::{EnvScope, PathStatus};

// Palette constants tuned for dark terminal themes.
const BG_DARK: Color = Color::Reset;
const BORDER_DIM: Color = Color::DarkGray;
const BORDER_ACTIVE: Color = Color::Cyan;
const TEXT_MAIN: Color = Color::White;
const TEXT_MUTED: Color = Color::DarkGray;
const ACCENT_CYAN: Color = Color::Cyan;
const ACCENT_GREEN: Color = Color::Green;
const ACCENT_YELLOW: Color = Color::Yellow;
const ACCENT_RED: Color = Color::Red;
const ACCENT_MAGENTA: Color = Color::Magenta;
const SELECT_BG: Color = Color::Rgb(32, 42, 58);

/// Renders the entire application state into a terminal frame.
pub fn render(frame: &mut Frame, app: &App) {
    let root = frame.area();
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Top summary header
            Constraint::Min(8),    // Main split view
            Constraint::Length(6), // Inspector / details panel
            Constraint::Length(2), // Status & keybinding bar
        ])
        .split(root);

    render_header(frame, vertical[0], app);
    render_body(frame, vertical[1], app);
    render_inspector(frame, vertical[2], app);
    render_footer(frame, vertical[3], app);

    match &app.modal {
        Modal::None => {}
        Modal::ExeInspector {
            dir,
            executables,
            scroll,
        } => {
            render_exe_modal(frame, dir, executables, *scroll);
        }
        Modal::Filter { buffer, .. } => {
            render_input_modal(
                frame,
                "Filter Entries (/ or w to edit, Enter to apply, Esc to revert)",
                buffer,
            );
        }
        Modal::AddEntry { buffer } => {
            let title = format!(
                "Append Directory to {} PATH (Enter to add, Esc to cancel)",
                app.target_add_scope().label()
            );
            render_input_modal(frame, &title, buffer);
        }
        Modal::ConfirmQuit => {
            render_confirm_quit_modal(frame);
        }
        Modal::Help => {
            render_help_modal(frame);
        }
    }
}

/// Renders the top summary bar with audit badges and privilege status.
fn render_header(frame: &mut Frame, area: Rect, app: &App) {
    let s = &app.summary;
    let admin_span = if app.is_admin {
        Span::styled(
            " [ADMIN] ",
            Style::default()
                .fg(Color::Black)
                .bg(ACCENT_GREEN)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            " [USER (Read-Only System)] ",
            Style::default().fg(ACCENT_YELLOW),
        )
    };

    let dirty_span = if app.has_unsaved_changes() {
        Span::styled(
            " [UNSAVED *] ",
            Style::default().fg(ACCENT_RED).add_modifier(Modifier::BOLD),
        )
    } else {
        Span::raw("")
    };

    let filter_span = if app.filter_query.is_empty() {
        Span::raw("")
    } else {
        Span::styled(
            format!(" [filter: \"{}\"] ", app.filter_query),
            Style::default().fg(ACCENT_CYAN),
        )
    };

    let line = Line::from(vec![
        Span::styled(
            " lazypath ",
            Style::default()
                .fg(ACCENT_CYAN)
                .add_modifier(Modifier::BOLD),
        ),
        admin_span,
        dirty_span,
        filter_span,
        Span::styled(" │ ", Style::default().fg(BORDER_DIM)),
        Span::styled(
            format!("dirs: {} ", s.total_entries),
            Style::default().fg(TEXT_MAIN),
        ),
        Span::styled(
            format!("missing: {} ", s.missing_count),
            Style::default().fg(if s.missing_count > 0 {
                ACCENT_RED
            } else {
                TEXT_MUTED
            }),
        ),
        Span::styled(
            format!("conflicts: {} ", s.conflict_entries),
            Style::default().fg(if s.conflict_entries > 0 {
                ACCENT_YELLOW
            } else {
                TEXT_MUTED
            }),
        ),
        Span::styled(
            format!("shadowed: {} ", s.shadowed_entries),
            Style::default().fg(if s.shadowed_entries > 0 {
                ACCENT_MAGENTA
            } else {
                TEXT_MUTED
            }),
        ),
        Span::styled(
            format!("dup: {} ", s.duplicate_count),
            Style::default().fg(if s.duplicate_count > 0 {
                ACCENT_YELLOW
            } else {
                TEXT_MUTED
            }),
        ),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_DIM))
        .style(Style::default().bg(BG_DARK));
    let paragraph = Paragraph::new(line).block(block);
    frame.render_widget(paragraph, area);
}

/// Renders the two-column body: left navigation sidebar and right main list.
fn render_body(frame: &mut Frame, area: Rect, app: &App) {
    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(28), Constraint::Min(30)])
        .split(area);
    render_sidebar(frame, horizontal[0], app);
    render_main_list(frame, horizontal[1], app);
}

/// Renders the left sidebar with PATH views and environment variables.
fn render_sidebar(frame: &mut Frame, area: Rect, app: &App) {
    let is_focused = app.active_pane == Pane::Variables;
    let border_color = if is_focused {
        BORDER_ACTIVE
    } else {
        BORDER_DIM
    };

    let items: Vec<ListItem> = app
        .sidebar_items
        .iter()
        .enumerate()
        .map(|(idx, item)| {
            let selected = idx == app.selected_sidebar;
            let prefix = if selected { "▸ " } else { "  " };
            let style = if selected {
                Style::default()
                    .fg(ACCENT_CYAN)
                    .bg(SELECT_BG)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(TEXT_MAIN)
            };
            let label = truncate_str(&item.display_label(), 23);
            ListItem::new(Line::from(Span::styled(format!("{prefix}{label}"), style)))
        })
        .collect();

    let mut state = ListState::default();
    if !app.sidebar_items.is_empty() {
        state.select(Some(
            app.selected_sidebar
                .min(app.sidebar_items.len().saturating_sub(1)),
        ));
    }

    let block = Block::default()
        .title(Span::styled(
            " Variables ",
            Style::default()
                .fg(if is_focused { ACCENT_CYAN } else { TEXT_MUTED })
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(border_color));
    let list = List::new(items).block(block);
    frame.render_stateful_widget(list, area, &mut state);
}

/// Renders the main list of PATH directories or the selected environment variable details.
fn render_main_list(frame: &mut Frame, area: Rect, app: &App) {
    let is_focused = app.active_pane == Pane::Entries;
    let border_color = if is_focused {
        BORDER_ACTIVE
    } else {
        BORDER_DIM
    };

    let sidebar = app.current_sidebar();
    let title = match sidebar {
        SidebarItem::PathCombined => " PATH Resolution Order (System → User) ".to_string(),
        SidebarItem::PathUser => {
            " User PATH (Editable: J/K move, x del, a add, d prune) ".to_string()
        }
        SidebarItem::PathSystem => {
            if app.is_admin {
                " System PATH [ADMIN] (Editable: J/K move, x del, a add, d prune) ".to_string()
            } else {
                " System PATH [Read-Only — Press E to Elevate] ".to_string()
            }
        }
        SidebarItem::Variable { scope, name } => {
            format!(" Variable: {name} ({}) ", scope.label())
        }
    };

    let block = Block::default()
        .title(Span::styled(
            title,
            Style::default()
                .fg(if is_focused { ACCENT_CYAN } else { TEXT_MUTED })
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(border_color));

    match sidebar {
        SidebarItem::PathCombined | SidebarItem::PathUser | SidebarItem::PathSystem => {
            let entries = app.visible_entries();
            let items: Vec<ListItem> = if entries.is_empty() {
                vec![ListItem::new(Line::from(Span::styled(
                    "  (no matching PATH entries)",
                    Style::default().fg(TEXT_MUTED),
                )))]
            } else {
                entries
                    .iter()
                    .enumerate()
                    .map(|(vis_idx, entry)| {
                        let is_selected = vis_idx == app.selected_entry;
                        format_path_entry_row(entry, is_selected)
                    })
                    .collect()
            };

            let mut state = ListState::default();
            if !items.is_empty() {
                state.select(Some(app.selected_entry.min(items.len().saturating_sub(1))));
            }
            let list = List::new(items).block(block);
            frame.render_stateful_widget(list, area, &mut state);
        }
        SidebarItem::Variable { .. } => {
            let lines = if let Some(var) = app.selected_variable() {
                render_variable_inspector(var, app)
            } else {
                vec![Line::from(Span::styled(
                    "  (variable not found)",
                    Style::default().fg(TEXT_MUTED),
                ))]
            };
            let paragraph = Paragraph::new(lines)
                .block(block)
                .wrap(Wrap { trim: false });
            frame.render_widget(paragraph, area);
        }
    }
}

/// Formats a single PATH entry row with index, scope tag, status badge, and directory string.
fn format_path_entry_row<'a>(entry: &crate::model::PathEntry, is_selected: bool) -> ListItem<'a> {
    let bg = if is_selected { SELECT_BG } else { BG_DARK };
    let status = entry.status();
    let (badge_color, path_color) = match status {
        PathStatus::Ok => (ACCENT_GREEN, TEXT_MAIN),
        PathStatus::Conflict => (ACCENT_YELLOW, TEXT_MAIN),
        PathStatus::Shadowed => (ACCENT_MAGENTA, TEXT_MUTED),
        PathStatus::Duplicate => (ACCENT_YELLOW, TEXT_MUTED),
        PathStatus::Missing => (ACCENT_RED, ACCENT_RED),
    };
    let scope_tag = match entry.scope {
        EnvScope::System => Span::styled("SYS ", Style::default().fg(ACCENT_CYAN).bg(bg)),
        EnvScope::User => Span::styled("USR ", Style::default().fg(ACCENT_GREEN).bg(bg)),
    };
    let badge = status.badge(entry.executables.len());
    let line = Line::from(vec![
        Span::styled(
            if is_selected { "▸" } else { " " },
            Style::default().fg(ACCENT_CYAN).bg(bg),
        ),
        Span::styled(
            format!("{:>2} ", entry.index + 1),
            Style::default().fg(TEXT_MUTED).bg(bg),
        ),
        scope_tag,
        Span::styled(
            format!("{badge:<13} "),
            Style::default()
                .fg(badge_color)
                .bg(bg)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(entry.raw.clone(), Style::default().fg(path_color).bg(bg)),
    ]);
    ListItem::new(line)
}

/// Renders the bottom inspector pane showing expanded paths and conflict details.
fn render_inspector(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(Span::styled(
            " Inspector ",
            Style::default().fg(TEXT_MUTED).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_DIM));

    let lines = match app.current_sidebar() {
        SidebarItem::PathCombined | SidebarItem::PathUser | SidebarItem::PathSystem => {
            if let Some(entry) = app.selected_path_entry() {
                render_path_inspector(entry)
            } else {
                vec![Line::from(Span::styled(
                    " No PATH entry selected.",
                    Style::default().fg(TEXT_MUTED),
                ))]
            }
        }
        SidebarItem::Variable { .. } => {
            if let Some(var) = app.selected_variable() {
                render_variable_inspector(var, app)
            } else {
                vec![Line::from(Span::styled(
                    " No variable selected.",
                    Style::default().fg(TEXT_MUTED),
                ))]
            }
        }
    };

    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, area);
}

fn render_path_inspector(entry: &crate::model::PathEntry) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let exe_count = entry.executables.len();

    // Line 1: Raw vs Expanded
    if entry.raw != entry.expanded {
        lines.push(Line::from(vec![
            Span::styled(" Raw:      ", Style::default().fg(TEXT_MUTED)),
            Span::styled(entry.raw.clone(), Style::default().fg(TEXT_MAIN)),
            Span::styled("  →  Expanded: ", Style::default().fg(TEXT_MUTED)),
            Span::styled(entry.expanded.clone(), Style::default().fg(ACCENT_CYAN)),
        ]));
    } else {
        lines.push(Line::from(vec![
            Span::styled(" Directory: ", Style::default().fg(TEXT_MUTED)),
            Span::styled(entry.expanded.clone(), Style::default().fg(ACCENT_CYAN)),
            Span::styled(
                format!(
                    "  ({} scope, {exe_count} executables — press Enter to inspect)",
                    entry.scope.label()
                ),
                Style::default().fg(TEXT_MUTED),
            ),
        ]));
    }

    // Line 2 & 3: Diagnostic warnings
    if !entry.exists {
        lines.push(Line::from(Span::styled(
            " ⚠ Directory does not exist on disk. Safe to delete (x) or auto-prune (d).",
            Style::default().fg(ACCENT_RED),
        )));
    } else if entry.is_duplicate {
        lines.push(Line::from(Span::styled(
            " ⚠ Duplicate of an earlier PATH entry. Safe to delete (x) or auto-prune (d).",
            Style::default().fg(ACCENT_YELLOW),
        )));
    } else {
        if !entry.shadows.is_empty() {
            let preview: Vec<String> = entry
                .shadows
                .iter()
                .take(4)
                .map(|c| {
                    format!(
                        "{} (shadows #{}: {})",
                        c.binary,
                        c.other_index + 1,
                        c.other_dir
                    )
                })
                .collect();
            let extra = if entry.shadows.len() > 4 {
                format!(" +{} more", entry.shadows.len() - 4)
            } else {
                String::new()
            };
            lines.push(Line::from(Span::styled(
                format!(" ⚡ Wins conflicts: {}{}", preview.join(", "), extra),
                Style::default().fg(ACCENT_YELLOW),
            )));
        }
        if !entry.shadowed_by.is_empty() {
            let preview: Vec<String> = entry
                .shadowed_by
                .iter()
                .take(4)
                .map(|c| {
                    format!(
                        "{} (won by #{}: {})",
                        c.binary,
                        c.other_index + 1,
                        c.other_dir
                    )
                })
                .collect();
            let extra = if entry.shadowed_by.len() > 4 {
                format!(" +{} more", entry.shadowed_by.len() - 4)
            } else {
                String::new()
            };
            lines.push(Line::from(Span::styled(
                format!(" ▼ Shadowed binaries: {}{}", preview.join(", "), extra),
                Style::default().fg(ACCENT_MAGENTA),
            )));
        }
        if entry.shadows.is_empty() && entry.shadowed_by.is_empty() {
            lines.push(Line::from(Span::styled(
                " ✓ Clean directory — no binary name collisions detected.",
                Style::default().fg(ACCENT_GREEN),
            )));
        }
    }
    lines
}

/// Evaluates whether a variable value looks like one or more filesystem paths and
/// checks each semicolon-delimited segment on disk after `%VAR%` expansion.
fn inspect_variable_paths(raw_value: &str, app: &App) -> (String, Option<(usize, Vec<String>)>) {
    let expanded = expand_env_vars(raw_value, &app.lookup);
    let looks_like_path = expanded.contains(":\\")
        || expanded.starts_with("\\\\")
        || raw_value.contains(":\\")
        || raw_value.starts_with("\\\\");
    if !looks_like_path {
        return (expanded, None);
    }
    let segments = split_path_value(&expanded);
    if segments.is_empty() {
        return (expanded, None);
    }
    let missing: Vec<String> = segments
        .iter()
        .filter(|seg| !Path::new(seg.as_str()).exists())
        .cloned()
        .collect();
    (expanded, Some((segments.len(), missing)))
}

fn render_variable_inspector(var: &crate::model::EnvVariable, app: &App) -> Vec<Line<'static>> {
    let (expanded, path_check) = inspect_variable_paths(&var.value, app);
    let mut header_spans = vec![
        Span::styled(
            format!(" {} ", var.name),
            Style::default()
                .fg(ACCENT_CYAN)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("({} — {})", var.scope.label(), var.kind.reg_type_name()),
            Style::default().fg(TEXT_MUTED),
        ),
    ];
    if var.modified {
        header_spans.push(Span::styled(
            " [MODIFIED]",
            Style::default()
                .fg(ACCENT_YELLOW)
                .add_modifier(Modifier::BOLD),
        ));
    }
    let mut lines = vec![
        Line::from(header_spans),
        Line::from(vec![
            Span::styled(" Value: ", Style::default().fg(TEXT_MUTED)),
            Span::styled(var.value.clone(), Style::default().fg(TEXT_MAIN)),
        ]),
    ];
    if expanded != var.value {
        lines.push(Line::from(vec![
            Span::styled(" Expanded: ", Style::default().fg(TEXT_MUTED)),
            Span::styled(expanded, Style::default().fg(ACCENT_CYAN)),
        ]));
    }
    if let Some((total_segments, missing_segments)) = path_check {
        if missing_segments.is_empty() {
            let msg = if total_segments == 1 {
                " ✓ Target path exists on disk.".to_string()
            } else {
                format!(" ✓ All {total_segments} target paths exist on disk.")
            };
            lines.push(Line::from(Span::styled(
                msg,
                Style::default().fg(ACCENT_GREEN),
            )));
        } else if total_segments == 1 {
            lines.push(Line::from(Span::styled(
                " ⚠ Target path does not exist on disk.",
                Style::default().fg(ACCENT_RED),
            )));
        } else {
            lines.push(Line::from(Span::styled(
                format!(
                    " ⚠ {}/{} paths do not exist on disk (first missing: {}).",
                    missing_segments.len(),
                    total_segments,
                    missing_segments[0]
                ),
                Style::default().fg(ACCENT_RED),
            )));
        }
    }
    lines
}

/// Renders the bottom status and keybinding hints bar.
fn render_footer(frame: &mut Frame, area: Rect, app: &App) {
    let status_color = match app.status_log.level {
        LogLevel::Ok => ACCENT_GREEN,
        LogLevel::Info => ACCENT_CYAN,
        LogLevel::Warn => ACCENT_YELLOW,
        LogLevel::Err => ACCENT_RED,
    };

    let keys_line = Line::from(vec![
        Span::styled(" j/k ", Style::default().fg(ACCENT_CYAN)),
        Span::styled("nav  ", Style::default().fg(TEXT_MUTED)),
        Span::styled("J/K ", Style::default().fg(ACCENT_CYAN)),
        Span::styled("move  ", Style::default().fg(TEXT_MUTED)),
        Span::styled("Enter ", Style::default().fg(ACCENT_CYAN)),
        Span::styled("inspect  ", Style::default().fg(TEXT_MUTED)),
        Span::styled("x ", Style::default().fg(ACCENT_CYAN)),
        Span::styled("del  ", Style::default().fg(TEXT_MUTED)),
        Span::styled("a ", Style::default().fg(ACCENT_CYAN)),
        Span::styled("add  ", Style::default().fg(TEXT_MUTED)),
        Span::styled("d ", Style::default().fg(ACCENT_CYAN)),
        Span::styled("prune  ", Style::default().fg(TEXT_MUTED)),
        Span::styled("/ ", Style::default().fg(ACCENT_CYAN)),
        Span::styled("filter  ", Style::default().fg(TEXT_MUTED)),
        Span::styled("r ", Style::default().fg(ACCENT_CYAN)),
        Span::styled("rescan  ", Style::default().fg(TEXT_MUTED)),
        Span::styled("s ", Style::default().fg(ACCENT_CYAN)),
        Span::styled("save  ", Style::default().fg(TEXT_MUTED)),
        Span::styled("b ", Style::default().fg(ACCENT_CYAN)),
        Span::styled("backup  ", Style::default().fg(TEXT_MUTED)),
        Span::styled("E ", Style::default().fg(ACCENT_CYAN)),
        Span::styled("admin  ", Style::default().fg(TEXT_MUTED)),
        Span::styled("? ", Style::default().fg(ACCENT_CYAN)),
        Span::styled("help  ", Style::default().fg(TEXT_MUTED)),
        Span::styled("q ", Style::default().fg(ACCENT_CYAN)),
        Span::styled("quit", Style::default().fg(TEXT_MUTED)),
    ]);

    let status_line = Line::from(vec![
        Span::styled(
            format!(" [{}] ", app.status_log.level.tag()),
            Style::default()
                .fg(status_color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            app.status_log.message.clone(),
            Style::default().fg(status_color),
        ),
    ]);
    let paragraph = Paragraph::new(vec![keys_line, status_line]);
    frame.render_widget(paragraph, area);
}

/// Renders a centered modal listing all executables in a directory and whether they are shadowed.
fn render_exe_modal(
    frame: &mut Frame,
    dir: &str,
    executables: &[(String, Option<String>)],
    scroll: usize,
) {
    let area = centered_rect(72, 70, frame.area());
    frame.render_widget(Clear, area);
    let title = format!(" Executables in {} (Esc to close) ", truncate_str(dir, 48));
    let block = Block::default()
        .title(Span::styled(
            title,
            Style::default()
                .fg(ACCENT_CYAN)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_ACTIVE))
        .style(Style::default().bg(BG_DARK));

    let items: Vec<ListItem> = if executables.is_empty() {
        vec![ListItem::new(Line::from(Span::styled(
            "  No PATHEXT executables found in this directory.",
            Style::default().fg(TEXT_MUTED),
        )))]
    } else {
        executables
            .iter()
            .enumerate()
            .map(|(idx, (exe, note))| {
                let selected = idx == scroll.min(executables.len().saturating_sub(1));
                let bg = if selected { SELECT_BG } else { BG_DARK };
                let mut spans = vec![
                    Span::styled(
                        if selected { " ▸ " } else { "   " },
                        Style::default().fg(ACCENT_CYAN).bg(bg),
                    ),
                    Span::styled(format!("{exe:<26}"), Style::default().fg(TEXT_MAIN).bg(bg)),
                ];
                if let Some(n) = note {
                    let color = if n.starts_with("shadowed") {
                        ACCENT_MAGENTA
                    } else {
                        ACCENT_YELLOW
                    };
                    spans.push(Span::styled(
                        format!(" ({n})"),
                        Style::default().fg(color).bg(bg),
                    ));
                }
                ListItem::new(Line::from(spans))
            })
            .collect()
    };

    let mut state = ListState::default();
    if !executables.is_empty() {
        state.select(Some(scroll.min(executables.len().saturating_sub(1))));
    }
    let list = List::new(items).block(block);
    frame.render_stateful_widget(list, area, &mut state);
}

/// Renders a single-line text input modal for filtering or adding a PATH directory.
fn render_input_modal(frame: &mut Frame, title: &str, buffer: &str) {
    let area = centered_rect(65, 20, frame.area());
    let popup = Rect {
        x: area.x,
        y: area.y,
        width: area.width,
        height: 3.min(area.height),
    };
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .title(Span::styled(
            format!(" {title} "),
            Style::default()
                .fg(ACCENT_CYAN)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_ACTIVE));

    // Reserve 2 columns for borders, 3 for the `" > "` prefix, and 1 for the cursor.
    let available_chars = popup.width.saturating_sub(6) as usize;
    let visible_buffer = tail_slice_for_width(buffer, available_chars);
    let line = Line::from(vec![
        Span::styled(" > ", Style::default().fg(ACCENT_CYAN)),
        Span::styled(visible_buffer.to_string(), Style::default().fg(TEXT_MAIN)),
        Span::styled("█", Style::default().fg(ACCENT_CYAN)),
    ]);
    let paragraph = Paragraph::new(line).block(block);
    frame.render_widget(paragraph, popup);
}

/// Renders a confirmation modal when the user attempts to quit with unsaved PATH edits.
fn render_confirm_quit_modal(frame: &mut Frame) {
    let area = centered_rect(64, 30, frame.area());
    let popup = Rect {
        x: area.x,
        y: area.y,
        width: area.width,
        height: 7.min(area.height),
    };
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .title(Span::styled(
            " Unsaved PATH Changes ",
            Style::default()
                .fg(ACCENT_YELLOW)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(ACCENT_YELLOW))
        .style(Style::default().bg(BG_DARK));

    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  You have unsaved PATH modifications in memory.",
            Style::default().fg(TEXT_MAIN),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "  [y / Enter] ",
                Style::default().fg(ACCENT_RED).add_modifier(Modifier::BOLD),
            ),
            Span::styled("Discard & quit   ", Style::default().fg(TEXT_MAIN)),
            Span::styled(
                "[s] ",
                Style::default()
                    .fg(ACCENT_GREEN)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Save & quit   ", Style::default().fg(TEXT_MAIN)),
            Span::styled(
                "[n / Esc] ",
                Style::default()
                    .fg(ACCENT_CYAN)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Cancel", Style::default().fg(TEXT_MAIN)),
        ]),
    ];
    let paragraph = Paragraph::new(lines).block(block);
    frame.render_widget(paragraph, popup);
}

/// Renders the help modal with full keyboard shortcuts.
fn render_help_modal(frame: &mut Frame) {
    let area = centered_rect(68, 74, frame.area());
    frame.render_widget(Clear, area);
    let block = Block::default()
        .title(Span::styled(
            " lazypath Keybindings (Esc / ? to close) ",
            Style::default()
                .fg(ACCENT_CYAN)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_ACTIVE));

    let lines = vec![
        Line::from(Span::styled(
            " Navigation",
            Style::default()
                .fg(ACCENT_CYAN)
                .add_modifier(Modifier::BOLD),
        )),
        help_row(
            "Tab / h / l / ← / →",
            "Switch focus between Variables and Entries",
        ),
        help_row("j / k / ↑ / ↓", "Move selection down / up"),
        help_row(
            "Home / End / PgUp / PgDn",
            "Jump to top / bottom or scroll by page",
        ),
        help_row(
            "Enter",
            "Inspect executables inside selected PATH directory",
        ),
        help_row("/ or w", "Filter entries by substring (Esc reverts)"),
        help_row("r", "Rescan filesystem PATH directories"),
        Line::from(""),
        Line::from(Span::styled(
            " Auditing & Editing (User PATH & Admin System PATH)",
            Style::default()
                .fg(ACCENT_CYAN)
                .add_modifier(Modifier::BOLD),
        )),
        help_row(
            "J / K / Alt+↑/↓",
            "Move selected PATH directory down / up in priority",
        ),
        help_row("x / Delete", "Remove selected directory from PATH"),
        help_row("a", "Append a new directory to PATH"),
        help_row("d", "Auto-prune all [MISSING] & [DUP] entries"),
        Line::from(""),
        Line::from(Span::styled(
            " Persistence & Safety",
            Style::default()
                .fg(ACCENT_CYAN)
                .add_modifier(Modifier::BOLD),
        )),
        help_row("s", "Save changes to Windows Registry + WM_SETTINGCHANGE"),
        help_row(
            "b",
            "Export JSON snapshot backup to %LOCALAPPDATA%\\lazypath",
        ),
        help_row("E (Shift+e)", "Relaunch lazypath as Administrator (UAC)"),
        help_row(
            "q / Esc",
            "Clear filter or quit lazypath (prompts if unsaved)",
        ),
    ];
    let paragraph = Paragraph::new(lines).block(block);
    frame.render_widget(paragraph, area);
}

fn help_row(key: &'static str, desc: &'static str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("  {key:<24}"), Style::default().fg(ACCENT_GREEN)),
        Span::styled(desc, Style::default().fg(TEXT_MAIN)),
    ])
}

/// Computes a centered rectangle of `percent_x` by `percent_y` inside `r`.
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn truncate_str(s: &str, max_chars: usize) -> String {
    let count = s.chars().count();
    if count <= max_chars {
        s.to_string()
    } else {
        let kept: String = s.chars().take(max_chars.saturating_sub(1)).collect();
        format!("{kept}…")
    }
}

/// Returns the trailing substring of `s` containing at most `max_chars` Unicode scalar values.
fn tail_slice_for_width(s: &str, max_chars: usize) -> &str {
    if max_chars == 0 {
        return "";
    }
    let total_chars = s.chars().count();
    if total_chars <= max_chars {
        return s;
    }
    let skip_chars = total_chars - max_chars;
    match s.char_indices().nth(skip_chars) {
        Some((byte_idx, _)) => &s[byte_idx..],
        None => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{EnvScope, EnvVariable};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn sample_app() -> App {
        let user_vars = vec![
            EnvVariable::new("Path", r"C:\UserBin;%USERPROFILE%\Tools", EnvScope::User),
            EnvVariable::new("USERPROFILE", r"C:\Users\Dev", EnvScope::User),
            EnvVariable::new(
                "PSModulePath",
                r"C:\MissingOne;C:\MissingTwo",
                EnvScope::User,
            ),
        ];
        let system_vars = vec![EnvVariable::new(
            "Path",
            r"C:\Windows\System32",
            EnvScope::System,
        )];
        App::new(user_vars, system_vars, false)
    }

    #[test]
    fn tail_slice_handles_ascii_and_unicode() {
        assert_eq!(tail_slice_for_width("C:\\Tools\\Bin", 20), "C:\\Tools\\Bin");
        assert_eq!(tail_slice_for_width("C:\\Tools\\Bin", 3), "Bin");
        assert_eq!(
            tail_slice_for_width("C:\\Папка\\Инструменты", 11),
            "Инструменты"
        );
        assert_eq!(tail_slice_for_width("anything", 0), "");
    }

    #[test]
    fn inspect_variable_paths_expands_placeholders_and_splits_semicolons() {
        let app = sample_app();
        let (expanded, check) = inspect_variable_paths(r"%USERPROFILE%\NonExistentDir", &app);
        assert_eq!(expanded, r"C:\Users\Dev\NonExistentDir");
        let (total, missing) = check.expect("should be recognized as a filesystem path");
        assert_eq!(total, 1);
        assert_eq!(missing.len(), 1);

        let (_, multi_check) = inspect_variable_paths(r"C:\MissingOne;C:\MissingTwo", &app);
        let (multi_total, multi_missing) =
            multi_check.expect("multi-directory variable should be checked");
        assert_eq!(multi_total, 2);
        assert_eq!(multi_missing.len(), 2);

        let (_, non_path_check) = inspect_variable_paths("production", &app);
        assert!(non_path_check.is_none());
    }

    #[test]
    fn render_handles_all_modals_without_panicking() {
        let backend = TestBackend::new(110, 32);
        let mut terminal = Terminal::new(backend).expect("failed to create test terminal");
        let mut app = sample_app();

        // Default view
        terminal.draw(|f| render(f, &app)).unwrap();

        // Filter modal
        app.modal = Modal::Filter {
            buffer: "sys".to_string(),
            original_query: String::new(),
        };
        terminal.draw(|f| render(f, &app)).unwrap();

        // AddEntry modal
        app.modal = Modal::AddEntry {
            buffer:
                "C:\\Very\\Long\\Directory\\Path\\That\\Exceeds\\Normal\\Width\\Limits\\For\\Input"
                    .to_string(),
        };
        terminal.draw(|f| render(f, &app)).unwrap();

        // ExeInspector modal with out-of-bounds scroll
        app.modal = Modal::ExeInspector {
            dir: "C:\\Windows\\System32".to_string(),
            executables: vec![("cmd.exe".to_string(), None)],
            scroll: 99,
        };
        terminal.draw(|f| render(f, &app)).unwrap();

        // ConfirmQuit modal
        app.modal = Modal::ConfirmQuit;
        terminal.draw(|f| render(f, &app)).unwrap();

        // Help modal
        app.modal = Modal::Help;
        terminal.draw(|f| render(f, &app)).unwrap();
    }
}
