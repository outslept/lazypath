//! Terminal UI rendering using `ratatui`.

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Cell, Clear, List, ListItem, ListState, Paragraph, Row, Table,
    TableState,
};
use ratatui::Frame;

use crate::app::{App, LogLevel, Modal, Pane, SidebarItem};
use crate::model::PathStatus;

/// Slate background color used for highlighted list and table rows.
const HIGHLIGHT_BG_COLOR: Color = Color::Rgb(30, 41, 59);

/// Renders the complete TUI frame (header, split panes, footer, and active modal).
pub fn render(frame: &mut Frame, app: &App) {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(10),
            Constraint::Length(2),
        ])
        .split(frame.area());
    render_header(frame, app, root[0]);
    render_body(frame, app, root[1]);
    render_footer(frame, app, root[2]);
    match &app.modal {
        Modal::None => {}
        Modal::ExeInspector {
            dir,
            executables,
            scroll,
        } => render_exe_modal(frame, dir, executables, *scroll),
        Modal::Filter { buffer } => {
            render_input_modal(frame, " Filter PATH by Directory or .exe ", buffer);
        }
        Modal::AddEntry { buffer } => {
            render_input_modal(frame, " Append Directory to Active PATH ", buffer);
        }
        Modal::Help => render_help_modal(frame),
    }
}

fn render_header(frame: &mut Frame, app: &App, area: Rect) {
    let s = &app.summary;
    let priv_label = if app.is_admin { "ADMIN" } else { "USER" };
    let priv_color = if app.is_admin {
        Color::LightGreen
    } else {
        Color::Yellow
    };
    let mut spans = vec![
        Span::styled(
            " lazypath ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled("mode ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            priv_label,
            Style::default().fg(priv_color).add_modifier(Modifier::BOLD),
        ),
        Span::raw("   "),
        Span::styled("dirs ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            s.total_entries.to_string(),
            Style::default().fg(Color::White),
        ),
        Span::raw("   "),
        Span::styled("missing ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            s.missing_count.to_string(),
            Style::default().fg(if s.missing_count > 0 {
                Color::LightRed
            } else {
                Color::Green
            }),
        ),
        Span::raw("   "),
        Span::styled("conflicts ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            s.conflict_entries.to_string(),
            Style::default().fg(if s.conflict_entries > 0 {
                Color::Yellow
            } else {
                Color::Green
            }),
        ),
        Span::raw("   "),
        Span::styled("shadowed ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            s.shadowed_entries.to_string(),
            Style::default().fg(if s.shadowed_entries > 0 {
                Color::Yellow
            } else {
                Color::Gray
            }),
        ),
    ];
    if app.has_unsaved_changes() {
        spans.push(Span::raw("   "));
        spans.push(Span::styled(
            "[MODIFIED - press 's' to save]",
            Style::default()
                .fg(Color::LightYellow)
                .add_modifier(Modifier::BOLD),
        ));
    }
    if !app.filter_query.is_empty() {
        spans.push(Span::raw("   "));
        spans.push(Span::styled(
            "filter ",
            Style::default().fg(Color::DarkGray),
        ));
        spans.push(Span::styled(
            format!("\"{}\"", app.filter_query),
            Style::default()
                .fg(Color::LightGreen)
                .add_modifier(Modifier::BOLD),
        ));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn render_body(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(28), Constraint::Percentage(72)])
        .split(area);
    render_variables_pane(frame, app, chunks[0]);
    render_right_pane(frame, app, chunks[1]);
}

fn render_variables_pane(frame: &mut Frame, app: &App, area: Rect) {
    let focused = app.active_pane == Pane::Variables;
    let border_color = if focused {
        Color::Cyan
    } else {
        Color::DarkGray
    };
    let items: Vec<ListItem> = app
        .sidebar_items
        .iter()
        .map(|item| {
            let label = item.display_label();
            let style = match item {
                SidebarItem::PathUser | SidebarItem::PathSystem | SidebarItem::PathCombined => {
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                }
                SidebarItem::Variable { .. } => Style::default().fg(Color::Gray),
            };
            ListItem::new(Line::from(Span::styled(label, style)))
        })
        .collect();
    let block = Block::default()
        .title(format!(" Variables ({}) ", app.sidebar_items.len()))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(border_color));
    let list = List::new(items)
        .block(block)
        .highlight_style(
            Style::default()
                .bg(HIGHLIGHT_BG_COLOR)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(" > ");
    let mut state = ListState::default();
    state.select(Some(app.selected_sidebar));
    frame.render_stateful_widget(list, area, &mut state);
}

fn render_right_pane(frame: &mut Frame, app: &App, area: Rect) {
    if let Some(var) = app.selected_variable() {
        render_variable_inspector(frame, app, var.name.as_str(), var.value.as_str(), area);
        return;
    }
    let split = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(6), Constraint::Length(3)])
        .split(area);
    render_path_table(frame, app, split[0]);
    render_warning_bar(frame, app, split[1]);
}

fn render_variable_inspector(frame: &mut Frame, app: &App, name: &str, value: &str, area: Rect) {
    let focused = app.active_pane == Pane::Entries;
    let border_color = if focused {
        Color::Cyan
    } else {
        Color::DarkGray
    };
    let block = Block::default()
        .title(format!(" Variable Inspector: {name} "))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(border_color));
    let exists_hint = if value.contains('\\') || value.contains('/') {
        if std::path::Path::new(value).exists() {
            "path exists on disk"
        } else {
            "warning: referenced path does not exist on disk"
        }
    } else {
        "scalar value"
    };
    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  Name:   ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                name,
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Value:  ", Style::default().fg(Color::DarkGray)),
            Span::styled(value, Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::styled("  Check:  ", Style::default().fg(Color::DarkGray)),
            Span::styled(exists_hint, Style::default().fg(Color::Yellow)),
        ]),
    ];
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_path_table(frame: &mut Frame, app: &App, area: Rect) {
    let focused = app.active_pane == Pane::Entries;
    let border_color = if focused {
        Color::Cyan
    } else {
        Color::DarkGray
    };
    let visible = app.visible_entries();
    let header = Row::new(vec![
        Cell::from("#"),
        Cell::from("DIRECTORY (PRIORITY TOP TO BOTTOM)"),
        Cell::from("SCOPE"),
        Cell::from("STATUS"),
    ])
    .style(
        Style::default()
            .fg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    );
    let rows: Vec<Row> = visible
        .iter()
        .map(|entry| {
            let status = entry.status();
            let status_style = match status {
                PathStatus::Ok => Style::default().fg(Color::Green),
                PathStatus::Conflict => Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
                PathStatus::Shadowed => Style::default().fg(Color::Yellow),
                PathStatus::Duplicate => Style::default().fg(Color::LightMagenta),
                PathStatus::Missing => Style::default()
                    .fg(Color::LightRed)
                    .add_modifier(Modifier::BOLD),
            };
            let badge = format!("[{}]", status.badge(entry.executables.len()));
            Row::new(vec![
                Cell::from(format!("{}.", entry.index + 1))
                    .style(Style::default().fg(Color::DarkGray)),
                Cell::from(entry.expanded.as_str()).style(Style::default().fg(Color::White)),
                Cell::from(entry.scope.label()).style(Style::default().fg(Color::Gray)),
                Cell::from(badge).style(status_style),
            ])
        })
        .collect();
    let widths = [
        Constraint::Length(4),
        Constraint::Min(32),
        Constraint::Length(8),
        Constraint::Length(16),
    ];
    let title = format!(
        " {} Contents ({}) ",
        app.current_sidebar().display_label(),
        visible.len()
    );
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(border_color));
    let table = Table::new(rows, widths)
        .header(header)
        .block(block)
        .row_highlight_style(
            Style::default()
                .bg(HIGHLIGHT_BG_COLOR)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(" > ");
    let mut state = TableState::default();
    if !visible.is_empty() {
        state.select(Some(app.selected_entry));
    }
    frame.render_stateful_widget(table, area, &mut state);
}

fn render_warning_bar(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::DarkGray));
    let line = if let Some(entry) = app.selected_path_entry() {
        if let Some(warning) = entry.headline_warning() {
            Line::from(vec![
                Span::styled(
                    " WARN ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" "),
                Span::styled(warning, Style::default().fg(Color::Yellow)),
            ])
        } else {
            Line::from(vec![
                Span::styled(
                    " OK ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" "),
                Span::styled(
                    format!(
                        "No conflicts detected in '{}' ({} executables)",
                        entry.expanded,
                        entry.executables.len()
                    ),
                    Style::default().fg(Color::Gray),
                ),
            ])
        }
    } else {
        Line::from(Span::styled(
            " No PATH entry selected",
            Style::default().fg(Color::DarkGray),
        ))
    };
    frame.render_widget(Paragraph::new(line).block(block), area);
}

fn render_footer(frame: &mut Frame, app: &App, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(1)])
        .split(area);
    let (tag_fg, tag_bg) = match app.status_log.level {
        LogLevel::Ok => (Color::Black, Color::Green),
        LogLevel::Info => (Color::Black, Color::Cyan),
        LogLevel::Warn => (Color::Black, Color::Yellow),
        LogLevel::Err => (Color::White, Color::Red),
    };
    let status_line = Line::from(vec![
        Span::styled(
            format!(" {} ", app.status_log.level.tag()),
            Style::default()
                .fg(tag_fg)
                .bg(tag_bg)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::styled(&app.status_log.message, Style::default().fg(Color::Gray)),
    ]);
    let keys_line = Line::from(vec![
        key_span("j/k"),
        desc_span("nav  "),
        key_span("J/K"),
        desc_span("priority  "),
        key_span("d"),
        desc_span("clean dead  "),
        key_span("Enter"),
        desc_span(".exe list  "),
        key_span("a/x"),
        desc_span("add/del  "),
        key_span("/"),
        desc_span("filter  "),
        key_span("b"),
        desc_span("backup  "),
        key_span("s"),
        desc_span("save  "),
        key_span("?"),
        desc_span("help  "),
        key_span("q"),
        desc_span("quit"),
    ]);
    frame.render_widget(Paragraph::new(status_line), rows[0]);
    frame.render_widget(Paragraph::new(keys_line), rows[1]);
}

fn key_span(k: &'static str) -> Span<'static> {
    Span::styled(
        k,
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )
}

fn desc_span(d: &'static str) -> Span<'static> {
    Span::styled(format!(" {d}"), Style::default().fg(Color::DarkGray))
}

fn render_exe_modal(
    frame: &mut Frame,
    dir: &str,
    executables: &[(String, Option<String>)],
    scroll: usize,
) {
    let area = centered_rect(68, 18, frame.area());
    frame.render_widget(Clear, area);
    let block = Block::default()
        .title(format!(" Executables in {} ({}) ", dir, executables.len()))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan));
    let items: Vec<ListItem> = executables
        .iter()
        .map(|(exe, note)| {
            if let Some(conflict_note) = note {
                ListItem::new(Line::from(vec![
                    Span::styled(
                        format!("  {exe:<22} "),
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!("[{conflict_note}]"),
                        Style::default().fg(Color::LightRed),
                    ),
                ]))
            } else {
                ListItem::new(Line::from(Span::styled(
                    format!("  {exe}"),
                    Style::default().fg(Color::White),
                )))
            }
        })
        .collect();
    let list = List::new(items)
        .block(block)
        .highlight_style(
            Style::default()
                .bg(HIGHLIGHT_BG_COLOR)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(" > ");
    let mut state = ListState::default();
    state.select(Some(scroll));
    frame.render_stateful_widget(list, area, &mut state);
}

fn render_input_modal(frame: &mut Frame, title: &'static str, buffer: &str) {
    let area = centered_rect(60, 5, frame.area());
    frame.render_widget(Clear, area);
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan));
    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  > ", Style::default().fg(Color::Cyan)),
            Span::styled(
                buffer,
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("_", Style::default().fg(Color::Cyan)),
        ]),
    ];
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_help_modal(frame: &mut Frame) {
    let area = centered_rect(66, 17, frame.area());
    frame.render_widget(Clear, area);
    let block = Block::default()
        .title(" Keybindings ")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan));
    let lines = vec![
        Line::from(""),
        help_row("j / k / Up / Down", "Navigate items in active pane"),
        help_row("Tab / h / l", "Switch focus between Variables and PATH"),
        help_row(
            "J / K (Alt+Up/Down)",
            "Move selected PATH directory priority",
        ),
        help_row("d", "Remove all MISSING and DUP entries"),
        help_row("Enter", "Inspect .exe/.cmd/.bat files in directory"),
        help_row("a / x", "Add new directory or remove selected entry"),
        help_row("/ or w", "Filter PATH entries by folder or .exe name"),
        help_row("b", "Export JSON environment snapshot backup"),
        help_row("s", "Save modified PATH to Windows Registry"),
        help_row("E", "Relaunch with UAC Administrator elevation"),
        help_row("q / Ctrl+C", "Exit lazypath"),
        Line::from(""),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .alignment(Alignment::Left),
        area,
    );
}

fn help_row(keys: &'static str, desc: &'static str) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("  {keys:<22}"),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(desc, Style::default().fg(Color::Gray)),
    ])
}

fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;
    Rect::new(x, y, width.min(area.width), height.min(area.height))
}
