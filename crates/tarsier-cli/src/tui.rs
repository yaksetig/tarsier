use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame, Terminal,
};
use std::io::stdout;
use tarsier_ir::counter_system::Trace;
use tarsier_ir::threshold_automaton::ThresholdAutomaton;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Panel {
    Config,
    Deliveries,
    Guards,
}

pub struct ExploreState {
    pub current_step: usize,
    pub total_steps: usize,
    pub trace: Trace,
    pub ta: Option<ThresholdAutomaton>,
    pub focus: Panel,
    pub delivery_scroll: usize,
    pub show_diff: bool,
    pub loop_start: Option<usize>,
}

pub fn run_explorer(
    trace: Trace,
    ta: Option<ThresholdAutomaton>,
    loop_start: Option<usize>,
) -> miette::Result<()> {
    let total_steps = trace.steps.len();
    let mut state = ExploreState {
        current_step: 0,
        total_steps,
        trace,
        ta,
        focus: Panel::Config,
        delivery_scroll: 0,
        show_diff: false,
        loop_start,
    };

    enable_raw_mode().map_err(|e| miette::miette!("Failed to enable raw mode: {e}"))?;
    stdout()
        .execute(EnterAlternateScreen)
        .map_err(|e| miette::miette!("Failed to enter alternate screen: {e}"))?;

    let backend = ratatui::backend::CrosstermBackend::new(stdout());
    let mut terminal =
        Terminal::new(backend).map_err(|e| miette::miette!("Failed to create terminal: {e}"))?;

    let result = run_event_loop(&mut terminal, &mut state);

    disable_raw_mode().ok();
    stdout().execute(LeaveAlternateScreen).ok();

    result
}

fn run_event_loop(
    terminal: &mut Terminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>,
    state: &mut ExploreState,
) -> miette::Result<()> {
    loop {
        terminal
            .draw(|f| draw_ui(f, state))
            .map_err(|e| miette::miette!("Draw error: {e}"))?;

        if let Event::Key(key) = event::read().map_err(|e| miette::miette!("Event error: {e}"))? {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => break,
                KeyCode::Char('n') | KeyCode::Right => {
                    if state.current_step < state.total_steps {
                        state.current_step += 1;
                        state.delivery_scroll = 0;
                    }
                }
                KeyCode::Char('p') | KeyCode::Left => {
                    if state.current_step > 0 {
                        state.current_step -= 1;
                        state.delivery_scroll = 0;
                    }
                }
                KeyCode::Char('d') => {
                    state.show_diff = !state.show_diff;
                }
                KeyCode::Tab => {
                    state.focus = match state.focus {
                        Panel::Config => Panel::Deliveries,
                        Panel::Deliveries => Panel::Guards,
                        Panel::Guards => Panel::Config,
                    };
                }
                KeyCode::Char('j') | KeyCode::Down => {
                    if state.focus == Panel::Deliveries {
                        state.delivery_scroll = state.delivery_scroll.saturating_add(1);
                    }
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    if state.focus == Panel::Deliveries {
                        state.delivery_scroll = state.delivery_scroll.saturating_sub(1);
                    }
                }
                KeyCode::Home => {
                    state.current_step = 0;
                    state.delivery_scroll = 0;
                }
                KeyCode::End => {
                    state.current_step = state.total_steps;
                    state.delivery_scroll = 0;
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn draw_ui(f: &mut Frame, state: &ExploreState) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(2)])
        .split(f.area());

    let main_area = outer[0];
    let status_area = outer[1];

    let panels = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(33),
            Constraint::Percentage(34),
            Constraint::Percentage(33),
        ])
        .split(main_area);

    draw_config_panel(f, panels[0], state);
    draw_shared_vars_panel(f, panels[1], state);
    draw_deliveries_panel(f, panels[2], state);
    draw_status_bar(f, status_area, state);
}

fn get_config_at_step(state: &ExploreState) -> &tarsier_ir::counter_system::Configuration {
    if state.current_step == 0 {
        &state.trace.initial_config
    } else {
        &state.trace.steps[state.current_step - 1].config
    }
}

fn get_prev_config(state: &ExploreState) -> Option<&tarsier_ir::counter_system::Configuration> {
    if state.current_step == 0 {
        None
    } else if state.current_step == 1 {
        Some(&state.trace.initial_config)
    } else {
        Some(&state.trace.steps[state.current_step - 2].config)
    }
}

fn draw_config_panel(f: &mut Frame, area: Rect, state: &ExploreState) {
    let config = get_config_at_step(state);
    let prev = if state.show_diff {
        get_prev_config(state)
    } else {
        None
    };

    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(Span::styled(
        "Location Occupancy (kappa)",
        Style::default().add_modifier(Modifier::BOLD),
    )));

    for (i, count) in config.kappa.iter().enumerate() {
        if *count <= 0 {
            continue;
        }
        let loc_name = state
            .ta
            .as_ref()
            .map(|ta| ta.locations[i].name.as_str())
            .unwrap_or("?");

        let changed = prev
            .map(|p| p.kappa.get(i).copied().unwrap_or(0) != *count)
            .unwrap_or(false);

        let style = if changed {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        };
        lines.push(Line::from(Span::styled(
            format!("  {loc_name}: {count}"),
            style,
        )));
    }

    if !state.trace.param_values.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Parameters",
            Style::default().add_modifier(Modifier::BOLD),
        )));
        for (name, val) in &state.trace.param_values {
            lines.push(Line::from(format!("  {name} = {val}")));
        }
    }

    let border_style = if state.focus == Panel::Config {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default()
    };

    let block = Block::default()
        .title(" Locations ")
        .borders(Borders::ALL)
        .border_style(border_style);
    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });
    f.render_widget(paragraph, area);
}

fn draw_shared_vars_panel(f: &mut Frame, area: Rect, state: &ExploreState) {
    let config = get_config_at_step(state);
    let prev = if state.show_diff {
        get_prev_config(state)
    } else {
        None
    };

    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(Span::styled(
        "Shared Variables (gamma)",
        Style::default().add_modifier(Modifier::BOLD),
    )));

    for (i, val) in config.gamma.iter().enumerate() {
        if *val == 0
            && prev
                .map(|p| p.gamma.get(i).copied().unwrap_or(0) == 0)
                .unwrap_or(true)
        {
            continue;
        }
        let var_name = state
            .ta
            .as_ref()
            .map(|ta| ta.shared_vars[i].name.as_str())
            .unwrap_or("?");

        let changed = prev
            .map(|p| p.gamma.get(i).copied().unwrap_or(0) != *val)
            .unwrap_or(false);

        let style = if changed {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        };
        lines.push(Line::from(Span::styled(
            format!("  {var_name}: {val}"),
            style,
        )));
    }

    let border_style = if state.focus == Panel::Guards {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default()
    };

    let block = Block::default()
        .title(" Shared Vars ")
        .borders(Borders::ALL)
        .border_style(border_style);
    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });
    f.render_widget(paragraph, area);
}

fn draw_deliveries_panel(f: &mut Frame, area: Rect, state: &ExploreState) {
    let mut lines: Vec<Line> = Vec::new();

    if state.current_step == 0 {
        lines.push(Line::from("(initial configuration — no deliveries)"));
    } else {
        let step = &state.trace.steps[state.current_step - 1];

        // Show rule info
        if let Some(ta) = &state.ta {
            let rule = &ta.rules[step.rule_id];
            let from = &ta.locations[rule.from].name;
            let to = &ta.locations[rule.to].name;
            lines.push(Line::from(Span::styled(
                format!("Rule r{} x{}", step.rule_id, step.delta),
                Style::default().add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(format!("  {from} -> {to}")));
            lines.push(Line::from(format!("  Guard: {}", rule.guard)));
            lines.push(Line::from(""));
        }

        lines.push(Line::from(Span::styled(
            format!("Deliveries ({})", step.deliveries.len()),
            Style::default().add_modifier(Modifier::BOLD),
        )));

        for (i, delivery) in step.deliveries.iter().enumerate() {
            if i < state.delivery_scroll {
                continue;
            }
            let sender = format_identity(&delivery.sender);
            let recipient = format_identity(&delivery.recipient);
            lines.push(Line::from(Span::styled(
                format!("  [{i}] {:?} x{}", delivery.kind, delivery.count),
                Style::default().fg(Color::Green),
            )));
            lines.push(Line::from(format!("    {sender} -> {recipient}")));
            lines.push(Line::from(format!(
                "    {} [{}]",
                delivery.payload.family,
                delivery
                    .payload
                    .fields
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
    }

    let border_style = if state.focus == Panel::Deliveries {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default()
    };

    let block = Block::default()
        .title(" Deliveries ")
        .borders(Borders::ALL)
        .border_style(border_style);
    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });
    f.render_widget(paragraph, area);
}

fn draw_status_bar(f: &mut Frame, area: Rect, state: &ExploreState) {
    let status = build_status_line(state);
    let bar = Paragraph::new(Line::from(Span::styled(
        status,
        Style::default()
            .fg(Color::White)
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    )));
    f.render_widget(bar, area);
}

/// Build the compact status/help line shown at the bottom of the explorer.
fn build_status_line(state: &ExploreState) -> String {
    let step_label = if state.current_step == 0 {
        "initial".to_string()
    } else {
        format!("{}", state.current_step)
    };

    let loop_indicator = state
        .loop_start
        .map(|ls| format!(" | loop@{ls}"))
        .unwrap_or_default();

    let diff_indicator = if state.show_diff { " DIFF" } else { "" };

    format!(
        " Step {step_label}/{} {loop_indicator}{diff_indicator} | n/p:nav  d:diff  Tab:panel  j/k:scroll  q:quit",
        state.total_steps
    )
}

fn format_identity(id: &tarsier_ir::counter_system::MessageIdentity) -> String {
    if let Some(pid) = &id.process {
        format!("{}#{pid}", id.role)
    } else {
        id.role.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tarsier_ir::counter_system::{Configuration, MessageIdentity, Trace, TraceStep};

    fn make_state(current_step: usize) -> ExploreState {
        ExploreState {
            current_step,
            total_steps: 2,
            trace: Trace {
                initial_config: Configuration {
                    kappa: vec![3, 0],
                    gamma: vec![1],
                    params: vec![4],
                },
                steps: vec![
                    TraceStep {
                        smt_step: 0,
                        rule_id: 0,
                        delta: 1,
                        deliveries: vec![],
                        config: Configuration {
                            kappa: vec![2, 1],
                            gamma: vec![2],
                            params: vec![4],
                        },
                        por_status: None,
                    },
                    TraceStep {
                        smt_step: 1,
                        rule_id: 0,
                        delta: 1,
                        deliveries: vec![],
                        config: Configuration {
                            kappa: vec![1, 2],
                            gamma: vec![3],
                            params: vec![4],
                        },
                        por_status: None,
                    },
                ],
                param_values: vec![("n".to_string(), 4)],
            },
            ta: None,
            focus: Panel::Config,
            delivery_scroll: 0,
            show_diff: false,
            loop_start: None,
        }
    }

    #[test]
    fn config_at_step_zero_reads_initial_config() {
        let state = make_state(0);
        let config = get_config_at_step(&state);
        assert_eq!(config.kappa, vec![3, 0]);
        assert_eq!(config.gamma, vec![1]);
    }

    #[test]
    fn config_at_nonzero_step_reads_previous_trace_step() {
        let state = make_state(2);
        let config = get_config_at_step(&state);
        assert_eq!(config.kappa, vec![1, 2]);
        assert_eq!(config.gamma, vec![3]);
    }

    #[test]
    fn prev_config_selection_tracks_step_boundaries() {
        let state0 = make_state(0);
        let state1 = make_state(1);
        let state2 = make_state(2);

        assert!(get_prev_config(&state0).is_none());
        assert_eq!(get_prev_config(&state1).unwrap().kappa, vec![3, 0]);
        assert_eq!(get_prev_config(&state2).unwrap().kappa, vec![2, 1]);
    }

    #[test]
    fn identity_formatting_includes_pid_when_present() {
        let with_pid = MessageIdentity {
            role: "Replica".to_string(),
            process: Some("7".to_string()),
            key: Some("replica_key".to_string()),
        };
        let no_pid = MessageIdentity {
            role: "Client".to_string(),
            process: None,
            key: None,
        };

        assert_eq!(format_identity(&with_pid), "Replica#7");
        assert_eq!(format_identity(&no_pid), "Client");
    }

    #[test]
    fn status_line_for_initial_step_has_no_loop_or_diff_tags() {
        let state = make_state(0);
        let line = build_status_line(&state);
        assert!(line.contains("Step initial/2"));
        assert!(!line.contains("loop@"));
        assert!(!line.contains("DIFF"));
    }

    #[test]
    fn status_line_includes_loop_and_diff_when_enabled() {
        let mut state = make_state(2);
        state.loop_start = Some(1);
        state.show_diff = true;
        let line = build_status_line(&state);
        assert!(line.contains("Step 2/2"));
        assert!(line.contains("loop@1"));
        assert!(line.contains("DIFF"));
    }
}
