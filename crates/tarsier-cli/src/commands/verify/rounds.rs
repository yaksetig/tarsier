use tarsier_engine::pipeline::RoundAbstractionSummary;
use tarsier_engine::result::{UnboundedFairLivenessResult, UnboundedSafetyResult};

use super::{
    unbounded_fair_result_kind, unbounded_safety_result_kind, RoundBoundMutationStats,
    RoundSweepPoint, RoundSweepReport,
};

pub(crate) fn round_name_matches(names: &[String], candidate: &str) -> bool {
    names
        .iter()
        .any(|name| !name.trim().is_empty() && name.trim().eq_ignore_ascii_case(candidate))
}

pub(crate) fn apply_round_upper_bound(
    program: &mut tarsier_dsl::ast::Program,
    vars: &[String],
    new_max: i64,
) -> RoundBoundMutationStats {
    let mut stats = RoundBoundMutationStats::default();
    let proto = &mut program.protocol.node;

    for role in &mut proto.roles {
        for var in &mut role.node.vars {
            if !round_name_matches(vars, &var.name) {
                continue;
            }
            stats.matched_targets += 1;
            match var.range.as_mut() {
                Some(range) => {
                    range.max = new_max;
                    if range.min > range.max {
                        range.min = range.max;
                    }
                    stats.updated_ranges += 1;
                }
                None => {
                    stats
                        .unbounded_targets
                        .push(format!("{}.{}", role.node.name, var.name));
                }
            }
        }
    }

    for msg in &mut proto.messages {
        for field in &mut msg.fields {
            if !round_name_matches(vars, &field.name) {
                continue;
            }
            stats.matched_targets += 1;
            match field.range.as_mut() {
                Some(range) => {
                    range.max = new_max;
                    if range.min > range.max {
                        range.min = range.max;
                    }
                    stats.updated_ranges += 1;
                }
                None => {
                    stats
                        .unbounded_targets
                        .push(format!("{}.{}", msg.name, field.name));
                }
            }
        }
    }

    stats
}

pub(crate) fn detect_round_sweep_cutoff(
    points: &[RoundSweepPoint],
    stable_window: usize,
) -> Option<(i64, String)> {
    if points.is_empty() || stable_window == 0 {
        return None;
    }
    let tail_kind = points.last()?.result.as_str();
    let mut tail_len = 0usize;
    for point in points.iter().rev() {
        if point.result == tail_kind {
            tail_len += 1;
        } else {
            break;
        }
    }
    if tail_len < stable_window {
        return None;
    }
    let cutoff_index = points.len() - tail_len;
    Some((points[cutoff_index].upper_bound, tail_kind.to_string()))
}

pub(crate) fn render_round_sweep_text(report: &RoundSweepReport) -> String {
    let mut out = String::new();
    out.push_str("ROUND SWEEP\n");
    out.push_str(&format!("File: {}\n", report.file));
    out.push_str(&format!("Swept vars: {}\n", report.vars.join(", ")));
    out.push_str(&format!(
        "Upper bounds: {}..={}\n",
        report.min_bound, report.max_bound
    ));
    out.push_str(&format!("Convergence window: {}\n", report.stable_window));
    out.push_str("Results:\n");
    for point in &report.points {
        out.push_str(&format!(
            "  - <= {} => {}\n",
            point.upper_bound, point.result
        ));
    }
    match (report.candidate_cutoff, report.stabilized_result.as_deref()) {
        (Some(cutoff), Some(kind)) => {
            out.push_str(&format!(
                "Candidate cutoff: {} (stable suffix result = {}).\n",
                cutoff, kind
            ));
        }
        _ => {
            out.push_str("Candidate cutoff: not detected (increase max bound or window).\n");
        }
    }
    out.push_str(&format!("Note: {}\n", report.note));
    out
}

pub(crate) fn render_prove_round_text(
    file: &str,
    summary: &RoundAbstractionSummary,
    result: &UnboundedSafetyResult,
) -> String {
    let mut out = String::new();
    out.push_str("ROUND ABSTRACTION PROOF\n");
    out.push_str(&format!("File: {file}\n"));
    out.push_str(&format!(
        "Erased vars: {}\n",
        summary.erased_vars.join(", ")
    ));
    out.push_str(&format!(
        "Locations: {} -> {}\n",
        summary.original_locations, summary.abstract_locations
    ));
    out.push_str(&format!(
        "Shared vars: {} -> {}\n",
        summary.original_shared_vars, summary.abstract_shared_vars
    ));
    out.push_str(&format!(
        "Message counters: {} -> {}\n",
        summary.original_message_counters, summary.abstract_message_counters
    ));
    out.push_str(&format!(
        "Result: {}\n",
        unbounded_safety_result_kind(result)
    ));
    out.push_str(&format!("{result}\n"));
    match result {
        UnboundedSafetyResult::Safe { .. }
        | UnboundedSafetyResult::ProbabilisticallySafe { .. } => {
            out.push_str(
                "Soundness note: SAFE on this abstraction is sound for unbounded rounds (over-approximation).\n",
            );
        }
        UnboundedSafetyResult::Unsafe { .. } => {
            out.push_str(
                "Soundness note: UNSAFE may be spurious under over-approximation; confirm on concrete model.\n",
            );
        }
        _ => {}
    }
    out
}

pub(crate) fn render_prove_fair_round_text(
    file: &str,
    summary: &RoundAbstractionSummary,
    result: &UnboundedFairLivenessResult,
) -> String {
    let mut out = String::new();
    out.push_str("ROUND ABSTRACTION FAIR-LIVENESS PROOF\n");
    out.push_str(&format!("File: {file}\n"));
    out.push_str(&format!(
        "Erased vars: {}\n",
        summary.erased_vars.join(", ")
    ));
    out.push_str(&format!(
        "Locations: {} -> {}\n",
        summary.original_locations, summary.abstract_locations
    ));
    out.push_str(&format!(
        "Shared vars: {} -> {}\n",
        summary.original_shared_vars, summary.abstract_shared_vars
    ));
    out.push_str(&format!(
        "Message counters: {} -> {}\n",
        summary.original_message_counters, summary.abstract_message_counters
    ));
    out.push_str(&format!("Result: {}\n", unbounded_fair_result_kind(result)));
    out.push_str(&format!("{result}\n"));
    match result {
        UnboundedFairLivenessResult::LiveProved { .. } => {
            out.push_str(
                "Soundness note: LIVE_PROVED on this abstraction is sound for unbounded rounds (over-approximation).\n",
            );
        }
        UnboundedFairLivenessResult::FairCycleFound { .. } => {
            out.push_str(
                "Soundness note: FAIR_CYCLE_FOUND may be spurious under over-approximation; confirm on concrete model.\n",
            );
        }
        _ => {}
    }
    out
}
