// Command handlers for: Verify, RoundSweep, ProveRound, ProveFairRound, Liveness, FairLiveness
//
// These commands handle bounded verification, round-sweep analysis,
// round-abstraction proofs, and liveness checking workflows.

use std::fs;
use std::path::PathBuf;

use miette::IntoDiagnostic;
use serde::Serialize;
use serde_json::{json, Value};

use tarsier_engine::pipeline::{
    take_run_diagnostics, PipelineOptions, PipelineRunDiagnostics, ProofEngine, SolverChoice,
};
use tarsier_engine::result::{
    CegarAuditReport, CegarCounterexampleAnalysis, CegarRunControls, CegarStageOutcome,
    FairLivenessResult, InductionCtiSummary, LivenessResult, LivenessUnknownReason,
    UnboundedFairLivenessCegarAuditReport, UnboundedFairLivenessCegarStageOutcome,
    UnboundedFairLivenessResult, UnboundedSafetyCegarAuditReport, UnboundedSafetyCegarStageOutcome,
    UnboundedSafetyResult, VerificationResult,
};
use tarsier_ir::counter_system::Trace;
use tarsier_proof_kernel::sha256_hex_bytes;

use super::helpers::{
    make_options, parse_fairness_mode, parse_output_format, parse_solver_choice,
    parse_soundness_mode, sandbox_read_source,
};
use crate::{
    network_faithfulness_section, render_fallback_summary, render_optimization_summary,
    render_phase_profile_summary, run_diagnostics_details, validate_cli_network_semantics_mode,
    CliNetworkSemanticsMode, OutputFormat,
};

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub(crate) struct RoundSweepPoint {
    pub upper_bound: i64,
    pub result: String,
    pub details: Value,
}

#[derive(Debug, Serialize)]
pub(crate) struct RoundSweepReport {
    pub schema_version: u32,
    pub file: String,
    pub vars: Vec<String>,
    pub min_bound: i64,
    pub max_bound: i64,
    pub stable_window: usize,
    pub points: Vec<RoundSweepPoint>,
    pub candidate_cutoff: Option<i64>,
    pub stabilized_result: Option<String>,
    pub note: String,
}

#[derive(Default)]
pub(crate) struct RoundBoundMutationStats {
    matched_targets: usize,
    updated_ranges: usize,
    unbounded_targets: Vec<String>,
}

// ---------------------------------------------------------------------------
// Helper functions — trace serialization
// ---------------------------------------------------------------------------

pub(crate) fn trace_details(trace: &Trace) -> Value {
    let deliveries: i64 = trace
        .steps
        .iter()
        .flat_map(|step| step.deliveries.iter())
        .filter(|d| d.kind == tarsier_ir::counter_system::MessageEventKind::Deliver)
        .map(|d| d.count)
        .sum();
    json!({
        "steps": trace.steps.len(),
        "deliveries": deliveries,
        "params": trace.param_values,
    })
}

pub(crate) fn cti_details(cti: &InductionCtiSummary) -> Value {
    json!({
        "k": cti.k,
        "classification": format!("{}", cti.classification),
        "classification_evidence": cti.classification_evidence,
        "rationale": cti.rationale,
        "params": cti.params,
        "hypothesis": {
            "locations": cti.hypothesis_locations,
            "shared": cti.hypothesis_shared,
        },
        "violating": {
            "locations": cti.violating_locations,
            "shared": cti.violating_shared,
        },
        "final_step_rules": cti.final_step_rules,
        "violated_condition": cti.violated_condition,
    })
}

pub(crate) fn trace_json(trace: &Trace) -> Value {
    let steps: Vec<Value> = trace
        .steps
        .iter()
        .enumerate()
        .map(|(idx, step)| {
            let deliveries: Vec<Value> = step
                .deliveries
                .iter()
                .map(|delivery| {
                    json!({
                        "kind": format!("{:?}", delivery.kind),
                        "count": delivery.count,
                        "shared_var": delivery.shared_var,
                        "shared_var_name": delivery.shared_var_name,
                        "sender": {
                            "role": delivery.sender.role.clone(),
                            "process": delivery.sender.process.clone(),
                            "key": delivery.sender.key.clone(),
                        },
                        "recipient": {
                            "role": delivery.recipient.role.clone(),
                            "process": delivery.recipient.process.clone(),
                            "key": delivery.recipient.key.clone(),
                        },
                        "payload": {
                            "family": delivery.payload.family.clone(),
                            "fields": delivery.payload.fields.clone(),
                            "variant": delivery.payload.variant.clone(),
                        },
                        "auth": {
                            "authenticated_channel": delivery.auth.authenticated_channel,
                            "signature_key": delivery.auth.signature_key.clone(),
                            "key_owner_role": delivery.auth.key_owner_role.clone(),
                            "key_compromised": delivery.auth.key_compromised,
                            "provenance": format!("{:?}", delivery.auth.provenance),
                        }
                    })
                })
                .collect();
            json!({
                "step": idx + 1,
                "smt_step": step.smt_step,
                "rule_id": step.rule_id,
                "delta": step.delta,
                "deliveries": deliveries,
                "kappa": step.config.kappa,
                "gamma": step.config.gamma,
                "por_status": step.por_status,
            })
        })
        .collect();
    json!({
        "params": trace.param_values,
        "initial": {
            "kappa": trace.initial_config.kappa,
            "gamma": trace.initial_config.gamma,
        },
        "steps": steps,
    })
}

// ---------------------------------------------------------------------------
// Helper functions — result classification
// ---------------------------------------------------------------------------

pub(crate) fn verification_result_kind(result: &VerificationResult) -> &'static str {
    match result {
        VerificationResult::Safe { .. } => "safe",
        VerificationResult::ProbabilisticallySafe { .. } => "probabilistically_safe",
        VerificationResult::Unsafe { .. } => "unsafe",
        VerificationResult::Unknown { .. } => "unknown",
    }
}

pub(crate) fn verification_result_details(result: &VerificationResult) -> Value {
    match result {
        VerificationResult::Safe { depth_checked } => {
            json!({"depth_checked": depth_checked})
        }
        VerificationResult::ProbabilisticallySafe {
            depth_checked,
            failure_probability,
            committee_analyses,
        } => json!({
            "depth_checked": depth_checked,
            "failure_probability": failure_probability,
            "committee_count": committee_analyses.len(),
        }),
        VerificationResult::Unsafe { trace } => json!({
            "trace_len": trace.steps.len(),
            "trace": trace_json(trace),
        }),
        VerificationResult::Unknown { reason } => {
            json!({"reason": reason})
        }
    }
}

pub(crate) fn unbounded_safety_result_kind(result: &UnboundedSafetyResult) -> &'static str {
    match result {
        UnboundedSafetyResult::Safe { .. } => "safe",
        UnboundedSafetyResult::ProbabilisticallySafe { .. } => "probabilistically_safe",
        UnboundedSafetyResult::Unsafe { .. } => "unsafe",
        UnboundedSafetyResult::NotProved { .. } => "not_proved",
        UnboundedSafetyResult::Unknown { .. } => "unknown",
    }
}

pub(crate) fn unbounded_safety_result_details(result: &UnboundedSafetyResult) -> Value {
    match result {
        UnboundedSafetyResult::Safe { induction_k } => json!({
            "induction_k": induction_k,
        }),
        UnboundedSafetyResult::ProbabilisticallySafe {
            induction_k,
            failure_probability,
            committee_analyses,
        } => json!({
            "induction_k": induction_k,
            "failure_probability": failure_probability,
            "committee_count": committee_analyses.len(),
        }),
        UnboundedSafetyResult::Unsafe { trace } => json!({
            "trace_len": trace.steps.len(),
            "trace": trace_json(trace),
        }),
        UnboundedSafetyResult::NotProved { max_k, cti } => json!({
            "max_k": max_k,
            "cti": cti.as_ref().map(cti_details),
        }),
        UnboundedSafetyResult::Unknown { reason } => json!({
            "reason": reason,
        }),
    }
}

pub(crate) fn unbounded_fair_result_kind(result: &UnboundedFairLivenessResult) -> &'static str {
    match result {
        UnboundedFairLivenessResult::LiveProved { .. } => "live_proved",
        UnboundedFairLivenessResult::FairCycleFound { .. } => "fair_cycle_found",
        UnboundedFairLivenessResult::NotProved { .. } => "not_proved",
        UnboundedFairLivenessResult::Unknown { .. } => "unknown",
    }
}

pub(crate) fn liveness_unknown_reason_payload(reason: &str) -> Value {
    let classified = LivenessUnknownReason::classify(reason);
    json!({
        "reason": reason,
        "reason_code": classified.code(),
    })
}

pub(crate) fn liveness_convergence_diagnostics(
    result: &UnboundedFairLivenessResult,
    diagnostics: Option<&PipelineRunDiagnostics>,
) -> Value {
    let mut payload = match result {
        UnboundedFairLivenessResult::LiveProved { frame } => json!({
            "outcome": "converged",
            "frontier_frame": frame,
            "proof_closed": true,
        }),
        UnboundedFairLivenessResult::FairCycleFound {
            depth, loop_start, ..
        } => json!({
            "outcome": "counterexample",
            "counterexample_depth": depth,
            "loop_start": loop_start,
        }),
        UnboundedFairLivenessResult::NotProved { max_k } => json!({
            "outcome": "not_converged",
            "frontier_frame": max_k,
            "bound_exhausted": true,
        }),
        UnboundedFairLivenessResult::Unknown { reason } => {
            let classified = LivenessUnknownReason::classify(reason);
            json!({
                "outcome": "inconclusive",
                "reason_code": classified.code(),
                "reason": reason,
            })
        }
    };

    if let Some(diag) = diagnostics {
        let total_solve_calls: u64 = diag.smt_profiles.iter().map(|p| p.solve_calls).sum();
        let total_solve_elapsed_ms: u128 =
            diag.smt_profiles.iter().map(|p| p.solve_elapsed_ms).sum();
        let total_encode_elapsed_ms: u128 =
            diag.smt_profiles.iter().map(|p| p.encode_elapsed_ms).sum();
        if let Some(obj) = payload.as_object_mut() {
            obj.insert(
                "phase_profile_entries".into(),
                json!(diag.phase_profiles.len()),
            );
            obj.insert("smt_profile_entries".into(), json!(diag.smt_profiles.len()));
            obj.insert("total_solve_calls".into(), json!(total_solve_calls));
            obj.insert(
                "total_solve_elapsed_ms".into(),
                json!(total_solve_elapsed_ms),
            );
            obj.insert(
                "total_encode_elapsed_ms".into(),
                json!(total_encode_elapsed_ms),
            );
        }
    }

    payload
}

pub(crate) fn unbounded_fair_result_details(result: &UnboundedFairLivenessResult) -> Value {
    let convergence = liveness_convergence_diagnostics(result, None);
    match result {
        UnboundedFairLivenessResult::LiveProved { frame } => json!({
            "frame": frame,
            "convergence": convergence.clone(),
        }),
        UnboundedFairLivenessResult::FairCycleFound {
            depth,
            loop_start,
            trace,
        } => json!({
            "depth": depth,
            "loop_start": loop_start,
            "trace_len": trace.steps.len(),
            "trace": trace_json(trace),
            "convergence": convergence.clone(),
        }),
        UnboundedFairLivenessResult::NotProved { max_k } => json!({
            "max_k": max_k,
            "convergence": convergence.clone(),
        }),
        UnboundedFairLivenessResult::Unknown { reason } => {
            let payload = liveness_unknown_reason_payload(reason);
            json!({
                "reason": payload["reason"],
                "reason_code": payload["reason_code"],
                "convergence": convergence.clone(),
            })
        }
    }
}

pub(crate) fn liveness_result_kind(result: &LivenessResult) -> &'static str {
    match result {
        LivenessResult::Live { .. } => "live",
        LivenessResult::NotLive { .. } => "not_live",
        LivenessResult::Unknown { .. } => "unknown",
    }
}

pub(crate) fn fair_liveness_result_kind(result: &FairLivenessResult) -> &'static str {
    match result {
        FairLivenessResult::NoFairCycleUpTo { .. } => "no_fair_cycle_up_to",
        FairLivenessResult::FairCycleFound { .. } => "fair_cycle_found",
        FairLivenessResult::Unknown { .. } => "unknown",
    }
}

pub(crate) fn liveness_result_details(result: &LivenessResult) -> Value {
    match result {
        LivenessResult::Live { depth_checked } => {
            json!({"depth_checked": depth_checked})
        }
        LivenessResult::NotLive { trace } => json!({
            "trace_len": trace.steps.len(),
            "trace": trace_json(trace),
        }),
        LivenessResult::Unknown { reason } => {
            json!({"reason": reason})
        }
    }
}

pub(crate) fn fair_liveness_result_details(result: &FairLivenessResult) -> Value {
    match result {
        FairLivenessResult::NoFairCycleUpTo { depth_checked } => {
            json!({"depth_checked": depth_checked})
        }
        FairLivenessResult::FairCycleFound {
            depth,
            loop_start,
            trace,
        } => json!({
            "depth": depth,
            "loop_start": loop_start,
            "trace_len": trace.steps.len(),
            "trace": trace_json(trace),
        }),
        FairLivenessResult::Unknown { reason } => {
            json!({"reason": reason})
        }
    }
}

// ---------------------------------------------------------------------------
// Helper functions — round-sweep support
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Helper functions — text rendering
// ---------------------------------------------------------------------------

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
    summary: &tarsier_engine::pipeline::RoundAbstractionSummary,
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
    summary: &tarsier_engine::pipeline::RoundAbstractionSummary,
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

// ---------------------------------------------------------------------------
// Helper functions — CEGAR report serialization
// ---------------------------------------------------------------------------

pub(crate) fn strip_cegar_volatile_fields(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.remove("elapsed_ms");
            for nested in map.values_mut() {
                strip_cegar_volatile_fields(nested);
            }
        }
        Value::Array(items) => {
            for nested in items {
                strip_cegar_volatile_fields(nested);
            }
        }
        _ => {}
    }
}

pub(crate) fn cegar_diff_friendly_projection(value: &Value) -> Value {
    let mut canonical = value.clone();
    strip_cegar_volatile_fields(&mut canonical);
    canonical
}

pub(crate) fn cegar_with_provenance(mut payload: Value) -> Value {
    let diff_friendly = cegar_diff_friendly_projection(&payload);
    let fingerprint_sha256 = serde_json::to_vec(&diff_friendly)
        .map(|bytes| sha256_hex_bytes(&bytes))
        .unwrap_or_else(|err| {
            sha256_hex_bytes(format!("cegar-fingerprint-error:{err}").as_bytes())
        });

    if let Value::Object(map) = &mut payload {
        map.insert(
            "provenance".into(),
            json!({
                "fingerprint_sha256": fingerprint_sha256,
                "canonicalization": "cegar.v1.drop_volatile_timing_fields",
                "volatile_fields": ["termination.elapsed_ms"],
            }),
        );
        map.insert("diff_friendly".into(), diff_friendly);
    }

    payload
}

pub(crate) fn cegar_stage_outcome_json(outcome: &CegarStageOutcome) -> Value {
    match outcome {
        CegarStageOutcome::Safe { depth_checked } => {
            json!({"result": "safe", "depth_checked": depth_checked})
        }
        CegarStageOutcome::ProbabilisticallySafe {
            depth_checked,
            failure_probability,
            committee_count,
        } => json!({
            "result": "probabilistically_safe",
            "depth_checked": depth_checked,
            "failure_probability": failure_probability,
            "committee_count": committee_count,
        }),
        CegarStageOutcome::Unsafe { trace } => {
            json!({"result": "unsafe", "trace": trace_json(trace)})
        }
        CegarStageOutcome::Unknown { reason } => {
            json!({"result": "unknown", "reason": reason})
        }
    }
}

pub(crate) fn cegar_counterexample_analysis_json(analysis: &CegarCounterexampleAnalysis) -> Value {
    json!({
        "classification": analysis.classification,
        "rationale": analysis.rationale,
    })
}

pub(crate) fn cegar_model_change_json(change: &tarsier_engine::result::CegarModelChange) -> Value {
    json!({
        "category": change.category,
        "target": change.target,
        "before": change.before,
        "after": change.after,
        "predicate": change.predicate,
    })
}

pub(crate) fn cegar_eliminated_trace_json(
    trace: &tarsier_engine::result::CegarEliminatedTrace,
) -> Value {
    json!({
        "kind": trace.kind,
        "source_stage": trace.source_stage,
        "eliminated_by": trace.eliminated_by,
        "rationale": trace.rationale,
        "trace": trace_json(&trace.trace),
    })
}

pub(crate) fn cegar_report_details(report: &CegarAuditReport) -> Value {
    let stages: Vec<Value> = report
        .stages
        .iter()
        .map(|stage| {
            json!({
                "stage": stage.stage,
                "label": stage.label,
                "refinements": stage.refinements,
                "model_changes": stage.model_changes.iter().map(cegar_model_change_json).collect::<Vec<_>>(),
                "eliminated_traces": stage.eliminated_traces.iter().map(cegar_eliminated_trace_json).collect::<Vec<_>>(),
                "discovered_predicates": stage.discovered_predicates,
                "note": stage.note,
                "outcome": cegar_stage_outcome_json(&stage.outcome),
                "counterexample_analysis": stage
                    .counterexample_analysis
                    .as_ref()
                    .map(cegar_counterexample_analysis_json),
            })
        })
        .collect();
    cegar_with_provenance(json!({
        "max_refinements": report.max_refinements,
        "classification": report.classification,
        "termination": {
            "reason": report.termination.reason,
            "iteration_budget": report.termination.iteration_budget,
            "iterations_used": report.termination.iterations_used,
            "timeout_secs": report.termination.timeout_secs,
            "elapsed_ms": report.termination.elapsed_ms,
            "reached_iteration_budget": report.termination.reached_iteration_budget,
            "reached_timeout_budget": report.termination.reached_timeout_budget,
        },
        "counterexample_analysis": report
            .counterexample_analysis
            .as_ref()
            .map(cegar_counterexample_analysis_json),
        "final_result": verification_result_kind(&report.final_result),
        "discovered_predicates": report.discovered_predicates,
        "stages": stages,
    }))
}

pub(crate) fn cegar_controls_json(controls: &CegarRunControls) -> Value {
    json!({
        "max_refinements": controls.max_refinements,
        "timeout_secs": controls.timeout_secs,
        "solver": controls.solver,
        "proof_engine": controls.proof_engine,
        "fairness": controls.fairness,
    })
}

pub(crate) fn unbounded_safety_cegar_stage_outcome_json(
    outcome: &UnboundedSafetyCegarStageOutcome,
) -> Value {
    match outcome {
        UnboundedSafetyCegarStageOutcome::Safe { induction_k } => {
            json!({"result": "safe", "induction_k": induction_k})
        }
        UnboundedSafetyCegarStageOutcome::ProbabilisticallySafe {
            induction_k,
            failure_probability,
            committee_count,
        } => json!({
            "result": "probabilistically_safe",
            "induction_k": induction_k,
            "failure_probability": failure_probability,
            "committee_count": committee_count,
        }),
        UnboundedSafetyCegarStageOutcome::Unsafe { trace } => {
            json!({"result": "unsafe", "trace": trace_json(trace)})
        }
        UnboundedSafetyCegarStageOutcome::NotProved { max_k, cti } => json!({
            "result": "not_proved",
            "max_k": max_k,
            "cti": cti.as_ref().map(cti_details),
        }),
        UnboundedSafetyCegarStageOutcome::Unknown { reason } => {
            json!({"result": "unknown", "reason": reason})
        }
    }
}

pub(crate) fn unbounded_fair_cegar_stage_outcome_json(
    outcome: &UnboundedFairLivenessCegarStageOutcome,
) -> Value {
    match outcome {
        UnboundedFairLivenessCegarStageOutcome::LiveProved { frame } => {
            json!({"result": "live_proved", "frame": frame})
        }
        UnboundedFairLivenessCegarStageOutcome::FairCycleFound {
            depth,
            loop_start,
            trace,
        } => json!({
            "result": "fair_cycle_found",
            "depth": depth,
            "loop_start": loop_start,
            "trace": trace_json(trace),
        }),
        UnboundedFairLivenessCegarStageOutcome::NotProved { max_k } => {
            json!({"result": "not_proved", "max_k": max_k})
        }
        UnboundedFairLivenessCegarStageOutcome::Unknown { reason } => {
            let payload = liveness_unknown_reason_payload(reason);
            json!({
                "result": "unknown",
                "reason": payload["reason"],
                "reason_code": payload["reason_code"],
            })
        }
    }
}

pub(crate) fn unbounded_safety_cegar_report_details(
    report: &UnboundedSafetyCegarAuditReport,
) -> Value {
    let stages: Vec<Value> = report
        .stages
        .iter()
        .map(|stage| {
            json!({
                "stage": stage.stage,
                "label": stage.label,
                "refinements": stage.refinements,
                "model_changes": stage.model_changes.iter().map(cegar_model_change_json).collect::<Vec<_>>(),
                "eliminated_traces": stage.eliminated_traces.iter().map(cegar_eliminated_trace_json).collect::<Vec<_>>(),
                "discovered_predicates": stage.discovered_predicates,
                "note": stage.note,
                "outcome": unbounded_safety_cegar_stage_outcome_json(&stage.outcome),
                "counterexample_analysis": stage
                    .counterexample_analysis
                    .as_ref()
                    .map(cegar_counterexample_analysis_json),
            })
        })
        .collect();
    cegar_with_provenance(json!({
        "controls": cegar_controls_json(&report.controls),
        "classification": report.classification,
        "termination": {
            "reason": report.termination.reason,
            "iteration_budget": report.termination.iteration_budget,
            "iterations_used": report.termination.iterations_used,
            "timeout_secs": report.termination.timeout_secs,
            "elapsed_ms": report.termination.elapsed_ms,
            "reached_iteration_budget": report.termination.reached_iteration_budget,
            "reached_timeout_budget": report.termination.reached_timeout_budget,
        },
        "discovered_predicates": report.discovered_predicates,
        "counterexample_analysis": report
            .counterexample_analysis
            .as_ref()
            .map(cegar_counterexample_analysis_json),
        "stages": stages,
        "baseline_result": {
            "result": unbounded_safety_result_kind(&report.baseline_result),
            "details": unbounded_safety_result_details(&report.baseline_result),
            "output": format!("{}", report.baseline_result),
        },
        "final_result": {
            "result": unbounded_safety_result_kind(&report.final_result),
            "details": unbounded_safety_result_details(&report.final_result),
            "output": format!("{}", report.final_result),
        },
    }))
}

pub(crate) fn unbounded_fair_cegar_report_details(
    report: &UnboundedFairLivenessCegarAuditReport,
) -> Value {
    let stages: Vec<Value> = report
        .stages
        .iter()
        .map(|stage| {
            json!({
                "stage": stage.stage,
                "label": stage.label,
                "refinements": stage.refinements,
                "model_changes": stage.model_changes.iter().map(cegar_model_change_json).collect::<Vec<_>>(),
                "eliminated_traces": stage.eliminated_traces.iter().map(cegar_eliminated_trace_json).collect::<Vec<_>>(),
                "discovered_predicates": stage.discovered_predicates,
                "note": stage.note,
                "outcome": unbounded_fair_cegar_stage_outcome_json(&stage.outcome),
                "counterexample_analysis": stage
                    .counterexample_analysis
                    .as_ref()
                    .map(cegar_counterexample_analysis_json),
            })
        })
        .collect();
    cegar_with_provenance(json!({
        "controls": cegar_controls_json(&report.controls),
        "classification": report.classification,
        "termination": {
            "reason": report.termination.reason,
            "iteration_budget": report.termination.iteration_budget,
            "iterations_used": report.termination.iterations_used,
            "timeout_secs": report.termination.timeout_secs,
            "elapsed_ms": report.termination.elapsed_ms,
            "reached_iteration_budget": report.termination.reached_iteration_budget,
            "reached_timeout_budget": report.termination.reached_timeout_budget,
        },
        "discovered_predicates": report.discovered_predicates,
        "counterexample_analysis": report
            .counterexample_analysis
            .as_ref()
            .map(cegar_counterexample_analysis_json),
        "stages": stages,
        "baseline_result": {
            "result": unbounded_fair_result_kind(&report.baseline_result),
            "details": unbounded_fair_result_details(&report.baseline_result),
            "output": format!("{}", report.baseline_result),
        },
        "final_result": {
            "result": unbounded_fair_result_kind(&report.final_result),
            "details": unbounded_fair_result_details(&report.final_result),
            "output": format!("{}", report.final_result),
        },
    }))
}

// ---------------------------------------------------------------------------
// Helper functions — JSON artifacts and solver portfolio
// ---------------------------------------------------------------------------

pub(crate) fn write_json_artifact(path: &PathBuf, value: &Value) -> miette::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).into_diagnostic()?;
    }
    fs::write(path, serde_json::to_string_pretty(value).into_diagnostic()?).into_diagnostic()?;
    Ok(())
}

pub(crate) fn solver_result_json<T>(
    res: &Result<T, String>,
    render_ok: impl Fn(&T) -> Value,
) -> Value {
    match res {
        Ok(v) => json!({"status": "ok", "data": render_ok(v)}),
        Err(e) => json!({"status": "error", "error": e}),
    }
}

pub(crate) fn solver_outcome_json<T>(
    res: &Result<T, String>,
    result_kind: impl Fn(&T) -> &'static str,
) -> Value {
    match res {
        Ok(v) => json!({"status": "ok", "result": result_kind(v)}),
        Err(e) => json!({"status": "error", "error": e}),
    }
}

pub(crate) fn trace_fingerprint(trace: &Trace) -> String {
    serde_json::to_string(&trace_json(trace))
        .unwrap_or_else(|_| format!("{:?}:{:?}", trace.param_values, trace.steps))
}

pub(crate) fn prefer_trace_a(trace_a: &Trace, trace_b: &Trace) -> bool {
    match trace_a.steps.len().cmp(&trace_b.steps.len()) {
        std::cmp::Ordering::Less => true,
        std::cmp::Ordering::Greater => false,
        std::cmp::Ordering::Equal => trace_fingerprint(trace_a) <= trace_fingerprint(trace_b),
    }
}

pub(crate) fn portfolio_merge_policy(result_precedence: &[&str], trace_tiebreak: &str) -> Value {
    json!({
        "deterministic": true,
        "result_precedence": result_precedence,
        "trace_tiebreak": trace_tiebreak,
    })
}

// ---------------------------------------------------------------------------
// Portfolio merge functions
// ---------------------------------------------------------------------------

pub(crate) fn merge_portfolio_verify_reports(
    z3: Result<tarsier_engine::result::CegarAuditReport, String>,
    cvc5: Result<tarsier_engine::result::CegarAuditReport, String>,
) -> (VerificationResult, Value) {
    let mut details = json!({
        "mode": "portfolio",
        "merge_policy": portfolio_merge_policy(
            &["unsafe", "safe", "probabilistically_safe", "unknown"],
            "shortest_trace_then_lexicographic",
        ),
        "z3": solver_result_json(&z3, |r| json!({
            "result": verification_result_kind(&r.final_result),
            "cegar": cegar_report_details(r),
        })),
        "cvc5": solver_result_json(&cvc5, |r| json!({
            "result": verification_result_kind(&r.final_result),
            "cegar": cegar_report_details(r),
        })),
    });

    let (final_result, selected_solver, merge_reason) = match (&z3, &cvc5) {
        (Ok(z), Ok(c)) => {
            let zr = &z.final_result;
            let cr = &c.final_result;
            if let (
                VerificationResult::Unsafe { trace: ta },
                VerificationResult::Unsafe { trace: tb },
            ) = (zr, cr)
            {
                if prefer_trace_a(ta, tb) {
                    (
                        VerificationResult::Unsafe { trace: ta.clone() },
                        "z3",
                        "Both solvers reported unsafe; selected z3 trace by deterministic shortest-trace/lexicographic tiebreak."
                            .to_string(),
                    )
                } else {
                    (
                        VerificationResult::Unsafe { trace: tb.clone() },
                        "cvc5",
                        "Both solvers reported unsafe; selected cvc5 trace by deterministic shortest-trace/lexicographic tiebreak."
                            .to_string(),
                    )
                }
            } else {
                match (zr, cr) {
                    (VerificationResult::Safe { .. }, VerificationResult::Safe { .. })
                    | (
                        VerificationResult::Safe { .. },
                        VerificationResult::ProbabilisticallySafe { .. },
                    )
                    | (
                        VerificationResult::ProbabilisticallySafe { .. },
                        VerificationResult::Safe { .. },
                    )
                    | (
                        VerificationResult::ProbabilisticallySafe { .. },
                        VerificationResult::ProbabilisticallySafe { .. },
                    ) => (
                        zr.clone(),
                        "z3",
                        "Both solvers returned safety-equivalent verdicts; selected z3 result by deterministic solver-order tie-break."
                            .to_string(),
                    ),
                    (
                        VerificationResult::Unknown { reason: rz },
                        VerificationResult::Unknown { reason: rc },
                    ) => (
                        VerificationResult::Unknown {
                            reason: format!(
                                "Portfolio: both solvers inconclusive (z3: {rz}; cvc5: {rc})."
                            ),
                        },
                        "none",
                        "Both solvers were inconclusive; merged result is unknown.".to_string(),
                    ),
                    _ => (
                        VerificationResult::Unknown {
                            reason: format!(
                                "Portfolio disagreement (z3: {}, cvc5: {}).",
                                verification_result_kind(zr),
                                verification_result_kind(cr)
                            ),
                        },
                        "none",
                        "Solvers disagreed on verification outcome; merged result is unknown."
                            .to_string(),
                    ),
                }
            }
        }
        (Ok(z), Err(e)) => (
            VerificationResult::Unknown {
                reason: format!(
                    "Portfolio incomplete: z3={}, cvc5 error={e}.",
                    verification_result_kind(&z.final_result)
                ),
            },
            "none",
            "cvc5 failed while z3 completed; merged result is unknown due to incomplete portfolio."
                .to_string(),
        ),
        (Err(e), Ok(c)) => (
            VerificationResult::Unknown {
                reason: format!(
                    "Portfolio incomplete: z3 error={e}, cvc5={}.",
                    verification_result_kind(&c.final_result)
                ),
            },
            "none",
            "z3 failed while cvc5 completed; merged result is unknown due to incomplete portfolio."
                .to_string(),
        ),
        (Err(e1), Err(e2)) => (
            VerificationResult::Unknown {
                reason: format!("Portfolio failed: z3 error={e1}; cvc5 error={e2}."),
            },
            "none",
            "Both portfolio solvers failed; merged result is unknown.".to_string(),
        ),
    };

    if let Some(obj) = details.as_object_mut() {
        obj.insert(
            "per_solver_outcomes".into(),
            json!({
                "z3": solver_outcome_json(&z3, |r| verification_result_kind(&r.final_result)),
                "cvc5": solver_outcome_json(&cvc5, |r| verification_result_kind(&r.final_result)),
            }),
        );
        obj.insert("selected_solver".into(), json!(selected_solver));
        obj.insert("merge_reason".into(), json!(merge_reason));
    }

    (final_result, details)
}

pub(crate) fn merge_portfolio_liveness_results(
    z3: Result<LivenessResult, String>,
    cvc5: Result<LivenessResult, String>,
) -> (LivenessResult, Value) {
    let mut details = json!({
        "mode": "portfolio",
        "merge_policy": portfolio_merge_policy(
            &["not_live", "live", "unknown"],
            "shortest_trace_then_lexicographic",
        ),
        "z3": solver_result_json(&z3, |r| json!({"result": liveness_result_kind(r), "output": format!("{r}")})),
        "cvc5": solver_result_json(&cvc5, |r| json!({"result": liveness_result_kind(r), "output": format!("{r}")})),
    });

    let (final_result, selected_solver, merge_reason) = match (&z3, &cvc5) {
        (Ok(LivenessResult::NotLive { trace: ta }), Ok(LivenessResult::NotLive { trace: tb })) => {
            if prefer_trace_a(ta, tb) {
                (
                    LivenessResult::NotLive { trace: ta.clone() },
                    "z3",
                    "Both solvers found liveness counterexamples; selected z3 trace by deterministic shortest-trace/lexicographic tiebreak."
                        .to_string(),
                )
            } else {
                (
                    LivenessResult::NotLive { trace: tb.clone() },
                    "cvc5",
                    "Both solvers found liveness counterexamples; selected cvc5 trace by deterministic shortest-trace/lexicographic tiebreak."
                        .to_string(),
                )
            }
        }
        (Ok(a), Ok(b)) => match (a, b) {
            (
                LivenessResult::Live { depth_checked: da },
                LivenessResult::Live { depth_checked: db },
            ) => (
                LivenessResult::Live {
                    depth_checked: (*da).min(*db),
                },
                "both",
                "Both solvers proved live; selected conservative minimum checked depth."
                    .to_string(),
            ),
            (LivenessResult::Unknown { reason: ra }, LivenessResult::Unknown { reason: rb }) => (
                LivenessResult::Unknown {
                    reason: format!("Portfolio: both solvers inconclusive (z3: {ra}; cvc5: {rb})."),
                },
                "none",
                "Both solvers were inconclusive; merged result is unknown.".to_string(),
            ),
            _ => (
                LivenessResult::Unknown {
                    reason: format!(
                        "Portfolio disagreement (z3: {}, cvc5: {}).",
                        liveness_result_kind(a),
                        liveness_result_kind(b)
                    ),
                },
                "none",
                "Solvers disagreed on liveness outcome; merged result is unknown.".to_string(),
            ),
        },
        (Ok(a), Err(e)) => (
            LivenessResult::Unknown {
                reason: format!(
                    "Portfolio incomplete: z3={}, cvc5 error={e}.",
                    liveness_result_kind(a)
                ),
            },
            "none",
            "cvc5 failed while z3 completed; merged result is unknown due to incomplete portfolio."
                .to_string(),
        ),
        (Err(e), Ok(b)) => (
            LivenessResult::Unknown {
                reason: format!(
                    "Portfolio incomplete: z3 error={e}, cvc5={}.",
                    liveness_result_kind(b)
                ),
            },
            "none",
            "z3 failed while cvc5 completed; merged result is unknown due to incomplete portfolio."
                .to_string(),
        ),
        (Err(e1), Err(e2)) => (
            LivenessResult::Unknown {
                reason: format!("Portfolio failed: z3 error={e1}; cvc5 error={e2}."),
            },
            "none",
            "Both portfolio solvers failed; merged result is unknown.".to_string(),
        ),
    };

    if let Some(obj) = details.as_object_mut() {
        obj.insert(
            "per_solver_outcomes".into(),
            json!({
                "z3": solver_outcome_json(&z3, liveness_result_kind),
                "cvc5": solver_outcome_json(&cvc5, liveness_result_kind),
            }),
        );
        obj.insert("selected_solver".into(), json!(selected_solver));
        obj.insert("merge_reason".into(), json!(merge_reason));
    }

    (final_result, details)
}

pub(crate) fn merge_portfolio_prove_results(
    z3: Result<UnboundedSafetyResult, String>,
    cvc5: Result<UnboundedSafetyResult, String>,
) -> (UnboundedSafetyResult, Value) {
    let mut details = json!({
        "mode": "portfolio",
        "merge_policy": portfolio_merge_policy(
            &["unsafe", "safe", "probabilistically_safe", "not_proved", "unknown"],
            "shortest_trace_then_lexicographic",
        ),
        "z3": solver_result_json(&z3, |r| json!({"result": unbounded_safety_result_kind(r), "output": format!("{r}")})),
        "cvc5": solver_result_json(&cvc5, |r| json!({"result": unbounded_safety_result_kind(r), "output": format!("{r}")})),
    });

    let (final_result, selected_solver, merge_reason) = match (&z3, &cvc5) {
        (
            Ok(UnboundedSafetyResult::Unsafe { trace: ta }),
            Ok(UnboundedSafetyResult::Unsafe { trace: tb }),
        ) => {
            if prefer_trace_a(ta, tb) {
                (
                    UnboundedSafetyResult::Unsafe { trace: ta.clone() },
                    "z3",
                    "Both solvers reported unsafe; selected z3 trace by deterministic shortest-trace/lexicographic tiebreak."
                        .to_string(),
                )
            } else {
                (
                    UnboundedSafetyResult::Unsafe { trace: tb.clone() },
                    "cvc5",
                    "Both solvers reported unsafe; selected cvc5 trace by deterministic shortest-trace/lexicographic tiebreak."
                        .to_string(),
                )
            }
        }
        (Ok(a), Ok(b)) => match (a, b) {
            (UnboundedSafetyResult::Safe { .. }, UnboundedSafetyResult::Safe { .. })
            | (
                UnboundedSafetyResult::Safe { .. },
                UnboundedSafetyResult::ProbabilisticallySafe { .. },
            )
            | (
                UnboundedSafetyResult::ProbabilisticallySafe { .. },
                UnboundedSafetyResult::Safe { .. },
            )
            | (
                UnboundedSafetyResult::ProbabilisticallySafe { .. },
                UnboundedSafetyResult::ProbabilisticallySafe { .. },
            ) => (
                a.clone(),
                "z3",
                "Both solvers returned safety-equivalent proof outcomes; selected z3 result by deterministic solver-order tie-break."
                    .to_string(),
            ),
            (
                UnboundedSafetyResult::NotProved {
                    max_k: ka,
                    cti: cti_a,
                },
                UnboundedSafetyResult::NotProved {
                    max_k: kb,
                    cti: cti_b,
                },
            ) => (
                UnboundedSafetyResult::NotProved {
                    max_k: (*ka).max(*kb),
                    cti: match (cti_a, cti_b) {
                        (Some(a), Some(b)) => {
                            if a.k >= b.k {
                                Some(a.clone())
                            } else {
                                Some(b.clone())
                            }
                        }
                        (Some(a), None) => Some(a.clone()),
                        (None, Some(b)) => Some(b.clone()),
                        (None, None) => None,
                    },
                },
                "both",
                "Both solvers returned not_proved; merged using deterministic max-k and highest-k CTI selection."
                    .to_string(),
            ),
            (
                UnboundedSafetyResult::Unknown { reason: ra },
                UnboundedSafetyResult::Unknown { reason: rb },
            ) => (
                UnboundedSafetyResult::Unknown {
                    reason: format!(
                        "Portfolio: both solvers inconclusive (z3: {ra}; cvc5: {rb})."
                    ),
                },
                "none",
                "Both solvers were inconclusive; merged result is unknown.".to_string(),
            ),
            _ => (
                UnboundedSafetyResult::Unknown {
                    reason: format!(
                        "Portfolio disagreement (z3: {}, cvc5: {}).",
                        unbounded_safety_result_kind(a),
                        unbounded_safety_result_kind(b)
                    ),
                },
                "none",
                "Solvers disagreed on unbounded safety outcome; merged result is unknown."
                    .to_string(),
            ),
        },
        (Ok(a), Err(e)) => (
            UnboundedSafetyResult::Unknown {
                reason: format!(
                    "Portfolio incomplete: z3={}, cvc5 error={e}.",
                    unbounded_safety_result_kind(a)
                ),
            },
            "none",
            "cvc5 failed while z3 completed; merged result is unknown due to incomplete portfolio."
                .to_string(),
        ),
        (Err(e), Ok(b)) => (
            UnboundedSafetyResult::Unknown {
                reason: format!(
                    "Portfolio incomplete: z3 error={e}, cvc5={}.",
                    unbounded_safety_result_kind(b)
                ),
            },
            "none",
            "z3 failed while cvc5 completed; merged result is unknown due to incomplete portfolio."
                .to_string(),
        ),
        (Err(e1), Err(e2)) => (
            UnboundedSafetyResult::Unknown {
                reason: format!("Portfolio failed: z3 error={e1}; cvc5 error={e2}."),
            },
            "none",
            "Both portfolio solvers failed; merged result is unknown.".to_string(),
        ),
    };

    if let Some(obj) = details.as_object_mut() {
        obj.insert(
            "per_solver_outcomes".into(),
            json!({
                "z3": solver_outcome_json(&z3, unbounded_safety_result_kind),
                "cvc5": solver_outcome_json(&cvc5, unbounded_safety_result_kind),
            }),
        );
        obj.insert("selected_solver".into(), json!(selected_solver));
        obj.insert("merge_reason".into(), json!(merge_reason));
    }

    (final_result, details)
}

pub(crate) fn merge_portfolio_fair_liveness_results(
    z3: Result<FairLivenessResult, String>,
    cvc5: Result<FairLivenessResult, String>,
) -> (FairLivenessResult, Value) {
    let mut details = json!({
        "mode": "portfolio",
        "merge_policy": portfolio_merge_policy(
            &["fair_cycle_found", "no_fair_cycle_up_to", "unknown"],
            "shortest_trace_then_lexicographic",
        ),
        "z3": solver_result_json(&z3, |r| json!({"result": fair_liveness_result_kind(r), "output": format!("{r}")})),
        "cvc5": solver_result_json(&cvc5, |r| json!({"result": fair_liveness_result_kind(r), "output": format!("{r}")})),
    });

    let (final_result, selected_solver, merge_reason) = match (&z3, &cvc5) {
        (
            Ok(FairLivenessResult::FairCycleFound {
                depth: da,
                loop_start: la,
                trace: ta,
            }),
            Ok(FairLivenessResult::FairCycleFound {
                depth: db,
                loop_start: lb,
                trace: tb,
            }),
        ) => {
            if prefer_trace_a(ta, tb) {
                (
                    FairLivenessResult::FairCycleFound {
                        depth: *da,
                        loop_start: *la,
                        trace: ta.clone(),
                    },
                    "z3",
                    "Both solvers found fair cycles; selected z3 trace by deterministic shortest-trace/lexicographic tiebreak."
                        .to_string(),
                )
            } else {
                (
                    FairLivenessResult::FairCycleFound {
                        depth: *db,
                        loop_start: *lb,
                        trace: tb.clone(),
                    },
                    "cvc5",
                    "Both solvers found fair cycles; selected cvc5 trace by deterministic shortest-trace/lexicographic tiebreak."
                        .to_string(),
                )
            }
        }
        (Ok(a), Ok(b)) => match (a, b) {
            (
                FairLivenessResult::NoFairCycleUpTo { depth_checked: da },
                FairLivenessResult::NoFairCycleUpTo { depth_checked: db },
            ) => (
                FairLivenessResult::NoFairCycleUpTo {
                    depth_checked: (*da).min(*db),
                },
                "both",
                "Both solvers found no fair cycle; selected conservative minimum checked depth."
                    .to_string(),
            ),
            (
                FairLivenessResult::Unknown { reason: ra },
                FairLivenessResult::Unknown { reason: rb },
            ) => (
                FairLivenessResult::Unknown {
                    reason: format!("Portfolio: both solvers inconclusive (z3: {ra}; cvc5: {rb})."),
                },
                "none",
                "Both solvers were inconclusive; merged result is unknown.".to_string(),
            ),
            _ => (
                FairLivenessResult::Unknown {
                    reason: format!(
                        "Portfolio disagreement (z3: {}, cvc5: {}).",
                        fair_liveness_result_kind(a),
                        fair_liveness_result_kind(b)
                    ),
                },
                "none",
                "Solvers disagreed on fair-liveness outcome; merged result is unknown.".to_string(),
            ),
        },
        (Ok(a), Err(e)) => (
            FairLivenessResult::Unknown {
                reason: format!(
                    "Portfolio incomplete: z3={}, cvc5 error={e}.",
                    fair_liveness_result_kind(a)
                ),
            },
            "none",
            "cvc5 failed while z3 completed; merged result is unknown due to incomplete portfolio."
                .to_string(),
        ),
        (Err(e), Ok(b)) => (
            FairLivenessResult::Unknown {
                reason: format!(
                    "Portfolio incomplete: z3 error={e}, cvc5={}.",
                    fair_liveness_result_kind(b)
                ),
            },
            "none",
            "z3 failed while cvc5 completed; merged result is unknown due to incomplete portfolio."
                .to_string(),
        ),
        (Err(e1), Err(e2)) => (
            FairLivenessResult::Unknown {
                reason: format!("Portfolio failed: z3 error={e1}; cvc5 error={e2}."),
            },
            "none",
            "Both portfolio solvers failed; merged result is unknown.".to_string(),
        ),
    };

    if let Some(obj) = details.as_object_mut() {
        obj.insert(
            "per_solver_outcomes".into(),
            json!({
                "z3": solver_outcome_json(&z3, fair_liveness_result_kind),
                "cvc5": solver_outcome_json(&cvc5, fair_liveness_result_kind),
            }),
        );
        obj.insert("selected_solver".into(), json!(selected_solver));
        obj.insert("merge_reason".into(), json!(merge_reason));
    }

    (final_result, details)
}

pub(crate) fn merge_portfolio_prove_fair_results(
    z3: Result<UnboundedFairLivenessResult, String>,
    cvc5: Result<UnboundedFairLivenessResult, String>,
) -> (UnboundedFairLivenessResult, Value) {
    let mut details = json!({
        "mode": "portfolio",
        "merge_policy": portfolio_merge_policy(
            &["fair_cycle_found", "live_proved", "not_proved", "unknown"],
            "shortest_trace_then_lexicographic",
        ),
        "z3": solver_result_json(&z3, |r| json!({
            "result": unbounded_fair_result_kind(r),
            "details": unbounded_fair_result_details(r),
            "output": format!("{r}"),
        })),
        "cvc5": solver_result_json(&cvc5, |r| json!({
            "result": unbounded_fair_result_kind(r),
            "details": unbounded_fair_result_details(r),
            "output": format!("{r}"),
        })),
    });

    let (final_result, selected_solver, merge_reason) = match (&z3, &cvc5) {
        (
            Ok(UnboundedFairLivenessResult::FairCycleFound {
                depth: da,
                loop_start: la,
                trace: ta,
            }),
            Ok(UnboundedFairLivenessResult::FairCycleFound {
                depth: db,
                loop_start: lb,
                trace: tb,
            }),
        ) => {
            if prefer_trace_a(ta, tb) {
                (
                    UnboundedFairLivenessResult::FairCycleFound {
                        depth: *da,
                        loop_start: *la,
                        trace: ta.clone(),
                    },
                    "z3",
                    "Both solvers found fair-cycle counterexamples; selected z3 trace by deterministic shortest-trace/lexicographic tiebreak."
                        .to_string(),
                )
            } else {
                (
                    UnboundedFairLivenessResult::FairCycleFound {
                        depth: *db,
                        loop_start: *lb,
                        trace: tb.clone(),
                    },
                    "cvc5",
                    "Both solvers found fair-cycle counterexamples; selected cvc5 trace by deterministic shortest-trace/lexicographic tiebreak."
                        .to_string(),
                )
            }
        }
        (Ok(a), Ok(b)) => match (a, b) {
            (
                UnboundedFairLivenessResult::LiveProved { frame: fa },
                UnboundedFairLivenessResult::LiveProved { frame: fb },
            ) => (
                UnboundedFairLivenessResult::LiveProved {
                    frame: (*fa).max(*fb),
                },
                "both",
                "Both solvers proved liveness; selected stronger max frame.".to_string(),
            ),
            (
                UnboundedFairLivenessResult::NotProved { max_k: ka },
                UnboundedFairLivenessResult::NotProved { max_k: kb },
            ) => (
                UnboundedFairLivenessResult::NotProved {
                    max_k: (*ka).max(*kb),
                },
                "both",
                "Both solvers returned not_proved; selected deterministic max-k bound.".to_string(),
            ),
            (
                UnboundedFairLivenessResult::Unknown { reason: ra },
                UnboundedFairLivenessResult::Unknown { reason: rb },
            ) => (
                UnboundedFairLivenessResult::Unknown {
                    reason: format!("Portfolio: both solvers inconclusive (z3: {ra}; cvc5: {rb})."),
                },
                "none",
                "Both solvers were inconclusive; merged result is unknown.".to_string(),
            ),
            _ => (
                UnboundedFairLivenessResult::Unknown {
                    reason: format!(
                        "Portfolio disagreement (z3: {}, cvc5: {}).",
                        unbounded_fair_result_kind(a),
                        unbounded_fair_result_kind(b)
                    ),
                },
                "none",
                "Solvers disagreed on unbounded fair-liveness outcome; merged result is unknown."
                    .to_string(),
            ),
        },
        (Ok(a), Err(e)) => (
            UnboundedFairLivenessResult::Unknown {
                reason: format!(
                    "Portfolio incomplete: z3={}, cvc5 error={e}.",
                    unbounded_fair_result_kind(a)
                ),
            },
            "none",
            "cvc5 failed while z3 completed; merged result is unknown due to incomplete portfolio."
                .to_string(),
        ),
        (Err(e), Ok(b)) => (
            UnboundedFairLivenessResult::Unknown {
                reason: format!(
                    "Portfolio incomplete: z3 error={e}, cvc5={}.",
                    unbounded_fair_result_kind(b)
                ),
            },
            "none",
            "z3 failed while cvc5 completed; merged result is unknown due to incomplete portfolio."
                .to_string(),
        ),
        (Err(e1), Err(e2)) => (
            UnboundedFairLivenessResult::Unknown {
                reason: format!("Portfolio failed: z3 error={e1}; cvc5 error={e2}."),
            },
            "none",
            "Both portfolio solvers failed; merged result is unknown.".to_string(),
        ),
    };

    if let Some(obj) = details.as_object_mut() {
        obj.insert(
            "per_solver_outcomes".into(),
            json!({
                "z3": solver_outcome_json(&z3, unbounded_fair_result_kind),
                "cvc5": solver_outcome_json(&cvc5, unbounded_fair_result_kind),
            }),
        );
        obj.insert("selected_solver".into(), json!(selected_solver));
        obj.insert("merge_reason".into(), json!(merge_reason));
    }

    (final_result, details)
}

// ---------------------------------------------------------------------------
// Command handlers
// ---------------------------------------------------------------------------

/// Run the `verify` CLI command.
///
/// Performs bounded model checking (BMC) with optional CEGAR refinement on the
/// given protocol file, optionally using portfolio (Z3 + cvc5) mode.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_verify_command(
    file: PathBuf,
    solver: String,
    depth: usize,
    timeout: u64,
    soundness: String,
    dump_smt: Option<String>,
    cegar_iters: usize,
    cegar_report_out: Option<PathBuf>,
    portfolio: bool,
    format: String,
    cli_network_mode: CliNetworkSemanticsMode,
) -> miette::Result<()> {
    let output_format = parse_output_format(&format);
    let source = sandbox_read_source(&file)?;
    let filename = file.display().to_string();
    let soundness_mode = parse_soundness_mode(&soundness);
    validate_cli_network_semantics_mode(&source, &filename, soundness_mode, cli_network_mode)?;
    let network_faithfulness =
        network_faithfulness_section(&source, &filename, cli_network_mode, soundness_mode);

    let options = PipelineOptions {
        solver: parse_solver_choice(&solver),
        max_depth: depth,
        timeout_secs: timeout,
        dump_smt,
        soundness: soundness_mode,
        proof_engine: ProofEngine::KInduction,
    };

    if portfolio {
        let mut z3_options = options.clone();
        z3_options.solver = SolverChoice::Z3;
        let mut cvc5_options = options.clone();
        cvc5_options.solver = SolverChoice::Cvc5;

        let src_z3 = source.clone();
        let file_z3 = filename.clone();
        let handle_z3 = std::thread::spawn(move || {
            let result = tarsier_engine::pipeline::verify_with_cegar_report(
                &src_z3,
                &file_z3,
                &z3_options,
                cegar_iters,
            )
            .map_err(|e| e.to_string());
            let diagnostics = take_run_diagnostics();
            (result, diagnostics)
        });

        let src_cvc5 = source.clone();
        let file_cvc5 = filename.clone();
        let handle_cvc5 = std::thread::spawn(move || {
            let result = tarsier_engine::pipeline::verify_with_cegar_report(
                &src_cvc5,
                &file_cvc5,
                &cvc5_options,
                cegar_iters,
            )
            .map_err(|e| e.to_string());
            let diagnostics = take_run_diagnostics();
            (result, diagnostics)
        });

        let (z3_result, z3_diag): (
            Result<tarsier_engine::result::CegarAuditReport, String>,
            Option<PipelineRunDiagnostics>,
        ) = match handle_z3.join() {
            Ok((res, diag)) => (res, Some(diag)),
            Err(_) => (Err("thread panicked".into()), None),
        };
        let (cvc5_result, cvc5_diag): (
            Result<tarsier_engine::result::CegarAuditReport, String>,
            Option<PipelineRunDiagnostics>,
        ) = match handle_cvc5.join() {
            Ok((res, diag)) => (res, Some(diag)),
            Err(_) => (Err("thread panicked".into()), None),
        };

        let (final_result, portfolio_details) =
            merge_portfolio_verify_reports(z3_result, cvc5_result);
        match output_format {
            OutputFormat::Json => {
                let artifact = json!({
                    "schema_version": 1,
                    "file": filename,
                    "result": verification_result_kind(&final_result),
                    "details": verification_result_details(&final_result),
                    "output": format!("{final_result}"),
                    "portfolio": portfolio_details,
                    "network_faithfulness": network_faithfulness,
                    "abstractions": {
                        "z3": z3_diag.as_ref().map(run_diagnostics_details),
                        "cvc5": cvc5_diag.as_ref().map(run_diagnostics_details),
                    },
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&artifact).into_diagnostic()?
                );
            }
            OutputFormat::Text => {
                println!("{final_result}");
                for (label, solver_diag) in [("z3", &z3_diag), ("cvc5", &cvc5_diag)] {
                    if let Some(d) = solver_diag {
                        if let Some(opt) = render_optimization_summary(d) {
                            eprintln!("[{label}] {opt}");
                        }
                        if let Some(fb) = render_fallback_summary(d) {
                            eprintln!("[{label}] {fb}");
                        }
                        if let Some(pp) = render_phase_profile_summary(d) {
                            eprintln!("[{label}] {pp}");
                        }
                    }
                }
            }
        }
        if let Some(out) = cegar_report_out {
            let artifact = json!({
                "schema_version": 1,
                "file": filename,
                "result": verification_result_kind(&final_result),
                "output": format!("{final_result}"),
                "portfolio": portfolio_details,
                "network_faithfulness": network_faithfulness,
                "abstractions": {
                    "z3": z3_diag.as_ref().map(run_diagnostics_details),
                    "cvc5": cvc5_diag.as_ref().map(run_diagnostics_details),
                },
            });
            write_json_artifact(&out, &artifact)?;
            if matches!(output_format, OutputFormat::Text) {
                println!("Portfolio CEGAR report written to {}", out.display());
            }
        }
    } else {
        match tarsier_engine::pipeline::verify_with_cegar_report(
            &source,
            &filename,
            &options,
            cegar_iters,
        ) {
            Ok(report) => {
                let diagnostics = take_run_diagnostics();
                match output_format {
                    OutputFormat::Json => {
                        let artifact = json!({
                            "schema_version": 1,
                            "file": filename,
                            "result": verification_result_kind(&report.final_result),
                            "details": verification_result_details(&report.final_result),
                            "output": format!("{}", report.final_result),
                            "cegar": cegar_report_details(&report),
                            "network_faithfulness": network_faithfulness,
                            "abstractions": run_diagnostics_details(&diagnostics),
                        });
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&artifact).into_diagnostic()?
                        );
                    }
                    OutputFormat::Text => {
                        println!("{}", report.final_result);
                        if let Some(opt) = render_optimization_summary(&diagnostics) {
                            eprintln!("{opt}");
                        }
                        if let Some(fb) = render_fallback_summary(&diagnostics) {
                            eprintln!("{fb}");
                        }
                        if let Some(pp) = render_phase_profile_summary(&diagnostics) {
                            eprintln!("{pp}");
                        }
                    }
                }
                if let Some(out) = cegar_report_out {
                    let artifact = json!({
                        "schema_version": 1,
                        "file": filename,
                        "result": verification_result_kind(&report.final_result),
                        "output": format!("{}", report.final_result),
                        "cegar": cegar_report_details(&report),
                        "network_faithfulness": network_faithfulness,
                        "abstractions": run_diagnostics_details(&diagnostics),
                    });
                    write_json_artifact(&out, &artifact)?;
                    if matches!(output_format, OutputFormat::Text) {
                        println!("CEGAR report written to {}", out.display());
                    }
                }
            }
            Err(e) => {
                match output_format {
                    OutputFormat::Json => {
                        let err = json!({"error": e.to_string()});
                        println!("{}", serde_json::to_string_pretty(&err).into_diagnostic()?);
                    }
                    OutputFormat::Text => {
                        eprintln!("Error: {e}");
                    }
                }
                std::process::exit(1);
            }
        }
    }

    Ok(())
}

/// Run the `round-sweep` CLI command.
///
/// Sweeps round/view upper bounds over a range and reports verdict convergence,
/// detecting a candidate cutoff where the result stabilizes.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_round_sweep_command(
    file: PathBuf,
    solver: String,
    depth: usize,
    timeout: u64,
    soundness: String,
    vars: Vec<String>,
    min_bound: i64,
    max_bound: i64,
    stable_window: usize,
    format: String,
    out: Option<PathBuf>,
    cli_network_mode: CliNetworkSemanticsMode,
) -> miette::Result<()> {
    if min_bound > max_bound {
        miette::bail!("min_bound must be <= max_bound");
    }
    if stable_window == 0 {
        miette::bail!("stable_window must be >= 1");
    }
    if vars.is_empty() {
        miette::bail!("Provide at least one variable name with --vars.");
    }

    let source = sandbox_read_source(&file)?;
    let filename = file.display().to_string();
    let soundness_mode = parse_soundness_mode(&soundness);
    validate_cli_network_semantics_mode(&source, &filename, soundness_mode, cli_network_mode)?;
    let base_program = tarsier_engine::pipeline::parse(&source, &filename).into_diagnostic()?;
    let options = PipelineOptions {
        solver: parse_solver_choice(&solver),
        max_depth: depth,
        timeout_secs: timeout,
        dump_smt: None,
        soundness: soundness_mode,
        proof_engine: ProofEngine::KInduction,
    };

    let mut points: Vec<RoundSweepPoint> = Vec::new();
    let mut applied_target_count: Option<usize> = None;

    for upper_bound in min_bound..=max_bound {
        let mut program = base_program.clone();
        let stats = apply_round_upper_bound(&mut program, &vars, upper_bound);
        if stats.matched_targets == 0 {
            miette::bail!(
                "No bounded variables/fields matched {:?}. Ensure the model declares ranges for these names.",
                vars
            );
        }
        if !stats.unbounded_targets.is_empty() {
            miette::bail!(
                "Round sweep targets must be bounded (`in a..b`). Add bounds for: {}",
                stats.unbounded_targets.join(", ")
            );
        }
        applied_target_count = Some(stats.updated_ranges);

        let result =
            tarsier_engine::pipeline::verify_program_ast(&program, &options).into_diagnostic()?;
        points.push(RoundSweepPoint {
            upper_bound,
            result: verification_result_kind(&result).to_string(),
            details: verification_result_details(&result),
        });
    }

    let (candidate_cutoff, stabilized_result) =
        if let Some((cutoff, kind)) = detect_round_sweep_cutoff(&points, stable_window) {
            (Some(cutoff), Some(kind))
        } else {
            (None, None)
        };

    let report = RoundSweepReport {
        schema_version: 1,
        file: filename.clone(),
        vars: vars.clone(),
        min_bound,
        max_bound,
        stable_window,
        points,
        candidate_cutoff,
        stabilized_result,
        note: format!(
            "Convergence is empirical over bounded runs ({} targeted ranges mutated). Treat as cutoff evidence, not a universal proof.",
            applied_target_count.unwrap_or(0)
        ),
    };

    match parse_output_format(&format) {
        OutputFormat::Text => {
            println!("{}", render_round_sweep_text(&report));
        }
        OutputFormat::Json => {
            let value = serde_json::to_value(&report).into_diagnostic()?;
            if let Some(path) = out {
                write_json_artifact(&path, &value)?;
                println!("Round sweep report written to {}", path.display());
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&value).into_diagnostic()?
                );
            }
        }
    }

    Ok(())
}

/// Run the `liveness` CLI command.
///
/// Checks bounded liveness: whether all processes satisfy the liveness target
/// by the given depth.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_liveness_command(
    file: PathBuf,
    solver: String,
    depth: usize,
    timeout: u64,
    soundness: String,
    dump_smt: Option<String>,
    format: String,
    cli_network_mode: CliNetworkSemanticsMode,
) -> miette::Result<()> {
    let source = sandbox_read_source(&file)?;
    let filename = file.display().to_string();
    let soundness_mode = parse_soundness_mode(&soundness);
    let output_format = parse_output_format(&format);
    validate_cli_network_semantics_mode(&source, &filename, soundness_mode, cli_network_mode)?;

    let options = PipelineOptions {
        solver: parse_solver_choice(&solver),
        max_depth: depth,
        timeout_secs: timeout,
        dump_smt,
        soundness: soundness_mode,
        proof_engine: ProofEngine::KInduction,
    };

    match tarsier_engine::pipeline::check_liveness(&source, &filename, &options) {
        Ok(result) => match output_format {
            OutputFormat::Json => {
                let artifact = json!({
                    "schema_version": 1,
                    "file": filename,
                    "result": liveness_result_kind(&result),
                    "details": liveness_result_details(&result),
                    "output": format!("{result}"),
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&artifact).into_diagnostic()?
                );
            }
            OutputFormat::Text => {
                println!("{result}");
            }
        },
        Err(e) => {
            match output_format {
                OutputFormat::Json => {
                    let err = json!({"error": e.to_string()});
                    println!("{}", serde_json::to_string_pretty(&err).into_diagnostic()?);
                }
                OutputFormat::Text => {
                    eprintln!("Error: {e}");
                }
            }
            std::process::exit(1);
        }
    }

    Ok(())
}

/// Run the `fair-liveness` CLI command.
///
/// Searches for bounded fair non-termination lassos, optionally using
/// portfolio (Z3 + cvc5) mode.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_fair_liveness_command(
    file: PathBuf,
    solver: String,
    depth: usize,
    timeout: u64,
    soundness: String,
    fairness: String,
    portfolio: bool,
    format: String,
    cli_network_mode: CliNetworkSemanticsMode,
) -> miette::Result<()> {
    let source = sandbox_read_source(&file)?;
    let filename = file.display().to_string();
    let soundness_mode = parse_soundness_mode(&soundness);
    let output_format = parse_output_format(&format);
    validate_cli_network_semantics_mode(&source, &filename, soundness_mode, cli_network_mode)?;

    let options = make_options(parse_solver_choice(&solver), depth, timeout, soundness_mode);
    let fairness = parse_fairness_mode(&fairness);
    if portfolio {
        let mut z3_options = options.clone();
        z3_options.solver = SolverChoice::Z3;
        let mut cvc5_options = options.clone();
        cvc5_options.solver = SolverChoice::Cvc5;

        let src_z3 = source.clone();
        let file_z3 = filename.clone();
        let handle_z3 = std::thread::spawn(move || {
            tarsier_engine::pipeline::check_fair_liveness_with_mode(
                &src_z3,
                &file_z3,
                &z3_options,
                fairness,
            )
            .map_err(|e| e.to_string())
        });

        let src_cvc5 = source.clone();
        let file_cvc5 = filename.clone();
        let handle_cvc5 = std::thread::spawn(move || {
            tarsier_engine::pipeline::check_fair_liveness_with_mode(
                &src_cvc5,
                &file_cvc5,
                &cvc5_options,
                fairness,
            )
            .map_err(|e| e.to_string())
        });

        let z3_result: Result<FairLivenessResult, String> = match handle_z3.join() {
            Ok(res) => res,
            Err(_) => Err("thread panicked".into()),
        };
        let cvc5_result: Result<FairLivenessResult, String> = match handle_cvc5.join() {
            Ok(res) => res,
            Err(_) => Err("thread panicked".into()),
        };
        let (result, details) = merge_portfolio_fair_liveness_results(z3_result, cvc5_result);
        match output_format {
            OutputFormat::Json => {
                let artifact = json!({
                    "schema_version": 1,
                    "file": filename,
                    "result": fair_liveness_result_kind(&result),
                    "details": fair_liveness_result_details(&result),
                    "output": format!("{result}"),
                    "portfolio": details,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&artifact).into_diagnostic()?
                );
            }
            OutputFormat::Text => {
                println!("{result}");
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({"portfolio": details}))
                        .into_diagnostic()?
                );
            }
        }
    } else {
        match tarsier_engine::pipeline::check_fair_liveness_with_mode(
            &source, &filename, &options, fairness,
        ) {
            Ok(result) => match output_format {
                OutputFormat::Json => {
                    let artifact = json!({
                        "schema_version": 1,
                        "file": filename,
                        "result": fair_liveness_result_kind(&result),
                        "details": fair_liveness_result_details(&result),
                        "output": format!("{result}"),
                    });
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&artifact).into_diagnostic()?
                    );
                }
                OutputFormat::Text => {
                    println!("{result}");
                }
            },
            Err(e) => {
                match output_format {
                    OutputFormat::Json => {
                        let err = json!({"error": e.to_string()});
                        println!("{}", serde_json::to_string_pretty(&err).into_diagnostic()?);
                    }
                    OutputFormat::Text => {
                        eprintln!("Error: {e}");
                    }
                }
                std::process::exit(1);
            }
        }
    }

    Ok(())
}

/// Run the `comm` CLI command.
///
/// Computes the communication complexity of the protocol at the given depth.
pub(crate) fn run_comm_command(
    file: PathBuf,
    depth: usize,
    format: String,
    out: Option<PathBuf>,
    cli_network_mode: CliNetworkSemanticsMode,
) -> miette::Result<()> {
    let source = sandbox_read_source(&file)?;
    let filename = file.display().to_string();
    validate_cli_network_semantics_mode(
        &source,
        &filename,
        tarsier_engine::pipeline::SoundnessMode::Strict,
        cli_network_mode,
    )?;
    let output_format = parse_output_format(&format);

    match tarsier_engine::pipeline::comm_complexity(&source, &filename, depth) {
        Ok(report) => {
            let report_json_value = serde_json::to_value(&report).into_diagnostic()?;
            if let Some(path) = out.as_ref() {
                write_json_artifact(path, &report_json_value)?;
                println!("Communication report written to {}", path.display());
            }

            match output_format {
                OutputFormat::Text => {
                    println!("{report}");
                }
                OutputFormat::Json => {
                    let json =
                        serde_json::to_string_pretty(&report_json_value).into_diagnostic()?;
                    println!("{json}");
                }
            }
        }
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }
    Ok(())
}
