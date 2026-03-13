use serde_json::{json, Value};

use tarsier_engine::result::{
    CegarAuditReport, CegarCounterexampleAnalysis, CegarEliminatedTrace, CegarLassoWitness,
    CegarModelChange, CegarRunControls, CegarStageOutcome, UnboundedFairLivenessCegarAuditReport,
    UnboundedFairLivenessCegarStageOutcome, UnboundedSafetyCegarAuditReport,
    UnboundedSafetyCegarStageOutcome,
};
use tarsier_proof_kernel::sha256_hex_bytes;

use super::{
    cti_details, liveness_unknown_reason_payload, trace_json, unbounded_fair_result_details,
    unbounded_fair_result_kind, unbounded_safety_result_details, unbounded_safety_result_kind,
    verification_result_kind,
};

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

pub(crate) fn cegar_model_change_json(change: &CegarModelChange) -> Value {
    json!({
        "category": change.category,
        "target": change.target,
        "before": change.before,
        "after": change.after,
        "predicate": change.predicate,
    })
}

pub(crate) fn cegar_eliminated_trace_json(trace: &CegarEliminatedTrace) -> Value {
    json!({
        "kind": trace.kind,
        "source_stage": trace.source_stage,
        "eliminated_by": trace.eliminated_by,
        "rationale": trace.rationale,
        "trace": trace_json(&trace.trace),
    })
}

pub(crate) fn cegar_lasso_witness_json(witness: &CegarLassoWitness) -> Value {
    json!({
        "depth": witness.depth,
        "loop_start": witness.loop_start,
        "loop_len": witness.loop_len,
        "prefix_len": witness.prefix_len,
        "trace_steps": witness.trace_steps,
        "loop_rule_ids": witness.loop_rule_ids,
        "param_values": witness.param_values.iter().map(|(name, value)| {
            json!({"name": name, "value": value})
        }).collect::<Vec<_>>(),
        "loop_steps": witness.loop_steps.iter().map(|step| {
            json!({
                "smt_step": step.smt_step,
                "rule_id": step.rule_id,
                "delta": step.delta,
            })
        }).collect::<Vec<_>>(),
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
                "lasso_witness": stage.lasso_witness.as_ref().map(cegar_lasso_witness_json),
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
