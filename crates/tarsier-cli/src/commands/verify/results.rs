use serde_json::{json, Value};

use tarsier_engine::pipeline::PipelineRunDiagnostics;
use tarsier_engine::result::{
    FairLivenessResult, InductionCtiSummary, LivenessResult, LivenessUnknownReason,
    UnboundedFairLivenessResult, UnboundedSafetyResult, VerificationResult,
};
use tarsier_ir::counter_system::Trace;

pub(crate) fn trace_details(trace: &Trace) -> Value {
    let deliveries: i64 = trace
        .steps
        .iter()
        .flat_map(|step| step.deliveries.iter())
        .filter(|delivery| delivery.kind == tarsier_ir::counter_system::MessageEventKind::Deliver)
        .map(|delivery| delivery.count)
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
        let total_solve_calls: u64 = diag
            .smt_profiles
            .iter()
            .map(|profile| profile.solve_calls)
            .sum();
        let total_solve_elapsed_ms: u128 = diag
            .smt_profiles
            .iter()
            .map(|profile| profile.solve_elapsed_ms)
            .sum();
        let total_encode_elapsed_ms: u128 = diag
            .smt_profiles
            .iter()
            .map(|profile| profile.encode_elapsed_ms)
            .sum();
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
