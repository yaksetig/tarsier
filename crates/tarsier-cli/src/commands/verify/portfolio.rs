use std::fs;
use std::path::PathBuf;

use miette::IntoDiagnostic;
use serde_json::{json, Value};

use tarsier_engine::result::{
    CegarAuditReport, FairLivenessResult, LivenessResult, UnboundedFairLivenessResult,
    UnboundedSafetyResult, VerificationResult,
};
use tarsier_ir::counter_system::Trace;

use super::{
    cegar_report_details, fair_liveness_result_kind, liveness_result_kind, trace_json,
    unbounded_fair_result_details, unbounded_fair_result_kind, unbounded_safety_result_kind,
    verification_result_kind,
};

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
        Ok(value) => json!({"status": "ok", "data": render_ok(value)}),
        Err(error) => json!({"status": "error", "error": error}),
    }
}

pub(crate) fn solver_outcome_json<T>(
    res: &Result<T, String>,
    result_kind: impl Fn(&T) -> &'static str,
) -> Value {
    match res {
        Ok(value) => json!({"status": "ok", "result": result_kind(value)}),
        Err(error) => json!({"status": "error", "error": error}),
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

pub(crate) fn merge_portfolio_verify_reports(
    z3: Result<CegarAuditReport, String>,
    cvc5: Result<CegarAuditReport, String>,
) -> (VerificationResult, Value) {
    let mut details = json!({
        "mode": "portfolio",
        "merge_policy": portfolio_merge_policy(
            &["unsafe", "safe", "probabilistically_safe", "unknown"],
            "shortest_trace_then_lexicographic",
        ),
        "z3": solver_result_json(&z3, |report| json!({
            "result": verification_result_kind(&report.final_result),
            "cegar": cegar_report_details(report),
        })),
        "cvc5": solver_result_json(&cvc5, |report| json!({
            "result": verification_result_kind(&report.final_result),
            "cegar": cegar_report_details(report),
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
        (Ok(z), Err(error)) => (
            VerificationResult::Unknown {
                reason: format!(
                    "Portfolio incomplete: z3={}, cvc5 error={error}.",
                    verification_result_kind(&z.final_result)
                ),
            },
            "none",
            "cvc5 failed while z3 completed; merged result is unknown due to incomplete portfolio."
                .to_string(),
        ),
        (Err(error), Ok(c)) => (
            VerificationResult::Unknown {
                reason: format!(
                    "Portfolio incomplete: z3 error={error}, cvc5={}.",
                    verification_result_kind(&c.final_result)
                ),
            },
            "none",
            "z3 failed while cvc5 completed; merged result is unknown due to incomplete portfolio."
                .to_string(),
        ),
        (Err(error_a), Err(error_b)) => (
            VerificationResult::Unknown {
                reason: format!("Portfolio failed: z3 error={error_a}; cvc5 error={error_b}."),
            },
            "none",
            "Both portfolio solvers failed; merged result is unknown.".to_string(),
        ),
    };

    if let Some(obj) = details.as_object_mut() {
        obj.insert(
            "per_solver_outcomes".into(),
            json!({
                "z3": solver_outcome_json(&z3, |report| verification_result_kind(&report.final_result)),
                "cvc5": solver_outcome_json(&cvc5, |report| verification_result_kind(&report.final_result)),
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
        "z3": solver_result_json(&z3, |result| json!({"result": liveness_result_kind(result), "output": format!("{result}")})),
        "cvc5": solver_result_json(&cvc5, |result| json!({"result": liveness_result_kind(result), "output": format!("{result}")})),
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
        (Ok(a), Err(error)) => (
            LivenessResult::Unknown {
                reason: format!(
                    "Portfolio incomplete: z3={}, cvc5 error={error}.",
                    liveness_result_kind(a)
                ),
            },
            "none",
            "cvc5 failed while z3 completed; merged result is unknown due to incomplete portfolio."
                .to_string(),
        ),
        (Err(error), Ok(b)) => (
            LivenessResult::Unknown {
                reason: format!(
                    "Portfolio incomplete: z3 error={error}, cvc5={}.",
                    liveness_result_kind(b)
                ),
            },
            "none",
            "z3 failed while cvc5 completed; merged result is unknown due to incomplete portfolio."
                .to_string(),
        ),
        (Err(error_a), Err(error_b)) => (
            LivenessResult::Unknown {
                reason: format!("Portfolio failed: z3 error={error_a}; cvc5 error={error_b}."),
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
        "z3": solver_result_json(&z3, |result| json!({"result": unbounded_safety_result_kind(result), "output": format!("{result}")})),
        "cvc5": solver_result_json(&cvc5, |result| json!({"result": unbounded_safety_result_kind(result), "output": format!("{result}")})),
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
        (Ok(a), Err(error)) => (
            UnboundedSafetyResult::Unknown {
                reason: format!(
                    "Portfolio incomplete: z3={}, cvc5 error={error}.",
                    unbounded_safety_result_kind(a)
                ),
            },
            "none",
            "cvc5 failed while z3 completed; merged result is unknown due to incomplete portfolio."
                .to_string(),
        ),
        (Err(error), Ok(b)) => (
            UnboundedSafetyResult::Unknown {
                reason: format!(
                    "Portfolio incomplete: z3 error={error}, cvc5={}.",
                    unbounded_safety_result_kind(b)
                ),
            },
            "none",
            "z3 failed while cvc5 completed; merged result is unknown due to incomplete portfolio."
                .to_string(),
        ),
        (Err(error_a), Err(error_b)) => (
            UnboundedSafetyResult::Unknown {
                reason: format!("Portfolio failed: z3 error={error_a}; cvc5 error={error_b}."),
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
        "z3": solver_result_json(&z3, |result| json!({"result": fair_liveness_result_kind(result), "output": format!("{result}")})),
        "cvc5": solver_result_json(&cvc5, |result| json!({"result": fair_liveness_result_kind(result), "output": format!("{result}")})),
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
        (Ok(a), Err(error)) => (
            FairLivenessResult::Unknown {
                reason: format!(
                    "Portfolio incomplete: z3={}, cvc5 error={error}.",
                    fair_liveness_result_kind(a)
                ),
            },
            "none",
            "cvc5 failed while z3 completed; merged result is unknown due to incomplete portfolio."
                .to_string(),
        ),
        (Err(error), Ok(b)) => (
            FairLivenessResult::Unknown {
                reason: format!(
                    "Portfolio incomplete: z3 error={error}, cvc5={}.",
                    fair_liveness_result_kind(b)
                ),
            },
            "none",
            "z3 failed while cvc5 completed; merged result is unknown due to incomplete portfolio."
                .to_string(),
        ),
        (Err(error_a), Err(error_b)) => (
            FairLivenessResult::Unknown {
                reason: format!("Portfolio failed: z3 error={error_a}; cvc5 error={error_b}."),
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
        "z3": solver_result_json(&z3, |result| json!({
            "result": unbounded_fair_result_kind(result),
            "details": unbounded_fair_result_details(result),
            "output": format!("{result}"),
        })),
        "cvc5": solver_result_json(&cvc5, |result| json!({
            "result": unbounded_fair_result_kind(result),
            "details": unbounded_fair_result_details(result),
            "output": format!("{result}"),
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
        (Ok(a), Err(error)) => (
            UnboundedFairLivenessResult::Unknown {
                reason: format!(
                    "Portfolio incomplete: z3={}, cvc5 error={error}.",
                    unbounded_fair_result_kind(a)
                ),
            },
            "none",
            "cvc5 failed while z3 completed; merged result is unknown due to incomplete portfolio."
                .to_string(),
        ),
        (Err(error), Ok(b)) => (
            UnboundedFairLivenessResult::Unknown {
                reason: format!(
                    "Portfolio incomplete: z3 error={error}, cvc5={}.",
                    unbounded_fair_result_kind(b)
                ),
            },
            "none",
            "z3 failed while cvc5 completed; merged result is unknown due to incomplete portfolio."
                .to_string(),
        ),
        (Err(error_a), Err(error_b)) => (
            UnboundedFairLivenessResult::Unknown {
                reason: format!("Portfolio failed: z3 error={error_a}; cvc5 error={error_b}."),
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
