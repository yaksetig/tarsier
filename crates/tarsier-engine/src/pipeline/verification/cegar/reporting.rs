//! CEGAR reporting, witness extraction, and stage-diff utilities.

use super::*;

pub(crate) fn cegar_signals_note(signals: &CegarTraceSignals) -> Option<String> {
    let tags = cegar_signal_tags(signals);
    if tags.is_empty() {
        None
    } else {
        Some(format!("Adaptive CEGAR trace signals: {}", tags.join(", ")))
    }
}

pub(crate) fn cegar_signal_tags(signals: &CegarTraceSignals) -> Vec<&'static str> {
    let mut tags = Vec::new();
    if signals.conflicting_variants {
        tags.push("conflicting_variants");
    }
    if signals.cross_recipient_delivery {
        tags.push("cross_recipient_delivery");
    }
    if signals.sign_abstract_values {
        tags.push("sign_abstract_values");
    }
    if signals.identity_scoped_channels {
        tags.push("identity_scoped_channels");
    }
    tags
}

pub(crate) fn cegar_stage_counterexample_analysis(
    stage: usize,
    refinements: &[String],
    result: &VerificationResult,
    baseline_is_unsafe: bool,
    baseline_signals: Option<&CegarTraceSignals>,
) -> Option<CegarCounterexampleAnalysis> {
    if !baseline_is_unsafe {
        return None;
    }
    let refinements_text = if refinements.is_empty() {
        "(none)".to_string()
    } else {
        refinements.join(", ")
    };
    let signal_text = baseline_signals
        .map(cegar_signal_tags)
        .filter(|tags| !tags.is_empty())
        .map(|tags| tags.join(", "));
    match result {
        VerificationResult::Unsafe { .. } => {
            let mut rationale = if stage == 0 {
                "Baseline stage reported UNSAFE before refinement replay; witness starts as potentially spurious until checked under stricter assumptions.".to_string()
            } else {
                format!(
                    "Witness persists at stage {} under refinements [{}]. Because refinements only restrict behaviors, this UNSAFE is treated as concrete.",
                    stage, refinements_text
                )
            };
            if let Some(signals) = signal_text {
                rationale.push_str(&format!(" Baseline trace signals: {signals}."));
            }
            Some(CegarCounterexampleAnalysis {
                classification: if stage == 0 {
                    "potentially_spurious".into()
                } else {
                    "concrete".into()
                },
                rationale,
            })
        }
        VerificationResult::Safe { .. } | VerificationResult::ProbabilisticallySafe { .. } => {
            Some(CegarCounterexampleAnalysis {
                classification: "potentially_spurious".into(),
                rationale: format!(
                    "Baseline UNSAFE witness is eliminated at stage {} under refinements [{}], so it may be spurious under the baseline abstraction.",
                    stage, refinements_text
                ),
            })
        }
        VerificationResult::Unknown { reason } => Some(CegarCounterexampleAnalysis {
            classification: "inconclusive".into(),
            rationale: format!(
                "Stage {} could not decisively confirm or eliminate the baseline UNSAFE witness under refinements [{}]: {}",
                stage, refinements_text, reason
            ),
        }),
    }
}

pub(crate) fn stage_outcome_from_verification(result: &VerificationResult) -> CegarStageOutcome {
    match result {
        VerificationResult::Safe { depth_checked } => CegarStageOutcome::Safe {
            depth_checked: *depth_checked,
        },
        VerificationResult::ProbabilisticallySafe {
            depth_checked,
            failure_probability,
            committee_analyses,
        } => CegarStageOutcome::ProbabilisticallySafe {
            depth_checked: *depth_checked,
            failure_probability: *failure_probability,
            committee_count: committee_analyses.len(),
        },
        VerificationResult::Unsafe { trace } => CegarStageOutcome::Unsafe {
            trace: trace.clone(),
        },
        VerificationResult::Unknown { reason } => CegarStageOutcome::Unknown {
            reason: reason.clone(),
        },
    }
}

pub(crate) fn stage_outcome_from_unbounded_safety(
    result: &UnboundedSafetyResult,
) -> UnboundedSafetyCegarStageOutcome {
    match result {
        UnboundedSafetyResult::Safe { induction_k } => UnboundedSafetyCegarStageOutcome::Safe {
            induction_k: *induction_k,
        },
        UnboundedSafetyResult::ProbabilisticallySafe {
            induction_k,
            failure_probability,
            committee_analyses,
        } => UnboundedSafetyCegarStageOutcome::ProbabilisticallySafe {
            induction_k: *induction_k,
            failure_probability: *failure_probability,
            committee_count: committee_analyses.len(),
        },
        UnboundedSafetyResult::Unsafe { trace } => UnboundedSafetyCegarStageOutcome::Unsafe {
            trace: trace.clone(),
        },
        UnboundedSafetyResult::NotProved { max_k, cti } => {
            UnboundedSafetyCegarStageOutcome::NotProved {
                max_k: *max_k,
                cti: cti.clone(),
            }
        }
        UnboundedSafetyResult::Unknown { reason } => UnboundedSafetyCegarStageOutcome::Unknown {
            reason: reason.clone(),
        },
    }
}

pub(crate) fn stage_outcome_from_unbounded_fair_liveness(
    result: &UnboundedFairLivenessResult,
) -> UnboundedFairLivenessCegarStageOutcome {
    match result {
        UnboundedFairLivenessResult::LiveProved { frame } => {
            UnboundedFairLivenessCegarStageOutcome::LiveProved { frame: *frame }
        }
        UnboundedFairLivenessResult::FairCycleFound {
            depth,
            loop_start,
            trace,
        } => UnboundedFairLivenessCegarStageOutcome::FairCycleFound {
            depth: *depth,
            loop_start: *loop_start,
            trace: trace.clone(),
        },
        UnboundedFairLivenessResult::NotProved { max_k } => {
            UnboundedFairLivenessCegarStageOutcome::NotProved { max_k: *max_k }
        }
        UnboundedFairLivenessResult::Unknown { reason } => {
            UnboundedFairLivenessCegarStageOutcome::Unknown {
                reason: reason.clone(),
            }
        }
    }
}

pub(crate) fn cegar_extract_lasso_witness_from_result(
    result: &UnboundedFairLivenessResult,
) -> Option<CegarLassoWitness> {
    let UnboundedFairLivenessResult::FairCycleFound {
        depth,
        loop_start,
        trace,
    } = result
    else {
        return None;
    };
    Some(cegar_extract_lasso_witness(*depth, *loop_start, trace))
}

pub(crate) fn cegar_extract_lasso_witness(
    depth: usize,
    loop_start: usize,
    trace: &tarsier_ir::counter_system::Trace,
) -> CegarLassoWitness {
    let loop_end = depth.min(trace.steps.len());
    let loop_start_idx = loop_start.min(loop_end);
    let loop_steps: Vec<crate::result::CegarLassoStep> = trace.steps[loop_start_idx..loop_end]
        .iter()
        .map(|step| crate::result::CegarLassoStep {
            smt_step: step.smt_step,
            rule_id: step.rule_id.as_usize(),
            delta: step.delta,
        })
        .collect();

    let mut seen = HashSet::new();
    let mut loop_rule_ids = Vec::new();
    for step in &loop_steps {
        if seen.insert(step.rule_id) {
            loop_rule_ids.push(step.rule_id);
        }
    }

    CegarLassoWitness {
        depth,
        loop_start,
        loop_len: depth.saturating_sub(loop_start),
        prefix_len: loop_start,
        trace_steps: trace.steps.len(),
        loop_steps,
        loop_rule_ids,
        param_values: trace.param_values.clone(),
    }
}

pub(crate) fn cegar_stage_counterexample_analysis_unbounded_safety(
    stage: usize,
    refinements: &[String],
    result: &UnboundedSafetyResult,
    baseline_is_unsafe: bool,
    baseline_signals: Option<&CegarTraceSignals>,
) -> Option<CegarCounterexampleAnalysis> {
    if !baseline_is_unsafe {
        return None;
    }
    let refinements_text = if refinements.is_empty() {
        "(none)".to_string()
    } else {
        refinements.join(", ")
    };
    let signal_text = baseline_signals
        .map(cegar_signal_tags)
        .filter(|tags| !tags.is_empty())
        .map(|tags| tags.join(", "));
    match result {
        UnboundedSafetyResult::Unsafe { .. } => {
            let mut rationale = if stage == 0 {
                "Baseline stage reported UNSAFE before refinement replay; witness starts as potentially spurious until checked under stricter assumptions.".to_string()
            } else {
                format!(
                    "Witness persists at stage {} under refinements [{}]. Because refinements only restrict behaviors, this UNSAFE is treated as concrete.",
                    stage, refinements_text
                )
            };
            if let Some(signals) = signal_text {
                rationale.push_str(&format!(" Baseline trace signals: {signals}."));
            }
            Some(CegarCounterexampleAnalysis {
                classification: if stage == 0 {
                    "potentially_spurious".into()
                } else {
                    "concrete".into()
                },
                rationale,
            })
        }
        UnboundedSafetyResult::Safe { .. } | UnboundedSafetyResult::ProbabilisticallySafe { .. } => {
            Some(CegarCounterexampleAnalysis {
                classification: "potentially_spurious".into(),
                rationale: format!(
                    "Baseline UNSAFE witness is eliminated at stage {} under refinements [{}], so it may be spurious under the baseline abstraction.",
                    stage, refinements_text
                ),
            })
        }
        UnboundedSafetyResult::NotProved { max_k, .. } => {
            let reason = format!("proof did not close up to k={max_k}");
            Some(CegarCounterexampleAnalysis {
                classification: "inconclusive".into(),
                rationale: format!(
                    "Stage {} could not decisively confirm or eliminate the baseline UNSAFE witness under refinements [{}]: {}",
                    stage, refinements_text, reason
                ),
            })
        }
        UnboundedSafetyResult::Unknown { reason } => {
            Some(CegarCounterexampleAnalysis {
                classification: "inconclusive".into(),
                rationale: format!(
                    "Stage {} could not decisively confirm or eliminate the baseline UNSAFE witness under refinements [{}]: {}",
                    stage, refinements_text, reason
                ),
            })
        }
    }
}

pub(crate) fn cegar_stage_counterexample_analysis_unbounded_fair(
    stage: usize,
    refinements: &[String],
    result: &UnboundedFairLivenessResult,
    baseline_has_cycle: bool,
    baseline_signals: Option<&CegarTraceSignals>,
) -> Option<CegarCounterexampleAnalysis> {
    if !baseline_has_cycle {
        return None;
    }
    let refinements_text = if refinements.is_empty() {
        "(none)".to_string()
    } else {
        refinements.join(", ")
    };
    let signal_text = baseline_signals
        .map(cegar_signal_tags)
        .filter(|tags| !tags.is_empty())
        .map(|tags| tags.join(", "));
    match result {
        UnboundedFairLivenessResult::FairCycleFound { .. } => {
            let mut rationale = if stage == 0 {
                "Baseline stage reported a fair-cycle witness before refinement replay; witness starts as potentially spurious until checked under stricter assumptions.".to_string()
            } else {
                format!(
                    "Fair-cycle witness persists at stage {} under refinements [{}]. Because refinements only restrict behaviors, this witness is treated as concrete.",
                    stage, refinements_text
                )
            };
            if let Some(signals) = signal_text {
                rationale.push_str(&format!(" Baseline trace signals: {signals}."));
            }
            Some(CegarCounterexampleAnalysis {
                classification: if stage == 0 {
                    "potentially_spurious".into()
                } else {
                    "concrete".into()
                },
                rationale,
            })
        }
        UnboundedFairLivenessResult::LiveProved { .. } => Some(CegarCounterexampleAnalysis {
            classification: "potentially_spurious".into(),
            rationale: format!(
                "Baseline fair-cycle witness is eliminated at stage {} under refinements [{}], so it may be spurious under the baseline abstraction.",
                stage, refinements_text
            ),
        }),
        UnboundedFairLivenessResult::NotProved { max_k } => Some(CegarCounterexampleAnalysis {
            classification: "inconclusive".into(),
            rationale: format!(
                "Stage {} could not decisively confirm or eliminate the baseline fair-cycle witness under refinements [{}]: proof did not converge up to frame {}.",
                stage, refinements_text, max_k
            ),
        }),
        UnboundedFairLivenessResult::Unknown { reason } => Some(CegarCounterexampleAnalysis {
            classification: "inconclusive".into(),
            rationale: format!(
                "Stage {} could not decisively confirm or eliminate the baseline fair-cycle witness under refinements [{}]: {}",
                stage, refinements_text, reason
            ),
        }),
    }
}

pub(crate) fn sorted_unique_strings(mut items: Vec<String>) -> Vec<String> {
    items.sort();
    items.dedup();
    items
}

pub(crate) fn effective_message_equivocation_mode(
    proto: &ast::ProtocolDecl,
    msg: &str,
    global_equivocation: &str,
) -> String {
    if effective_message_non_equivocating(proto, msg, global_equivocation) {
        "none".to_string()
    } else {
        "full".to_string()
    }
}

pub(crate) fn effective_message_auth_mode(
    proto: &ast::ProtocolDecl,
    msg: &str,
    global_auth: &str,
) -> String {
    if effective_message_authenticated(proto, msg, global_auth) {
        "authenticated".to_string()
    } else {
        "unauthenticated".to_string()
    }
}

pub(crate) fn cegar_stage_model_changes(
    program: &ast::Program,
    refinement: &CegarRefinement,
) -> Vec<CegarModelChange> {
    let proto = &program.protocol.node;
    let global_auth = adversary_value(proto, "auth")
        .or_else(|| adversary_value(proto, "authentication"))
        .unwrap_or("none");
    let global_equivocation = adversary_value(proto, "equivocation").unwrap_or("full");
    let network = adversary_value(proto, "network")
        .or_else(|| adversary_value(proto, "network_semantics"))
        .unwrap_or("classic");
    let values = adversary_value(proto, "values")
        .or_else(|| adversary_value(proto, "value_abstraction"))
        .unwrap_or("exact");

    let mut changes = Vec::new();
    for atom in &refinement.atoms {
        match &atom.kind {
            CegarRefinementKind::GlobalEquivocationNone => changes.push(CegarModelChange {
                category: "adversary".into(),
                target: "equivocation".into(),
                before: global_equivocation.to_string(),
                after: "none".into(),
                predicate: atom.predicate.clone(),
            }),
            CegarRefinementKind::GlobalAuthSigned => changes.push(CegarModelChange {
                category: "adversary".into(),
                target: "auth".into(),
                before: global_auth.to_string(),
                after: "signed".into(),
                predicate: atom.predicate.clone(),
            }),
            CegarRefinementKind::GlobalValuesExact => changes.push(CegarModelChange {
                category: "adversary".into(),
                target: "values".into(),
                before: values.to_string(),
                after: "exact".into(),
                predicate: atom.predicate.clone(),
            }),
            CegarRefinementKind::GlobalNetworkIdentitySelective => changes.push(CegarModelChange {
                category: "adversary".into(),
                target: "network".into(),
                before: network.to_string(),
                after: "identity_selective".into(),
                predicate: atom.predicate.clone(),
            }),
            CegarRefinementKind::GlobalNetworkProcessSelective => changes.push(CegarModelChange {
                category: "adversary".into(),
                target: "network".into(),
                before: network.to_string(),
                after: "process_selective".into(),
                predicate: atom.predicate.clone(),
            }),
            CegarRefinementKind::MessageEquivocationNone { message } => {
                changes.push(CegarModelChange {
                    category: "equivocation".into(),
                    target: message.clone(),
                    before: effective_message_equivocation_mode(
                        proto,
                        message,
                        global_equivocation,
                    ),
                    after: "none".into(),
                    predicate: atom.predicate.clone(),
                })
            }
            CegarRefinementKind::MessageAuthAuthenticated { message } => {
                changes.push(CegarModelChange {
                    category: "channel".into(),
                    target: message.clone(),
                    before: effective_message_auth_mode(proto, message, global_auth),
                    after: "authenticated".into(),
                    predicate: atom.predicate.clone(),
                })
            }
        }
    }

    changes.sort_by(|a, b| {
        a.category
            .cmp(&b.category)
            .then_with(|| a.target.cmp(&b.target))
            .then_with(|| a.predicate.cmp(&b.predicate))
    });
    changes.dedup_by(|a, b| {
        a.category == b.category
            && a.target == b.target
            && a.before == b.before
            && a.after == b.after
            && a.predicate == b.predicate
    });
    changes
}

pub(crate) fn cegar_stage_eliminated_traces(
    stage: usize,
    result: &VerificationResult,
    baseline_trace: Option<&tarsier_ir::counter_system::Trace>,
    effective_preds: &[String],
) -> Vec<CegarEliminatedTrace> {
    let Some(trace) = baseline_trace else {
        return Vec::new();
    };
    if !matches!(
        result,
        VerificationResult::Safe { .. } | VerificationResult::ProbabilisticallySafe { .. }
    ) {
        return Vec::new();
    }
    vec![CegarEliminatedTrace {
        kind: "baseline_unsafe_witness".into(),
        source_stage: 0,
        eliminated_by: sorted_unique_strings(effective_preds.to_vec()),
        rationale: format!(
            "Baseline unsafe trace is eliminated at stage {stage} under monotone refinement replay."
        ),
        trace: trace.clone(),
    }]
}

pub(crate) fn cegar_stage_eliminated_traces_unbounded_safety(
    stage: usize,
    result: &UnboundedSafetyResult,
    baseline_trace: Option<&tarsier_ir::counter_system::Trace>,
    effective_preds: &[String],
) -> Vec<CegarEliminatedTrace> {
    let Some(trace) = baseline_trace else {
        return Vec::new();
    };
    if !matches!(
        result,
        UnboundedSafetyResult::Safe { .. } | UnboundedSafetyResult::ProbabilisticallySafe { .. }
    ) {
        return Vec::new();
    }
    vec![CegarEliminatedTrace {
        kind: "baseline_unsafe_witness".into(),
        source_stage: 0,
        eliminated_by: sorted_unique_strings(effective_preds.to_vec()),
        rationale: format!(
            "Baseline unsafe proof witness is eliminated at stage {stage} under monotone refinement replay."
        ),
        trace: trace.clone(),
    }]
}

pub(crate) fn cegar_stage_eliminated_traces_unbounded_fair(
    stage: usize,
    result: &UnboundedFairLivenessResult,
    baseline_trace: Option<&tarsier_ir::counter_system::Trace>,
    effective_preds: &[String],
) -> Vec<CegarEliminatedTrace> {
    let Some(trace) = baseline_trace else {
        return Vec::new();
    };
    if !matches!(result, UnboundedFairLivenessResult::LiveProved { .. }) {
        return Vec::new();
    }
    vec![CegarEliminatedTrace {
        kind: "baseline_fair_cycle_witness".into(),
        source_stage: 0,
        eliminated_by: sorted_unique_strings(effective_preds.to_vec()),
        rationale: format!(
            "Baseline fair-cycle witness is eliminated at stage {stage} under monotone refinement replay."
        ),
        trace: trace.clone(),
    }]
}

pub(crate) fn cegar_build_termination(
    reason: &str,
    max_refinements: usize,
    stages: &[CegarStageReport],
    timeout_secs: u64,
    started_at: Instant,
    reached_timeout_budget: bool,
) -> CegarTermination {
    let iterations_used = stages.iter().filter(|stage| stage.stage > 0).count();
    let reached_iteration_budget = max_refinements > 0 && iterations_used >= max_refinements;
    CegarTermination {
        reason: reason.to_string(),
        iteration_budget: max_refinements,
        iterations_used,
        timeout_secs,
        elapsed_ms: started_at.elapsed().as_millis(),
        reached_iteration_budget,
        reached_timeout_budget,
    }
}

pub(crate) fn cegar_build_termination_from_iterations(
    reason: &str,
    max_refinements: usize,
    iterations_used: usize,
    timeout_secs: u64,
    started_at: Instant,
    reached_timeout_budget: bool,
) -> CegarTermination {
    let reached_iteration_budget = max_refinements > 0 && iterations_used >= max_refinements;
    CegarTermination {
        reason: reason.to_string(),
        iteration_budget: max_refinements,
        iterations_used,
        timeout_secs,
        elapsed_ms: started_at.elapsed().as_millis(),
        reached_iteration_budget,
        reached_timeout_budget,
    }
}
