//! Fair-liveness proof and bounded fair-cycle entry points.

use crate::pipeline::verification::*;
use crate::pipeline::*;

pub(crate) fn prove_fair_liveness_program_with_mode(
    program: &ast::Program,
    options: &PipelineOptions,
    fairness: FairnessMode,
) -> Result<UnboundedFairLivenessResult, PipelineError> {
    info!("Lowering to threshold automaton...");
    let ta = lower_with_active_controls(program, "prove_fair_liveness")?;
    ensure_n_parameter(&ta)?;
    prove_fair_liveness_for_ta(ta, program, options, fairness)
}

pub fn prove_fair_liveness_with_mode(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
    fairness: FairnessMode,
) -> Result<UnboundedFairLivenessResult, PipelineError> {
    reset_run_diagnostics();
    info!("Parsing {filename}...");
    let program = parse(source, filename)?;
    preflight_validate(&program, options, PipelineCommand::Liveness)?;
    prove_fair_liveness_program_with_mode(&program, options, fairness)
}

/// Run unbounded fair-liveness proof with adaptive CEGAR refinements.
///
/// Refinements are monotone restrictions over adversary assumptions and value
/// abstraction. If a baseline fair cycle is eliminated by refinements and no
/// refined stage still finds a fair cycle, the result is reported as `UNKNOWN`
/// (potentially spurious baseline cycle).
pub fn prove_fair_liveness_with_cegar(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
    fairness: FairnessMode,
    max_refinements: usize,
) -> Result<UnboundedFairLivenessResult, PipelineError> {
    reset_run_diagnostics();
    info!("Parsing {filename}...");
    let program = parse(source, filename)?;
    preflight_validate(&program, options, PipelineCommand::Liveness)?;

    let deadline = deadline_from_timeout_secs(options.timeout_secs);
    let baseline_options =
        match options_with_remaining_timeout(options, deadline, "CEGAR fair-liveness proof") {
            Ok(adjusted) => adjusted,
            Err(_) => {
                return Ok(UnboundedFairLivenessResult::Unknown {
                    reason: timeout_unknown_reason("CEGAR fair-liveness proof"),
                });
            }
        };
    let baseline_result =
        prove_fair_liveness_program_with_mode(&program, &baseline_options, fairness)?;
    let baseline_is_cycle = matches!(
        baseline_result,
        UnboundedFairLivenessResult::FairCycleFound { .. }
    );
    if !baseline_is_cycle || max_refinements == 0 {
        return Ok(baseline_result);
    }

    let trace_signals = match &baseline_result {
        UnboundedFairLivenessResult::FairCycleFound { trace, .. } => {
            let ta_for_signals =
                lower_with_active_controls(&program, "prove_fair_liveness_cegar.signals")?;
            Some(cegar_trace_signals_from_trace(&ta_for_signals, trace))
        }
        _ => None,
    };
    let mut saw_eliminated = false;
    let mut saw_inconclusive = false;
    let refinement_ladder = cegar_refinement_ladder_with_signals(
        &program,
        trace_signals.as_ref(),
        options.solver,
        options.timeout_secs,
    );
    let mut discovered_predicates: Vec<String> = Vec::new();
    let mut eval_cache = CegarStageEvalCache::<UnboundedFairLivenessResult>::default();

    for refinement in refinement_ladder.into_iter().take(max_refinements) {
        crate::sandbox::enforce_active_limits()?;
        let refined_options =
            match options_with_remaining_timeout(options, deadline, "CEGAR fair-liveness proof") {
                Ok(adjusted) => adjusted,
                Err(_) => {
                    eval_cache.emit_notes();
                    return Ok(UnboundedFairLivenessResult::Unknown {
                        reason: timeout_unknown_reason("CEGAR fair-liveness proof"),
                    });
                }
            };
        let mut result = eval_cache.eval(&refinement, || {
            let mut refined_program = program.clone();
            refinement.apply(&mut refined_program);
            prove_fair_liveness_program_with_mode(&refined_program, &refined_options, fairness)
        })?;
        let refinement_preds = refinement.refinements();
        let mut effective_preds = refinement_preds.clone();
        let mut used_realizability_replay = false;

        if let UnboundedFairLivenessResult::FairCycleFound { trace, .. } = &result {
            let mut stage_program = program.clone();
            refinement.apply(&mut stage_program);
            let ta_for_signals = lower_with_active_controls(
                &stage_program,
                "prove_fair_liveness_cegar.realizability.signals",
            )?;
            let stage_signals = cegar_trace_signals_from_trace(&ta_for_signals, trace);
            let replay_atoms = cegar_liveness_realizability_atoms(
                &stage_program,
                &stage_signals,
                &effective_preds,
            );

            for atom in replay_atoms.into_iter().take(3) {
                let replay_options = match options_with_remaining_timeout(
                    options,
                    deadline,
                    "CEGAR fair-liveness realizability replay",
                ) {
                    Ok(adjusted) => adjusted,
                    Err(_) => {
                        eval_cache.emit_notes();
                        return Ok(UnboundedFairLivenessResult::Unknown {
                            reason: timeout_unknown_reason("CEGAR fair-liveness proof"),
                        });
                    }
                };
                let mut replay_refinement = refinement.clone();
                replay_refinement.atoms.push(atom.clone());
                let replay_result = match eval_cache.eval(&replay_refinement, || {
                    let mut replay_program = program.clone();
                    replay_refinement.apply(&mut replay_program);
                    prove_fair_liveness_program_with_mode(
                        &replay_program,
                        &replay_options,
                        fairness,
                    )
                }) {
                    Ok(value) => value,
                    Err(PipelineError::Lowering(
                        tarsier_ir::lowering::LoweringError::Unsupported(_),
                    )) => {
                        // Some strict replay predicates require role metadata not
                        // present in all protocols; skip inapplicable candidates.
                        continue;
                    }
                    Err(err) => return Err(err),
                };
                if !matches!(
                    replay_result,
                    UnboundedFairLivenessResult::FairCycleFound { .. }
                ) {
                    effective_preds = sorted_unique_strings(replay_refinement.refinements());
                    result = replay_result;
                    used_realizability_replay = true;
                    break;
                }
            }
        }

        match result {
            UnboundedFairLivenessResult::FairCycleFound { .. } => {
                eval_cache.emit_notes();
                return Ok(result);
            }
            UnboundedFairLivenessResult::LiveProved { .. } => {
                if !used_realizability_replay && refinement.atoms.len() > 1 {
                    let maybe_core = cegar_shrink_refinement_core(&refinement, |candidate| {
                        let refined_options = match options_with_remaining_timeout(
                            options,
                            deadline,
                            "CEGAR fair-liveness core extraction",
                        ) {
                            Ok(adjusted) => adjusted,
                            Err(_) => return Ok(None),
                        };
                        let candidate_result = eval_cache.eval(candidate, || {
                            let mut candidate_program = program.clone();
                            candidate.apply(&mut candidate_program);
                            prove_fair_liveness_program_with_mode(
                                &candidate_program,
                                &refined_options,
                                fairness,
                            )
                        })?;
                        Ok(Some(!matches!(
                            candidate_result,
                            UnboundedFairLivenessResult::FairCycleFound { .. }
                        )))
                    })?;
                    if let Some(core) = maybe_core {
                        effective_preds = core.refinements();
                    }
                }
                saw_eliminated = true;
                for pred in &effective_preds {
                    if !discovered_predicates.contains(pred) {
                        discovered_predicates.push(pred.clone());
                    }
                }
                if let Some(core_predicate) = cegar_core_compound_predicate(&effective_preds) {
                    if !discovered_predicates.contains(&core_predicate) {
                        discovered_predicates.push(core_predicate);
                    }
                }
            }
            UnboundedFairLivenessResult::NotProved { .. }
            | UnboundedFairLivenessResult::Unknown { .. } => {
                saw_inconclusive = true;
            }
        }
    }
    eval_cache.emit_notes();

    if saw_eliminated {
        discovered_predicates = sorted_unique_strings(discovered_predicates);
        return Ok(UnboundedFairLivenessResult::Unknown {
            reason: format!(
                "CEGAR refinements eliminated the baseline fair-cycle witness, \
                 but no refined fair cycle was found. Potentially spurious under \
                 refinements: {}",
                if discovered_predicates.is_empty() {
                    "<none>".into()
                } else {
                    discovered_predicates.join(", ")
                }
            ),
        });
    }
    if saw_inconclusive {
        return Ok(UnboundedFairLivenessResult::Unknown {
            reason: "CEGAR refinements were inconclusive; baseline fair-cycle witness \
                     is not confirmed under refined assumptions."
                .into(),
        });
    }
    Ok(UnboundedFairLivenessResult::Unknown {
        reason: "CEGAR refinement ladder exhausted without a confirmed fair cycle or \
                 elimination witness."
            .into(),
    })
}

/// Run unbounded fair-liveness proof with CEGAR and return a machine-readable report.
///
/// This API is intended for CI/governance integrations that need explicit
/// refinement controls and baseline/final outcome tracking.
pub fn prove_fair_liveness_with_cegar_report(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
    fairness: FairnessMode,
    max_refinements: usize,
) -> Result<UnboundedFairLivenessCegarAuditReport, PipelineError> {
    let started_at = Instant::now();
    reset_run_diagnostics();
    info!("Parsing {filename}...");
    let program = parse(source, filename)?;
    preflight_validate(&program, options, PipelineCommand::Liveness)?;

    let deadline = deadline_from_timeout_secs(options.timeout_secs);
    let baseline_options =
        match options_with_remaining_timeout(options, deadline, "CEGAR fair-liveness proof") {
            Ok(adjusted) => adjusted,
            Err(_) => {
                let baseline_result = UnboundedFairLivenessResult::Unknown {
                    reason: timeout_unknown_reason("CEGAR fair-liveness proof"),
                };
                let stages = vec![UnboundedFairLivenessCegarStageReport {
                    stage: 0,
                    label: "baseline".into(),
                    refinements: Vec::new(),
                    outcome: stage_outcome_from_unbounded_fair_liveness(&baseline_result),
                    note: Some("Global timeout exhausted before baseline stage.".into()),
                    model_changes: Vec::new(),
                    eliminated_traces: Vec::new(),
                    lasso_witness: None,
                    discovered_predicates: Vec::new(),
                    counterexample_analysis: None,
                    scored_predicates: Vec::new(),
                }];
                let termination = cegar_build_termination_from_iterations(
                    "baseline_timeout",
                    max_refinements,
                    0,
                    options.timeout_secs,
                    started_at,
                    true,
                );
                return Ok(UnboundedFairLivenessCegarAuditReport {
                    controls: CegarRunControls {
                        max_refinements,
                        timeout_secs: options.timeout_secs,
                        solver: solver_choice_label(options.solver).into(),
                        proof_engine: Some(proof_engine_label(options.proof_engine).into()),
                        fairness: Some(fairness_mode_label(fairness).into()),
                    },
                    stages,
                    discovered_predicates: Vec::new(),
                    baseline_result: baseline_result.clone(),
                    final_result: baseline_result,
                    classification: "timeout".into(),
                    counterexample_analysis: None,
                    termination,
                });
            }
        };

    let baseline_result =
        prove_fair_liveness_program_with_mode(&program, &baseline_options, fairness)?;
    let trace_signals = match &baseline_result {
        UnboundedFairLivenessResult::FairCycleFound { trace, .. } => {
            let ta_for_signals =
                lower_with_active_controls(&program, "prove_fair_liveness_cegar.signals")?;
            Some(cegar_trace_signals_from_trace(&ta_for_signals, trace))
        }
        _ => None,
    };
    let baseline_has_cycle = matches!(
        baseline_result,
        UnboundedFairLivenessResult::FairCycleFound { .. }
    );
    let mut stages = vec![UnboundedFairLivenessCegarStageReport {
        stage: 0,
        label: "baseline".into(),
        refinements: Vec::new(),
        outcome: stage_outcome_from_unbounded_fair_liveness(&baseline_result),
        note: trace_signals.as_ref().and_then(cegar_signals_note),
        model_changes: Vec::new(),
        eliminated_traces: Vec::new(),
        lasso_witness: cegar_extract_lasso_witness_from_result(&baseline_result),
        discovered_predicates: Vec::new(),
        counterexample_analysis: cegar_stage_counterexample_analysis_unbounded_fair(
            0,
            &[],
            &baseline_result,
            baseline_has_cycle,
            trace_signals.as_ref(),
        ),
        scored_predicates: Vec::new(),
    }];
    let mut final_result = baseline_result.clone();
    let mut discovered_predicates: Vec<String> = Vec::new();
    let mut saw_timeout = false;
    let mut saw_eliminated = false;
    let mut saw_inconclusive = false;
    let mut confirmed_cycle = false;
    let mut eval_cache = CegarStageEvalCache::<UnboundedFairLivenessResult>::default();

    if !baseline_has_cycle || max_refinements == 0 {
        let classification = if baseline_has_cycle {
            "fair_cycle_unrefined"
        } else if matches!(
            baseline_result,
            UnboundedFairLivenessResult::LiveProved { .. }
        ) {
            "live_proved"
        } else {
            "inconclusive"
        };
        let termination = cegar_build_termination_from_iterations(
            if baseline_has_cycle {
                "iteration_budget_zero"
            } else {
                "baseline_non_counterexample"
            },
            max_refinements,
            0,
            options.timeout_secs,
            started_at,
            false,
        );
        return Ok(UnboundedFairLivenessCegarAuditReport {
            controls: CegarRunControls {
                max_refinements,
                timeout_secs: options.timeout_secs,
                solver: solver_choice_label(options.solver).into(),
                proof_engine: Some(proof_engine_label(options.proof_engine).into()),
                fairness: Some(fairness_mode_label(fairness).into()),
            },
            stages,
            discovered_predicates,
            baseline_result: baseline_result.clone(),
            final_result: baseline_result,
            classification: classification.into(),
            counterexample_analysis: if baseline_has_cycle {
                Some(CegarCounterexampleAnalysis {
                    classification: "potentially_spurious".into(),
                    rationale: "No refinement replay was performed, so the baseline fair-cycle witness is not yet confirmed under stricter assumptions.".into(),
                })
            } else {
                None
            },
            termination,
        });
    }

    let refinement_plan = cegar_refinement_plan_with_signals(
        &program,
        trace_signals.as_ref(),
        options.solver,
        options.timeout_secs,
    );

    for (idx, plan_entry) in refinement_plan
        .into_iter()
        .take(max_refinements)
        .enumerate()
    {
        crate::sandbox::enforce_active_limits()?;
        let refinement = plan_entry.refinement;
        let refined_options =
            match options_with_remaining_timeout(options, deadline, "CEGAR fair-liveness proof") {
                Ok(adjusted) => adjusted,
                Err(_) => {
                    saw_timeout = true;
                    final_result = UnboundedFairLivenessResult::Unknown {
                        reason: timeout_unknown_reason("CEGAR fair-liveness proof"),
                    };
                    break;
                }
            };
        let mut result = eval_cache.eval(&refinement, || {
            let mut refined_program = program.clone();
            refinement.apply(&mut refined_program);
            prove_fair_liveness_program_with_mode(&refined_program, &refined_options, fairness)
        })?;
        let refinement_preds = sorted_unique_strings(refinement.refinements());
        let mut effective_refinement = refinement.clone();
        let mut effective_preds = refinement_preds.clone();
        let mut used_realizability_replay = false;
        let mut realizability_note: Option<String> = None;

        if let UnboundedFairLivenessResult::FairCycleFound { trace, .. } = &result {
            let mut stage_program = program.clone();
            effective_refinement.apply(&mut stage_program);
            let ta_for_signals = lower_with_active_controls(
                &stage_program,
                "prove_fair_liveness_cegar.realizability.signals",
            )?;
            let stage_signals = cegar_trace_signals_from_trace(&ta_for_signals, trace);
            let replay_atoms = cegar_liveness_realizability_atoms(
                &stage_program,
                &stage_signals,
                &effective_preds,
            );

            for atom in replay_atoms.into_iter().take(3) {
                let replay_options = match options_with_remaining_timeout(
                    options,
                    deadline,
                    "CEGAR fair-liveness realizability replay",
                ) {
                    Ok(adjusted) => adjusted,
                    Err(_) => {
                        saw_timeout = true;
                        result = UnboundedFairLivenessResult::Unknown {
                            reason: timeout_unknown_reason("CEGAR fair-liveness proof"),
                        };
                        break;
                    }
                };
                let mut replay_refinement = effective_refinement.clone();
                replay_refinement.atoms.push(atom.clone());
                let replay_result = match eval_cache.eval(&replay_refinement, || {
                    let mut replay_program = program.clone();
                    replay_refinement.apply(&mut replay_program);
                    prove_fair_liveness_program_with_mode(
                        &replay_program,
                        &replay_options,
                        fairness,
                    )
                }) {
                    Ok(value) => value,
                    Err(PipelineError::Lowering(
                        tarsier_ir::lowering::LoweringError::Unsupported(_),
                    )) => {
                        // Candidate not applicable to this protocol shape; try next atom.
                        continue;
                    }
                    Err(err) => return Err(err),
                };
                if !matches!(
                    replay_result,
                    UnboundedFairLivenessResult::FairCycleFound { .. }
                ) {
                    effective_refinement = replay_refinement;
                    effective_preds = sorted_unique_strings(effective_refinement.refinements());
                    result = replay_result;
                    used_realizability_replay = true;
                    realizability_note = Some(format!(
                        "Realizability replay added predicate {} from lasso evidence.",
                        atom.predicate
                    ));
                    break;
                }
            }
        }
        let model_changes = cegar_stage_model_changes(&program, &effective_refinement);

        let mut note = match &result {
            UnboundedFairLivenessResult::FairCycleFound { .. } => {
                if used_realizability_replay {
                    Some(
                        "Fair-cycle witness persists after realizability replay; treated as concrete."
                            .into(),
                    )
                } else {
                    Some(
                        "Fair-cycle witness persists under this refinement; treated as concrete."
                            .into(),
                    )
                }
            }
            UnboundedFairLivenessResult::LiveProved { .. } => {
                if used_realizability_replay {
                    Some(
                        "Realizability replay eliminated the abstract fair-cycle witness under additional predicates."
                            .into(),
                    )
                } else {
                    Some("Baseline fair-cycle witness is eliminated under this refinement.".into())
                }
            }
            UnboundedFairLivenessResult::NotProved { .. }
            | UnboundedFairLivenessResult::Unknown { .. } => {
                if used_realizability_replay {
                    Some(
                        "Realizability replay did not confirm the fair-cycle witness as concrete."
                            .into(),
                    )
                } else {
                    Some("Refinement did not produce a decisive verdict for this stage.".into())
                }
            }
        };
        let selection_note = format!("Selection rationale: {}", plan_entry.rationale);
        note = Some(match note {
            Some(existing) => format!("{selection_note} {existing}"),
            None => selection_note,
        });
        if let Some(extra_note) = realizability_note {
            note = Some(match note {
                Some(existing) => format!("{existing} {extra_note}"),
                None => extra_note,
            });
        }

        if !used_realizability_replay
            && !matches!(result, UnboundedFairLivenessResult::FairCycleFound { .. })
            && refinement.atoms.len() > 1
        {
            let maybe_core = cegar_shrink_refinement_core(&refinement, |candidate| {
                let refined_options = match options_with_remaining_timeout(
                    options,
                    deadline,
                    "CEGAR fair-liveness core extraction",
                ) {
                    Ok(adjusted) => adjusted,
                    Err(_) => return Ok(None),
                };
                let candidate_result = eval_cache.eval(candidate, || {
                    let mut candidate_program = program.clone();
                    candidate.apply(&mut candidate_program);
                    prove_fair_liveness_program_with_mode(
                        &candidate_program,
                        &refined_options,
                        fairness,
                    )
                })?;
                Ok(Some(!matches!(
                    candidate_result,
                    UnboundedFairLivenessResult::FairCycleFound { .. }
                )))
            })?;
            if let Some(core) = maybe_core {
                let core_preds = core.refinements();
                effective_preds = core_preds.clone();
                let core_note = format!("Refinement-elimination core: {}", core.label());
                note = Some(match note {
                    Some(existing) => format!("{existing} {core_note}"),
                    None => core_note,
                });
            }
        }
        if let Some(core_predicate) = cegar_core_compound_predicate(&effective_preds) {
            let core_note = format!("Generated core predicate: {core_predicate}");
            note = Some(match note {
                Some(existing) => format!("{existing} {core_note}"),
                None => core_note,
            });
        }
        let stage_counterexample_analysis = cegar_stage_counterexample_analysis_unbounded_fair(
            idx + 1,
            &effective_preds,
            &result,
            baseline_has_cycle,
            trace_signals.as_ref(),
        );
        let baseline_trace = match &stages[0].outcome {
            UnboundedFairLivenessCegarStageOutcome::FairCycleFound { trace, .. } => Some(trace),
            _ => None,
        };
        let eliminated_traces = cegar_stage_eliminated_traces_unbounded_fair(
            idx + 1,
            &result,
            baseline_trace,
            &effective_preds,
        );
        let stage_discovered_predicates = if eliminated_traces.is_empty() {
            Vec::new()
        } else {
            let mut preds = effective_preds.clone();
            if let Some(core_predicate) = cegar_core_compound_predicate(&effective_preds) {
                preds.push(core_predicate);
            }
            sorted_unique_strings(preds)
        };

        stages.push(UnboundedFairLivenessCegarStageReport {
            stage: idx + 1,
            label: effective_refinement.label(),
            refinements: sorted_unique_strings(effective_preds.clone()),
            outcome: stage_outcome_from_unbounded_fair_liveness(&result),
            note,
            model_changes,
            eliminated_traces,
            lasso_witness: cegar_extract_lasso_witness_from_result(&result),
            discovered_predicates: stage_discovered_predicates,
            counterexample_analysis: stage_counterexample_analysis,
            scored_predicates: Vec::new(),
        });

        match result {
            UnboundedFairLivenessResult::FairCycleFound { .. } => {
                final_result = result;
                confirmed_cycle = true;
                break;
            }
            UnboundedFairLivenessResult::LiveProved { .. } => {
                saw_eliminated = true;
                for pred in &effective_preds {
                    if !discovered_predicates.contains(pred) {
                        discovered_predicates.push(pred.clone());
                    }
                }
                if let Some(core_predicate) = cegar_core_compound_predicate(&effective_preds) {
                    if !discovered_predicates.contains(&core_predicate) {
                        discovered_predicates.push(core_predicate);
                    }
                }
            }
            UnboundedFairLivenessResult::NotProved { .. }
            | UnboundedFairLivenessResult::Unknown { .. } => {
                saw_inconclusive = true;
            }
        }
    }
    eval_cache.emit_notes();
    discovered_predicates = sorted_unique_strings(discovered_predicates);

    if !confirmed_cycle && saw_eliminated {
        final_result = UnboundedFairLivenessResult::Unknown {
            reason: "CEGAR refinements eliminated the baseline fair-cycle witness, but no refined fair cycle was found. Treat as inconclusive and inspect the CEGAR report.".into(),
        };
    } else if !confirmed_cycle && saw_timeout {
        final_result = UnboundedFairLivenessResult::Unknown {
            reason: timeout_unknown_reason("CEGAR fair-liveness proof"),
        };
    } else if !confirmed_cycle && saw_inconclusive {
        final_result = UnboundedFairLivenessResult::Unknown {
            reason: "CEGAR refinements were inconclusive; baseline fair-cycle witness is not confirmed under refined assumptions.".into(),
        };
    }

    let classification = if confirmed_cycle {
        "fair_cycle_confirmed"
    } else if saw_eliminated {
        "inconclusive"
    } else if saw_timeout {
        "timeout"
    } else {
        "inconclusive"
    };
    let counterexample_analysis = if confirmed_cycle {
        let confirmation = stages
            .iter()
            .find(|stage| {
                stage.stage > 0
                    && matches!(
                        stage.outcome,
                        UnboundedFairLivenessCegarStageOutcome::FairCycleFound { .. }
                    )
            })
            .map(|stage| stage.stage)
            .unwrap_or(0);
        Some(CegarCounterexampleAnalysis {
            classification: "concrete".into(),
            rationale: format!(
                "Baseline fair-cycle witness is confirmed concrete by refined replay at stage {}.",
                confirmation
            ),
        })
    } else if saw_eliminated {
        Some(CegarCounterexampleAnalysis {
            classification: "potentially_spurious".into(),
            rationale: format!(
                "Baseline fair-cycle witness was eliminated by refinement predicates [{}], so the overall result is inconclusive until a concrete refined fair-cycle witness is found.",
                if discovered_predicates.is_empty() {
                    "<none>".into()
                } else {
                    discovered_predicates.join(", ")
                }
            ),
        })
    } else if saw_timeout {
        Some(CegarCounterexampleAnalysis {
            classification: "inconclusive".into(),
            rationale: timeout_unknown_reason("CEGAR fair-liveness proof"),
        })
    } else {
        Some(CegarCounterexampleAnalysis {
            classification: "inconclusive".into(),
            rationale: "Unable to confirm or eliminate the baseline fair-cycle witness within refinement budget.".into(),
        })
    };
    let termination_reason = if confirmed_cycle {
        "confirmed_fair_cycle"
    } else if saw_eliminated {
        "counterexample_eliminated_no_confirmation"
    } else if saw_timeout {
        "timeout"
    } else if stages.iter().filter(|stage| stage.stage > 0).count() >= max_refinements {
        "max_refinements_reached"
    } else {
        "inconclusive"
    };
    let termination = cegar_build_termination_from_iterations(
        termination_reason,
        max_refinements,
        stages.iter().filter(|stage| stage.stage > 0).count(),
        options.timeout_secs,
        started_at,
        saw_timeout,
    );

    Ok(UnboundedFairLivenessCegarAuditReport {
        controls: CegarRunControls {
            max_refinements,
            timeout_secs: options.timeout_secs,
            solver: solver_choice_label(options.solver).into(),
            proof_engine: Some(proof_engine_label(options.proof_engine).into()),
            fairness: Some(fairness_mode_label(fairness).into()),
        },
        stages,
        discovered_predicates,
        baseline_result,
        final_result,
        classification: classification.into(),
        counterexample_analysis,
        termination,
    })
}

pub(crate) fn prove_fair_liveness_for_ta(
    mut ta: ThresholdAutomaton,
    program: &ast::Program,
    options: &PipelineOptions,
    fairness: FairnessMode,
) -> Result<UnboundedFairLivenessResult, PipelineError> {
    push_reduction_note("encoder.structural_hashing=on");
    push_reduction_note("pdr.symmetry_generalization=on");
    push_reduction_note("pdr.incremental_query_reuse=on");
    push_reduction_note("por.stutter_time_signature_collapse=on");
    push_reduction_note(&format!("guardrail.timeout_secs={}", options.timeout_secs));
    match current_execution_controls()
        .liveness_memory_budget_mb
        .filter(|mb| *mb > 0)
    {
        Some(mb) => push_reduction_note(&format!("guardrail.liveness_memory_budget_mb={mb}")),
        None => push_reduction_note("guardrail.liveness_memory_budget_mb=off"),
    }
    let committee_summaries = analyze_and_constrain_committees(&mut ta)?;
    let has_committees = !committee_summaries.is_empty();
    let committee_bounds: Vec<(usize, u64)> = ta
        .constraints
        .committees
        .iter()
        .zip(committee_summaries.iter())
        .filter_map(|(spec, summary)| spec.bound_param.map(|pid| (pid.as_usize(), summary.b_max)))
        .collect();

    if has_committees && committee_bounds.is_empty() {
        return Ok(UnboundedFairLivenessResult::Unknown {
            reason: "Committee analysis present, but no bound_param specified; \
                     probabilistic bounds are not enforced."
                .into(),
        });
    }

    let liveness_spec = extract_liveness_spec(&ta, program)?;
    if matches!(&liveness_spec, LivenessSpec::TerminationGoalLocs(goal_locs) if goal_locs.is_empty())
    {
        return Err(PipelineError::Property(
            "Unbounded fair-liveness proof requires either a `property ...: liveness { ... }` declaration or a boolean local variable named `decided`."
                .into(),
        ));
    }
    let target = fair_liveness_target_from_spec(&ta, liveness_spec)?;

    let cs = abstract_to_cs(ta.clone());
    let overall_timeout = if options.timeout_secs == 0 {
        None
    } else {
        Some(Duration::from_secs(options.timeout_secs))
    };
    crate::sandbox::enforce_active_limits()?;
    match options.solver {
        SolverChoice::Z3 => {
            let mut solver = Z3Solver::with_timeout_secs(options.timeout_secs);
            run_unbounded_fair_pdr(
                &mut solver,
                &cs,
                options.max_depth,
                &target,
                &committee_bounds,
                fairness,
                overall_timeout,
            )
        }
        SolverChoice::Cvc5 => {
            use tarsier_smt::backends::cvc5_backend::Cvc5Solver;
            let mut solver = Cvc5Solver::with_timeout_secs(options.timeout_secs)
                .map_err(|e| PipelineError::Solver(e.to_string()))?;
            run_unbounded_fair_pdr(
                &mut solver,
                &cs,
                options.max_depth,
                &target,
                &committee_bounds,
                fairness,
                overall_timeout,
            )
        }
    }
}

/// Attempt unbounded fair-liveness proof on a round/view-erased over-approximation.
///
/// LIVE_PROVED is sound for the concrete model. FAIR_CYCLE_FOUND may be
/// spurious due to abstraction.
pub fn prove_fair_liveness_with_round_abstraction(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
    fairness: FairnessMode,
    erased_round_vars: &[String],
) -> Result<RoundAbstractionFairProofResult, PipelineError> {
    reset_run_diagnostics();
    info!("Parsing {filename}...");
    let program = parse(source, filename)?;
    preflight_validate(&program, options, PipelineCommand::Liveness)?;

    if normalize_erased_var_names(erased_round_vars).is_empty() {
        return Err(PipelineError::Validation(
            "Round abstraction requires at least one erased variable name.".into(),
        ));
    }

    info!("Lowering to threshold automaton...");
    let ta = lower_with_active_controls(&program, "prove_fair_round")?;
    ensure_n_parameter(&ta)?;

    let (abstract_ta, summary) = apply_round_erasure_abstraction(&ta, erased_round_vars);
    let result = prove_fair_liveness_for_ta(abstract_ta, &program, options, fairness)?;
    Ok(RoundAbstractionFairProofResult { summary, result })
}

/// Attempt unbounded fair-liveness proof under weak fairness.
pub fn prove_fair_liveness(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
) -> Result<UnboundedFairLivenessResult, PipelineError> {
    reset_run_diagnostics();
    prove_fair_liveness_with_mode(source, filename, options, FairnessMode::Weak)
}

/// Search for bounded fair non-terminating lassos.
///
/// If a fair lasso is found, liveness is violated. If no lasso is found up to
/// `max_depth`, the result is "no fair counterexample up to bound" (not a full
/// unbounded proof).
pub fn check_fair_liveness_with_mode(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
    fairness: FairnessMode,
) -> Result<FairLivenessResult, PipelineError> {
    reset_run_diagnostics();
    with_smt_profile("check_fair_liveness", || {
        push_reduction_note("encoder.structural_hashing=on");
        info!("Parsing {filename}...");
        let program = parse(source, filename)?;
        preflight_validate(&program, options, PipelineCommand::Liveness)?;

        info!("Lowering to threshold automaton...");
        let mut ta = lower_with_active_controls(&program, "check_fair_liveness")?;
        ensure_n_parameter(&ta)?;

        let committee_summaries = analyze_and_constrain_committees(&mut ta)?;
        let has_committees = !committee_summaries.is_empty();
        let committee_bounds: Vec<(usize, u64)> = ta
            .constraints
            .committees
            .iter()
            .zip(committee_summaries.iter())
            .filter_map(|(spec, summary)| {
                spec.bound_param.map(|pid| (pid.as_usize(), summary.b_max))
            })
            .collect();

        if has_committees && committee_bounds.is_empty() {
            return Ok(FairLivenessResult::Unknown {
                reason: "Committee analysis present, but no bound_param specified; \
                     probabilistic bounds are not enforced."
                    .into(),
            });
        }

        let liveness_spec = extract_liveness_spec(&ta, &program)?;
        if matches!(&liveness_spec, LivenessSpec::TerminationGoalLocs(goal_locs) if goal_locs.is_empty())
        {
            return Err(PipelineError::Property(
            "Fair liveness check requires either a `property ...: liveness { ... }` declaration or a boolean local variable named `decided`."
                .into(),
        ));
        }
        let target = fair_liveness_target_from_spec(&ta, liveness_spec)?;
        if matches!(&target, FairLivenessTarget::NonGoalLocs(non_goal_locs) if non_goal_locs.is_empty())
        {
            return Ok(FairLivenessResult::NoFairCycleUpTo {
                depth_checked: options.max_depth,
            });
        }

        let cs = abstract_to_cs(ta.clone());
        match options.solver {
            SolverChoice::Z3 => {
                let mut solver = Z3Solver::with_timeout_secs(options.timeout_secs);
                run_fair_lasso_search(
                    &mut solver,
                    &cs,
                    options.max_depth,
                    &target,
                    &committee_bounds,
                    fairness,
                    deadline_from_timeout_secs(options.timeout_secs),
                )
            }
            SolverChoice::Cvc5 => {
                use tarsier_smt::backends::cvc5_backend::Cvc5Solver;
                let mut solver = Cvc5Solver::with_timeout_secs(options.timeout_secs)
                    .map_err(|e| PipelineError::Solver(e.to_string()))?;
                run_fair_lasso_search(
                    &mut solver,
                    &cs,
                    options.max_depth,
                    &target,
                    &committee_bounds,
                    fairness,
                    deadline_from_timeout_secs(options.timeout_secs),
                )
            }
        }
    })
}

/// Search for bounded weak-fair non-terminating lassos.
pub fn check_fair_liveness(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
) -> Result<FairLivenessResult, PipelineError> {
    reset_run_diagnostics();
    check_fair_liveness_with_mode(source, filename, options, FairnessMode::Weak)
}
