//! Unbounded safety proof entry points and CEGAR reporting.

use crate::pipeline::verification::*;
use crate::pipeline::*;

pub(crate) fn prove_safety_for_ta(
    mut ta: ThresholdAutomaton,
    program: &ast::Program,
    options: &PipelineOptions,
) -> Result<UnboundedSafetyResult, PipelineError> {
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
        return Ok(UnboundedSafetyResult::Unknown {
            reason: "Committee analysis present, but no bound_param specified; \
                     probabilistic bounds are not enforced."
                .into(),
        });
    }

    let property = extract_property(&ta, program, options.soundness)?;
    let cs = abstract_to_cs(ta.clone());

    info!(
        solver = ?options.solver,
        proof_engine = ?options.proof_engine,
        max_k = options.max_depth,
        "Starting unbounded safety proof..."
    );

    let kind_result = match options.solver {
        SolverChoice::Z3 => {
            let mut solver = Z3Solver::with_timeout_secs(options.timeout_secs);
            run_unbounded_with_engine(
                &mut solver,
                &cs,
                &property,
                options.max_depth,
                &committee_bounds,
                options.proof_engine,
                overall_timeout_duration(options.timeout_secs),
            )?
        }
        SolverChoice::Cvc5 => {
            use tarsier_smt::backends::cvc5_backend::Cvc5Solver;
            let mut solver = Cvc5Solver::with_timeout_secs(options.timeout_secs)
                .map_err(|e| PipelineError::Solver(e.to_string()))?;
            run_unbounded_with_engine(
                &mut solver,
                &cs,
                &property,
                options.max_depth,
                &committee_bounds,
                options.proof_engine,
                overall_timeout_duration(options.timeout_secs),
            )?
        }
    };

    Ok(kind_result_to_unbounded_safety(
        kind_result,
        &cs,
        &property,
        &committee_bounds,
        &committee_summaries,
        options,
    ))
}

pub(crate) fn prove_safety_program(
    program: &ast::Program,
    options: &PipelineOptions,
) -> Result<UnboundedSafetyResult, PipelineError> {
    info!("Lowering to threshold automaton...");
    let ta = lower_with_active_controls(program, "prove_safety")?;
    ensure_n_parameter(&ta)?;
    prove_safety_for_ta(ta, program, options)
}

/// Run an unbounded safety proof attempt on an already-parsed program.
///
/// This is useful for workflows that synthesize/mutate property declarations
/// before invoking the solver.
pub fn prove_safety_program_ast(
    program: &ast::Program,
    options: &PipelineOptions,
) -> Result<UnboundedSafetyResult, PipelineError> {
    reset_run_diagnostics();
    with_smt_profile("prove_safety", || {
        if !has_safety_properties(program) && has_liveness_properties(program) {
            return Err(PipelineError::Validation(
                "Unbounded safety proof (`prove`) is safety-only, but this protocol declares only \
                 liveness properties. Use `prove-fair` / `prove_fair_liveness` for unbounded \
                 temporal liveness proofs."
                    .into(),
            ));
        }
        preflight_validate(program, options, PipelineCommand::Verify)?;
        prove_safety_program(program, options)
    })
}

/// Run an unbounded safety proof attempt via k-induction.
///
/// Uses `options.max_depth` as the maximum induction depth `k`.
///
/// # Examples
///
/// ```rust,no_run
/// use tarsier_engine::pipeline::verification::prove_safety;
/// use tarsier_engine::pipeline::{PipelineOptions, ProofEngine, SolverChoice, SoundnessMode};
///
/// let source = r#"
/// protocol TrivialLive {
///     params n, t, f;
///     resilience: n > 3*t;
///
///     adversary {
///         model: byzantine;
///         bound: f;
///     }
///
///     role R {
///         var decided: bool = true;
///         init done;
///         phase done {}
///     }
///
///     property inv: safety {
///         forall p: R. p.decided == true
///     }
/// }
/// "#;
///
/// let options = PipelineOptions {
///     solver: SolverChoice::Z3,
///     max_depth: 12,
///     timeout_secs: 30,
///     dump_smt: None,
///     soundness: SoundnessMode::Strict,
///     proof_engine: ProofEngine::KInduction,
/// };
///
/// let _result = prove_safety(source, "trivial_live.trs", &options)?;
/// # Ok::<(), tarsier_engine::pipeline::PipelineError>(())
/// ```
pub fn prove_safety(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
) -> Result<UnboundedSafetyResult, PipelineError> {
    reset_run_diagnostics();
    with_smt_profile("prove_safety", || {
        info!("Parsing {filename}...");
        let program = parse(source, filename)?;
        if !has_safety_properties(&program) && has_liveness_properties(&program) {
            return Err(PipelineError::Validation(
                "Unbounded safety proof (`prove`) is safety-only, but this protocol declares only \
                 liveness properties. Use `prove-fair` / `prove_fair_liveness` for unbounded \
                 temporal liveness proofs."
                    .into(),
            ));
        }
        preflight_validate(&program, options, PipelineCommand::Verify)?;
        prove_safety_program(&program, options)
    })
}

/// Run unbounded safety proof with adaptive CEGAR refinements.
///
/// Refinements are monotone restrictions over adversary assumptions and value
/// abstraction. If a baseline `UNSAFE` trace is eliminated by refinements and
/// no refined stage remains `UNSAFE`, the result is reported as `UNKNOWN`
/// (potentially spurious baseline trace).
pub fn prove_safety_with_cegar(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
    max_refinements: usize,
) -> Result<UnboundedSafetyResult, PipelineError> {
    reset_run_diagnostics();
    with_smt_profile("prove_safety_cegar", || {
        info!("Parsing {filename}...");
        let program = parse(source, filename)?;
        if !has_safety_properties(&program) && has_liveness_properties(&program) {
            return Err(PipelineError::Validation(
                "Unbounded safety proof (`prove`) is safety-only, but this protocol declares only \
                 liveness properties. Use `prove-fair` / `prove_fair_liveness` for unbounded \
                 temporal liveness proofs."
                    .into(),
            ));
        }
        preflight_validate(&program, options, PipelineCommand::Verify)?;

        let deadline = deadline_from_timeout_secs(options.timeout_secs);
        let baseline_options =
            match options_with_remaining_timeout(options, deadline, "CEGAR unbounded safety") {
                Ok(adjusted) => adjusted,
                Err(_) => {
                    return Ok(UnboundedSafetyResult::Unknown {
                        reason: timeout_unknown_reason("CEGAR unbounded safety"),
                    });
                }
            };

        let baseline_result = prove_safety_program(&program, &baseline_options)?;
        let baseline_is_unsafe = matches!(baseline_result, UnboundedSafetyResult::Unsafe { .. });
        if baseline_is_unsafe {
            if max_refinements == 0 {
                return Ok(baseline_result);
            }

            let trace_signals = match &baseline_result {
                UnboundedSafetyResult::Unsafe { trace } => {
                    let ta_for_signals =
                        lower_with_active_controls(&program, "prove_safety_cegar.signals")?;
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
            let mut eval_cache = CegarStageEvalCache::<UnboundedSafetyResult>::default();

            for refinement in refinement_ladder.into_iter().take(max_refinements) {
                crate::sandbox::enforce_active_limits()?;
                let refined_options = match options_with_remaining_timeout(
                    options,
                    deadline,
                    "CEGAR unbounded safety",
                ) {
                    Ok(adjusted) => adjusted,
                    Err(_) => {
                        eval_cache.emit_notes();
                        return Ok(UnboundedSafetyResult::Unknown {
                            reason: timeout_unknown_reason("CEGAR unbounded safety"),
                        });
                    }
                };
                let result = eval_cache.eval(&refinement, || {
                    let mut refined_program = program.clone();
                    refinement.apply(&mut refined_program);
                    prove_safety_program(&refined_program, &refined_options)
                })?;
                let refinement_preds = refinement.refinements();
                let mut effective_preds = refinement_preds.clone();
                match result {
                    UnboundedSafetyResult::Unsafe { .. } => {
                        eval_cache.emit_notes();
                        return Ok(result);
                    }
                    UnboundedSafetyResult::Safe { .. }
                    | UnboundedSafetyResult::ProbabilisticallySafe { .. } => {
                        if refinement.atoms.len() > 1 {
                            let maybe_core =
                                cegar_shrink_refinement_core(&refinement, |candidate| {
                                    let refined_options = match options_with_remaining_timeout(
                                        options,
                                        deadline,
                                        "CEGAR unbounded safety core extraction",
                                    ) {
                                        Ok(adjusted) => adjusted,
                                        Err(_) => return Ok(None),
                                    };
                                    let candidate_result = eval_cache.eval(candidate, || {
                                        let mut candidate_program = program.clone();
                                        candidate.apply(&mut candidate_program);
                                        prove_safety_program(&candidate_program, &refined_options)
                                    })?;
                                    Ok(Some(!matches!(
                                        candidate_result,
                                        UnboundedSafetyResult::Unsafe { .. }
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
                        if let Some(core_predicate) =
                            cegar_core_compound_predicate(&effective_preds)
                        {
                            if !discovered_predicates.contains(&core_predicate) {
                                discovered_predicates.push(core_predicate);
                            }
                        }
                    }
                    UnboundedSafetyResult::NotProved { .. }
                    | UnboundedSafetyResult::Unknown { .. } => {
                        saw_inconclusive = true;
                    }
                }
            }
            eval_cache.emit_notes();

            if saw_eliminated {
                discovered_predicates = sorted_unique_strings(discovered_predicates);
                return Ok(UnboundedSafetyResult::Unknown {
                    reason: format!(
                        "CEGAR refinements eliminated the baseline unsafe proof witness, \
                         but no refined unsafe witness was found. Potentially spurious \
                         under refinements: {}",
                        if discovered_predicates.is_empty() {
                            "<none>".into()
                        } else {
                            discovered_predicates.join(", ")
                        }
                    ),
                });
            }
            if saw_inconclusive {
                return Ok(UnboundedSafetyResult::Unknown {
                    reason: "CEGAR refinements were inconclusive; baseline unsafe witness is not \
                             confirmed under refined assumptions."
                        .into(),
                });
            }
            return Ok(UnboundedSafetyResult::Unknown {
                reason: "CEGAR refinement ladder exhausted without a confirmed unsafe or \
                         elimination witness."
                    .into(),
            });
        }

        if max_refinements == 0 {
            return Ok(baseline_result);
        }

        let Some(cti_summary) = (match &baseline_result {
            UnboundedSafetyResult::NotProved { cti: Some(cti), .. } => Some(cti.clone()),
            _ => None,
        }) else {
            return Ok(baseline_result);
        };

        info!("Attempting automatic invariant synthesis from induction CTI...");
        let mut ta = lower_with_active_controls(&program, "prove_safety_cegar.synthesis")?;
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
            return Ok(baseline_result);
        }

        let property = extract_property(&ta, &program, options.soundness)?;
        let cs = abstract_to_cs(ta.clone());
        let synthesized_locs = match synthesize_cti_zero_location_invariants(
            &ta,
            &property,
            &cti_summary,
            CtiSynthesisContext {
                cs: &cs,
                options,
                committee_bounds: &committee_bounds,
                max_refinements,
                deadline,
            },
        ) {
            Ok(locs) => locs,
            Err(PipelineError::Solver(reason)) if reason.contains("timed out") => {
                return Ok(UnboundedSafetyResult::Unknown { reason });
            }
            Err(e) => return Err(e),
        };
        if synthesized_locs.is_empty() {
            return Ok(baseline_result);
        }

        let mut labels: Vec<String> = synthesized_locs
            .iter()
            .map(|loc| format!("loc_unreachable:{}", ta.locations[*loc].name))
            .collect();
        labels.sort();
        labels.dedup();

        let run_with_engine = |engine: ProofEngine,
                               stage_options: &PipelineOptions|
         -> Result<KInductionResult, PipelineError> {
            match stage_options.solver {
                SolverChoice::Z3 => {
                    let mut solver = Z3Solver::with_timeout_secs(stage_options.timeout_secs);
                    let run_config = UnboundedEngineRunConfig {
                        cs: &cs,
                        property: &property,
                        max_k: stage_options.max_depth,
                        committee_bounds: &committee_bounds,
                        engine,
                        invariant_zero_locs: &synthesized_locs,
                        overall_timeout: overall_timeout_duration(stage_options.timeout_secs),
                    };
                    run_unbounded_with_engine_and_location_invariants(&mut solver, &run_config)
                }
                SolverChoice::Cvc5 => {
                    use tarsier_smt::backends::cvc5_backend::Cvc5Solver;
                    let mut solver = Cvc5Solver::with_timeout_secs(stage_options.timeout_secs)
                        .map_err(|e| PipelineError::Solver(e.to_string()))?;
                    let run_config = UnboundedEngineRunConfig {
                        cs: &cs,
                        property: &property,
                        max_k: stage_options.max_depth,
                        committee_bounds: &committee_bounds,
                        engine,
                        invariant_zero_locs: &synthesized_locs,
                        overall_timeout: overall_timeout_duration(stage_options.timeout_secs),
                    };
                    run_unbounded_with_engine_and_location_invariants(&mut solver, &run_config)
                }
            }
        };

        let final_stage_options =
            match options_with_remaining_timeout(options, deadline, "CEGAR unbounded safety") {
                Ok(adjusted) => adjusted,
                Err(_) => {
                    return Ok(UnboundedSafetyResult::Unknown {
                        reason: timeout_unknown_reason("CEGAR unbounded safety"),
                    });
                }
            };

        let kind_result = run_with_engine(options.proof_engine, &final_stage_options)?;

        let mut refined = kind_result_to_unbounded_safety(
            kind_result,
            &cs,
            &property,
            &committee_bounds,
            &committee_summaries,
            &final_stage_options,
        );
        match &mut refined {
            UnboundedSafetyResult::Unknown { reason } => {
                *reason = format!(
                    "{reason} Auto-synthesized predicates: {}",
                    labels.join(", ")
                );
            }
            UnboundedSafetyResult::NotProved { cti: Some(cti), .. } => {
                cti.violated_condition = format!(
                    "{} | auto-synthesized predicates: {}",
                    cti.violated_condition,
                    labels.join(", ")
                );
            }
            _ => {}
        }

        Ok(refined)
    })
}

pub fn prove_safety_with_cegar_report(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
    max_refinements: usize,
) -> Result<UnboundedSafetyCegarAuditReport, PipelineError> {
    with_smt_profile("prove_safety_cegar_report", || {
        let started_at = Instant::now();
        reset_run_diagnostics();
        info!("Parsing {filename}...");
        let program = parse(source, filename)?;
        if !has_safety_properties(&program) && has_liveness_properties(&program) {
            return Err(PipelineError::Validation(
                "Unbounded safety proof (`prove`) is safety-only, but this protocol declares only \
                 liveness properties. Use `prove-fair` / `prove_fair_liveness` for unbounded \
                 temporal liveness proofs."
                    .into(),
            ));
        }
        preflight_validate(&program, options, PipelineCommand::Verify)?;

        let deadline = deadline_from_timeout_secs(options.timeout_secs);
        let baseline_options =
            match options_with_remaining_timeout(options, deadline, "CEGAR unbounded safety") {
                Ok(adjusted) => adjusted,
                Err(_) => {
                    let baseline_result = UnboundedSafetyResult::Unknown {
                        reason: timeout_unknown_reason("CEGAR unbounded safety"),
                    };
                    let stages = vec![UnboundedSafetyCegarStageReport {
                        stage: 0,
                        label: "baseline".into(),
                        refinements: Vec::new(),
                        outcome: stage_outcome_from_unbounded_safety(&baseline_result),
                        note: Some("Global timeout exhausted before baseline stage.".into()),
                        model_changes: Vec::new(),
                        eliminated_traces: Vec::new(),
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
                    return Ok(UnboundedSafetyCegarAuditReport {
                        controls: CegarRunControls {
                            max_refinements,
                            timeout_secs: options.timeout_secs,
                            solver: solver_choice_label(options.solver).into(),
                            proof_engine: Some(proof_engine_label(options.proof_engine).into()),
                            fairness: None,
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
        let baseline_result = prove_safety_program(&program, &baseline_options)?;
        let trace_signals = match &baseline_result {
            UnboundedSafetyResult::Unsafe { trace } => {
                let ta_for_signals =
                    lower_with_active_controls(&program, "prove_safety_cegar.signals")?;
                Some(cegar_trace_signals_from_trace(&ta_for_signals, trace))
            }
            _ => None,
        };
        let baseline_is_unsafe = matches!(baseline_result, UnboundedSafetyResult::Unsafe { .. });
        let mut stages = vec![UnboundedSafetyCegarStageReport {
            stage: 0,
            label: "baseline".into(),
            refinements: Vec::new(),
            outcome: stage_outcome_from_unbounded_safety(&baseline_result),
            note: trace_signals.as_ref().and_then(cegar_signals_note),
            model_changes: Vec::new(),
            eliminated_traces: Vec::new(),
            discovered_predicates: Vec::new(),
            counterexample_analysis: cegar_stage_counterexample_analysis_unbounded_safety(
                0,
                &[],
                &baseline_result,
                baseline_is_unsafe,
                trace_signals.as_ref(),
            ),
            scored_predicates: Vec::new(),
        }];

        let mut final_result = baseline_result.clone();
        let mut discovered_predicates: Vec<String> = Vec::new();
        let mut saw_timeout = false;
        let mut saw_eliminated = false;
        let mut saw_inconclusive = false;
        let mut confirmed_unsafe = false;
        let mut eval_cache = CegarStageEvalCache::<UnboundedSafetyResult>::default();

        if !baseline_is_unsafe {
            if max_refinements > 0
                && matches!(baseline_result, UnboundedSafetyResult::NotProved { .. })
                && options.proof_engine == ProofEngine::KInduction
            {
                let synthesized =
                    prove_safety_with_cegar(source, filename, options, max_refinements)?;
                final_result = synthesized.clone();
                let note =
                    "Applied CTI-driven invariant synthesis for NOT_PROVED baseline.".to_string();
                stages.push(UnboundedSafetyCegarStageReport {
                    stage: 1,
                    label: "cti-synthesis".into(),
                    refinements: Vec::new(),
                    outcome: stage_outcome_from_unbounded_safety(&synthesized),
                    note: Some(note),
                    model_changes: Vec::new(),
                    eliminated_traces: Vec::new(),
                    discovered_predicates: Vec::new(),
                    counterexample_analysis: None,
                    scored_predicates: Vec::new(),
                });
            }

            let classification = if matches!(
                final_result,
                UnboundedSafetyResult::Safe { .. }
                    | UnboundedSafetyResult::ProbabilisticallySafe { .. }
            ) {
                "safe"
            } else {
                "inconclusive"
            };
            let termination = cegar_build_termination_from_iterations(
                "baseline_non_unsafe",
                max_refinements,
                stages.len().saturating_sub(1),
                options.timeout_secs,
                started_at,
                false,
            );
            return Ok(UnboundedSafetyCegarAuditReport {
                controls: CegarRunControls {
                    max_refinements,
                    timeout_secs: options.timeout_secs,
                    solver: solver_choice_label(options.solver).into(),
                    proof_engine: Some(proof_engine_label(options.proof_engine).into()),
                    fairness: None,
                },
                stages,
                discovered_predicates,
                baseline_result,
                final_result,
                classification: classification.into(),
                counterexample_analysis: None,
                termination,
            });
        }

        if max_refinements == 0 {
            let termination = cegar_build_termination_from_iterations(
                "iteration_budget_zero",
                max_refinements,
                0,
                options.timeout_secs,
                started_at,
                false,
            );
            return Ok(UnboundedSafetyCegarAuditReport {
            controls: CegarRunControls {
                max_refinements,
                timeout_secs: options.timeout_secs,
                solver: solver_choice_label(options.solver).into(),
                proof_engine: Some(proof_engine_label(options.proof_engine).into()),
                fairness: None,
            },
            stages,
            discovered_predicates,
            baseline_result: baseline_result.clone(),
            final_result: baseline_result,
            classification: "unsafe_unrefined".into(),
            counterexample_analysis: Some(CegarCounterexampleAnalysis {
                classification: "potentially_spurious".into(),
                rationale: "No refinement replay was performed, so the baseline UNSAFE witness is not yet confirmed under stricter assumptions.".into(),
            }),
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
                match options_with_remaining_timeout(options, deadline, "CEGAR unbounded safety") {
                    Ok(adjusted) => adjusted,
                    Err(_) => {
                        saw_timeout = true;
                        final_result = UnboundedSafetyResult::Unknown {
                            reason: timeout_unknown_reason("CEGAR unbounded safety"),
                        };
                        break;
                    }
                };
            let result = eval_cache.eval(&refinement, || {
                let mut refined_program = program.clone();
                refinement.apply(&mut refined_program);
                prove_safety_program(&refined_program, &refined_options)
            })?;
            let refinement_preds = sorted_unique_strings(refinement.refinements());
            let mut effective_preds = refinement_preds.clone();
            let model_changes = cegar_stage_model_changes(&program, &refinement);

            let mut note = match &result {
                UnboundedSafetyResult::Unsafe { .. } => Some(
                    "Counterexample persists under this refinement; treated as concrete.".into(),
                ),
                UnboundedSafetyResult::Safe { .. }
                | UnboundedSafetyResult::ProbabilisticallySafe { .. } => {
                    Some("Baseline counterexample is eliminated under this refinement.".into())
                }
                UnboundedSafetyResult::NotProved { .. } | UnboundedSafetyResult::Unknown { .. } => {
                    Some("Refinement did not produce a decisive verdict for this stage.".into())
                }
            };
            let selection_note = format!("Selection rationale: {}", plan_entry.rationale);
            note = Some(match note {
                Some(existing) => format!("{selection_note} {existing}"),
                None => selection_note,
            });

            if !matches!(result, UnboundedSafetyResult::Unsafe { .. }) && refinement.atoms.len() > 1
            {
                let maybe_core = cegar_shrink_refinement_core(&refinement, |candidate| {
                    let refined_options = match options_with_remaining_timeout(
                        options,
                        deadline,
                        "CEGAR unbounded safety core extraction",
                    ) {
                        Ok(adjusted) => adjusted,
                        Err(_) => return Ok(None),
                    };
                    let candidate_result = eval_cache.eval(candidate, || {
                        let mut candidate_program = program.clone();
                        candidate.apply(&mut candidate_program);
                        prove_safety_program(&candidate_program, &refined_options)
                    })?;
                    Ok(Some(!matches!(
                        candidate_result,
                        UnboundedSafetyResult::Unsafe { .. }
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
            let stage_counterexample_analysis =
                cegar_stage_counterexample_analysis_unbounded_safety(
                    idx + 1,
                    &effective_preds,
                    &result,
                    baseline_is_unsafe,
                    trace_signals.as_ref(),
                );
            let baseline_trace = match &stages[0].outcome {
                UnboundedSafetyCegarStageOutcome::Unsafe { trace } => Some(trace),
                _ => None,
            };
            let eliminated_traces = cegar_stage_eliminated_traces_unbounded_safety(
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

            stages.push(UnboundedSafetyCegarStageReport {
                stage: idx + 1,
                label: refinement.label(),
                refinements: sorted_unique_strings(refinement_preds.clone()),
                outcome: stage_outcome_from_unbounded_safety(&result),
                note,
                model_changes,
                eliminated_traces,
                discovered_predicates: stage_discovered_predicates,
                counterexample_analysis: stage_counterexample_analysis,
                scored_predicates: Vec::new(),
            });

            match result {
                UnboundedSafetyResult::Unsafe { .. } => {
                    final_result = result;
                    confirmed_unsafe = true;
                    break;
                }
                UnboundedSafetyResult::Safe { .. }
                | UnboundedSafetyResult::ProbabilisticallySafe { .. } => {
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
                UnboundedSafetyResult::NotProved { .. } | UnboundedSafetyResult::Unknown { .. } => {
                    saw_inconclusive = true;
                }
            }
        }
        eval_cache.emit_notes();
        discovered_predicates = sorted_unique_strings(discovered_predicates);

        if !confirmed_unsafe && saw_eliminated {
            final_result = UnboundedSafetyResult::Unknown {
            reason: "CEGAR refinements eliminated the baseline unsafe proof witness, but no refined unsafe witness was found. Treat as inconclusive and inspect the CEGAR report.".into(),
        };
        } else if !confirmed_unsafe && saw_timeout {
            final_result = UnboundedSafetyResult::Unknown {
                reason: timeout_unknown_reason("CEGAR unbounded safety"),
            };
        } else if !confirmed_unsafe && saw_inconclusive {
            final_result = UnboundedSafetyResult::Unknown {
            reason: "CEGAR refinements were inconclusive; baseline unsafe witness is not confirmed under refined assumptions."
                .into(),
        };
        }

        let classification = if confirmed_unsafe {
            "unsafe_confirmed"
        } else if saw_eliminated {
            "inconclusive"
        } else if saw_timeout {
            "timeout"
        } else {
            "inconclusive"
        };
        let counterexample_analysis = if confirmed_unsafe {
            let confirmation = stages
                .iter()
                .find(|stage| {
                    stage.stage > 0
                        && matches!(
                            stage.outcome,
                            UnboundedSafetyCegarStageOutcome::Unsafe { .. }
                        )
                })
                .map(|stage| stage.stage)
                .unwrap_or(0);
            Some(CegarCounterexampleAnalysis {
                classification: "concrete".into(),
                rationale: format!(
                    "Baseline UNSAFE witness is confirmed concrete by refined replay at stage {}.",
                    confirmation
                ),
            })
        } else if saw_eliminated {
            Some(CegarCounterexampleAnalysis {
            classification: "potentially_spurious".into(),
            rationale: format!(
                "Baseline UNSAFE witness was eliminated by refinement predicates [{}], so the overall result is inconclusive until a concrete refined UNSAFE witness is found.",
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
                rationale: timeout_unknown_reason("CEGAR unbounded safety"),
            })
        } else {
            Some(CegarCounterexampleAnalysis {
            classification: "inconclusive".into(),
            rationale: "Unable to confirm or eliminate the baseline UNSAFE witness within refinement budget.".into(),
        })
        };
        let termination_reason = if confirmed_unsafe {
            "confirmed_unsafe"
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

        Ok(UnboundedSafetyCegarAuditReport {
            controls: CegarRunControls {
                max_refinements,
                timeout_secs: options.timeout_secs,
                solver: solver_choice_label(options.solver).into(),
                proof_engine: Some(proof_engine_label(options.proof_engine).into()),
                fairness: None,
            },
            stages,
            discovered_predicates,
            baseline_result,
            final_result,
            classification: classification.into(),
            counterexample_analysis,
            termination,
        })
    })
}

/// Prove unbounded safety on an over-approximating round/view-erased abstraction.
///
/// The abstraction merges locations that differ only in erased round variables and
/// merges message counters across erased round fields. SAFE outcomes are sound for
/// the concrete model; UNSAFE outcomes may be spurious due to over-approximation.
pub fn prove_safety_with_round_abstraction(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
    erased_round_vars: &[String],
) -> Result<RoundAbstractionProofResult, PipelineError> {
    reset_run_diagnostics();
    info!("Parsing {filename}...");
    let program = parse(source, filename)?;
    preflight_validate(&program, options, PipelineCommand::Verify)?;

    if normalize_erased_var_names(erased_round_vars).is_empty() {
        return Err(PipelineError::Validation(
            "Round abstraction requires at least one erased variable name.".into(),
        ));
    }

    info!("Lowering to threshold automaton...");
    let ta = lower_with_active_controls(&program, "prove_round")?;
    ensure_n_parameter(&ta)?;

    let (abstract_ta, summary) = apply_round_erasure_abstraction(&ta, erased_round_vars);
    let result = prove_safety_for_ta(abstract_ta, &program, options)?;
    Ok(RoundAbstractionProofResult { summary, result })
}
