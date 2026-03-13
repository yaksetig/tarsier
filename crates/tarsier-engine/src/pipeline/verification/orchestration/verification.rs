//! Verification entry points and CEGAR coordination.

use crate::pipeline::verification::*;
use crate::pipeline::*;

/// Run bounded verification over the declared properties in `source`.
///
/// A passing result means no violating execution was found up to
/// `options.max_depth`. This is primarily a bug-finding and bounded-analysis
/// entrypoint, not an unbounded proof.
///
/// # Examples
///
/// ```rust,no_run
/// use tarsier_engine::pipeline::verification::verify;
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
///     max_depth: 8,
///     timeout_secs: 30,
///     dump_smt: None,
///     soundness: SoundnessMode::Strict,
///     proof_engine: ProofEngine::KInduction,
/// };
///
/// let _result = verify(source, "trivial_live.trs", &options)?;
/// # Ok::<(), tarsier_engine::pipeline::PipelineError>(())
/// ```
pub fn verify(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
) -> Result<VerificationResult, PipelineError> {
    reset_run_diagnostics();
    verify_with_cegar(source, filename, options, 0)
}

/// Run verification on an already-parsed program.
///
/// This is useful for workflows that synthesize or mutate protocol ASTs
/// (for example, round-bound sweeps) without re-rendering to source.
pub fn verify_program_ast(
    program: &ast::Program,
    options: &PipelineOptions,
) -> Result<VerificationResult, PipelineError> {
    reset_run_diagnostics();
    preflight_validate(program, options, PipelineCommand::Verify)?;
    verify_program(program, options, options.dump_smt.as_deref())
}

/// Verify all named properties in declaration order, each independently.
///
/// Safety and liveness properties are both checked in one run. Each property
/// gets its own verdict and compilation trace.
pub fn verify_all_properties(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
) -> Result<MultiPropertyResult, PipelineError> {
    reset_run_diagnostics();
    let program = tarsier_dsl::parse(source, filename)?;
    preflight_validate(&program, options, PipelineCommand::VerifyAllProperties)?;

    // Classify all properties upfront (fail-fast for unsupported shapes).
    let fragments = validate_property_fragments(&program).map_err(|diags| {
        PipelineError::Property(
            diags
                .iter()
                .map(|d| d.to_string())
                .collect::<Vec<_>>()
                .join("; "),
        )
    })?;

    // Lower automaton once (shared across all properties).
    let mut ta = lower_with_active_controls(&program, "verify")?;
    ensure_n_parameter(&ta)?;
    let committee_summaries = analyze_and_constrain_committees(&mut ta)?;
    let has_committees = !committee_summaries.is_empty();
    let committee_bounds: Vec<(usize, u64)> = ta
        .constraints
        .committees
        .iter()
        .zip(committee_summaries.iter())
        .filter_map(|(spec, summary)| spec.bound_param.map(|pid| (pid.as_usize(), summary.b_max)))
        .collect();
    let committee_failure_bound = if has_committees {
        Some(committee_summaries.iter().map(|s| s.epsilon).sum::<f64>())
    } else {
        None
    };

    if has_committees && committee_bounds.is_empty() {
        let property_kind_by_name: BTreeMap<String, String> = program
            .protocol
            .node
            .properties
            .iter()
            .map(|p| (p.node.name.clone(), p.node.kind.to_string()))
            .collect();
        let assumptions = make_property_assumptions(&ta, options, &committee_bounds, None);
        let mut verdicts = Vec::new();
        for (name, frag) in &fragments {
            let result = VerificationResult::Unknown {
                reason: "Committee analysis present, but no bound_param specified.".into(),
            };
            push_property_result_diagnostic(PropertyResultDiagnostic {
                property_id: name.clone(),
                property_name: name.clone(),
                property_kind: property_kind_by_name
                    .get(name)
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string()),
                fragment: frag.to_string(),
                verdict: result.verdict_class().to_string(),
                assumptions: assumptions.clone(),
                witness: None,
            });
            verdicts.push(PropertyVerdict {
                name: name.clone(),
                fragment: frag.to_string(),
                result,
            });
        }
        return Ok(MultiPropertyResult { verdicts });
    }

    let cs = abstract_to_cs(ta.clone());
    let fragment_by_name: BTreeMap<String, QuantifiedFragment> =
        fragments.into_iter().collect::<BTreeMap<_, _>>();
    let mut verdicts = Vec::new();

    for prop_spanned in &program.protocol.node.properties {
        let prop = &prop_spanned.node;
        let frag = fragment_by_name
            .get(&prop.name)
            .cloned()
            .unwrap_or(QuantifiedFragment::UniversalInvariant);
        let frag_name = frag.to_string();
        let mut temporal_monitor_for_witness: Option<TemporalBuchiAutomaton> = None;

        let result = match frag {
            QuantifiedFragment::UniversalAgreement | QuantifiedFragment::UniversalInvariant => {
                let property = extract_property_from_decl(&ta, prop)?;
                let compiled_payload = safety_property_canonical(&property);
                let compiled_summary = format!(
                    "target=safety_property kind={} quantifiers={}",
                    prop.kind,
                    prop.formula.quantifiers.len()
                );
                record_property_compilation(
                    "verify_all_properties",
                    prop,
                    &frag_name,
                    "safety_property",
                    compiled_summary,
                    compiled_payload,
                );

                let preview_encoding = encode_bmc(&cs, &property, options.max_depth);
                let (constraint_summary, constraint_payload) =
                    property_constraint_trace(&preview_encoding, &committee_bounds);
                record_property_compilation(
                    "verify_all_properties",
                    prop,
                    &frag_name,
                    "safety_bmc_constraints",
                    constraint_summary,
                    constraint_payload,
                );

                let (bmc_result, bmc_cs) =
                    run_bmc_for_ta(&ta, &property, options, &committee_bounds, None)?;
                if has_committees {
                    let total_epsilon = committee_failure_bound.unwrap_or(0.0);
                    match bmc_result {
                        BmcResult::Safe { depth_checked } => {
                            VerificationResult::ProbabilisticallySafe {
                                depth_checked,
                                failure_probability: total_epsilon,
                                committee_analyses: committee_summaries.clone(),
                            }
                        }
                        BmcResult::Unsafe { depth, model } => {
                            let trace = extract_trace(&bmc_cs, &model, depth);
                            VerificationResult::Unsafe { trace }
                        }
                        BmcResult::Unknown { reason, .. } => VerificationResult::Unknown { reason },
                    }
                } else {
                    bmc_result_to_verification(bmc_result, &bmc_cs)
                }
            }
            QuantifiedFragment::UniversalTermination
            | QuantifiedFragment::UniversalTemporal
            | QuantifiedFragment::ExistentialTemporal => {
                let liveness_spec = extract_liveness_spec_from_decl(&ta, prop)?;
                match &liveness_spec {
                    LivenessSpec::TerminationGoalLocs(goal_locs) => {
                        let mut sorted_goals = goal_locs.clone();
                        sorted_goals.sort_unstable();
                        let compiled_payload = format!("goal_locs={sorted_goals:?}");
                        let compiled_summary = format!(
                            "target=termination_goal_locations count={}",
                            sorted_goals.len()
                        );
                        record_property_compilation(
                            "verify_all_properties",
                            prop,
                            &frag_name,
                            "liveness_goal_locations",
                            compiled_summary,
                            compiled_payload,
                        );

                        let property = SafetyProperty::Termination {
                            goal_locs: sorted_goals.iter().copied().map(Into::into).collect(),
                        };
                        let preview_encoding = encode_bmc(&cs, &property, options.max_depth);
                        let (constraint_summary, constraint_payload) =
                            property_constraint_trace(&preview_encoding, &committee_bounds);
                        record_property_compilation(
                            "verify_all_properties",
                            prop,
                            &frag_name,
                            "liveness_bmc_constraints",
                            constraint_summary,
                            constraint_payload,
                        );
                    }
                    LivenessSpec::Temporal {
                        quantifiers,
                        formula,
                        ..
                    } => {
                        let monitor =
                            compile_temporal_buchi_automaton_with_bindings(quantifiers, formula)?;
                        temporal_monitor_for_witness = Some(monitor.clone());
                        let monitor_payload = temporal_buchi_monitor_canonical(&monitor);
                        let monitor_summary = format!(
                            "target=temporal_buchi_monitor states={} initial={} acceptance_sets={} atoms={}",
                            monitor.states.len(),
                            monitor.initial_states.len(),
                            monitor.acceptance_sets.len(),
                            monitor.atoms.len()
                        );
                        record_property_compilation(
                            "verify_all_properties",
                            prop,
                            &frag_name,
                            "temporal_buchi_monitor",
                            monitor_summary,
                            monitor_payload,
                        );

                        let preview_encoding = encode_temporal_liveness_violation_with_bindings(
                            &ta,
                            &cs,
                            quantifiers,
                            formula,
                            options.max_depth,
                            &committee_bounds,
                        )?;
                        let (constraint_summary, constraint_payload) =
                            property_constraint_trace(&preview_encoding, &committee_bounds);
                        record_property_compilation(
                            "verify_all_properties",
                            prop,
                            &frag_name,
                            "liveness_temporal_constraints",
                            constraint_summary,
                            constraint_payload,
                        );
                    }
                }
                let liveness_result = run_liveness_spec_bmc(
                    &ta,
                    &cs,
                    &liveness_spec,
                    options,
                    &committee_bounds,
                    None,
                )?;
                liveness_result_to_property_verification(liveness_result)
            }
        };
        let witness =
            build_property_witness_metadata(&ta, &result, temporal_monitor_for_witness.as_ref())?;
        let assumptions =
            make_property_assumptions(&ta, options, &committee_bounds, committee_failure_bound);
        push_property_result_diagnostic(PropertyResultDiagnostic {
            property_id: prop.name.clone(),
            property_name: prop.name.clone(),
            property_kind: prop.kind.to_string(),
            fragment: frag_name.clone(),
            verdict: result.verdict_class().to_string(),
            assumptions,
            witness,
        });

        verdicts.push(PropertyVerdict {
            name: prop.name.clone(),
            fragment: frag_name,
            result,
        });
    }

    Ok(MultiPropertyResult { verdicts })
}

pub(crate) fn verify_program(
    program: &ast::Program,
    options: &PipelineOptions,
    dump_smt: Option<&str>,
) -> Result<VerificationResult, PipelineError> {
    info!("Lowering to threshold automaton...");
    let mut ta = lower_with_active_controls(program, "verify")?;
    info!(
        locations = ta.locations.len(),
        rules = ta.rules.len(),
        "Threshold automaton constructed"
    );
    ensure_n_parameter(&ta)?;

    // Analyze committees (if any) and derive adversary bounds.
    let committee_summaries = analyze_and_constrain_committees(&mut ta)?;
    let has_committees = !committee_summaries.is_empty();

    // Collect per-committee (param_id, b_max) bounds for SMT injection.
    let committee_bounds: Vec<(usize, u64)> = ta
        .constraints
        .committees
        .iter()
        .zip(committee_summaries.iter())
        .filter_map(|(spec, summary)| spec.bound_param.map(|pid| (pid.as_usize(), summary.b_max)))
        .collect();

    if has_committees && committee_bounds.is_empty() {
        return Ok(VerificationResult::Unknown {
            reason: "Committee analysis present, but no bound_param specified; \
                     probabilistic bounds are not enforced."
                .into(),
        });
    }

    // Route by classified fragment when an explicit safety-kind property exists.
    // This allows temporal formulas under safety-kind declarations to execute via
    // the temporal liveness backend rather than being rejected at extraction.
    if let Some(prop) = select_single_safety_property_decl(program, options.soundness)? {
        let fragment = classify_property_fragment(prop)
            .map_err(|diag| PipelineError::Property(diag.to_string()))?;

        if matches!(
            fragment,
            QuantifiedFragment::UniversalTermination
                | QuantifiedFragment::UniversalTemporal
                | QuantifiedFragment::ExistentialTemporal
        ) {
            let cs = abstract_to_cs(ta.clone());
            let liveness_spec = extract_liveness_spec_from_decl(&ta, prop)?;
            crate::sandbox::enforce_active_limits()?;
            let liveness_result = run_liveness_spec_bmc(
                &ta,
                &cs,
                &liveness_spec,
                options,
                &committee_bounds,
                dump_smt,
            )?;
            return Ok(liveness_result_to_property_verification(liveness_result));
        }
    }

    let property = extract_property(&ta, program, options.soundness)?;

    info!(
        solver = ?options.solver,
        max_depth = options.max_depth,
        "Starting BMC verification..."
    );

    crate::sandbox::enforce_active_limits()?;
    let (bmc_result, cs) = run_bmc_for_ta(&ta, &property, options, &committee_bounds, dump_smt)?;

    if has_committees {
        // Union bound for overall failure probability.
        let total_epsilon: f64 = committee_summaries.iter().map(|c| c.epsilon).sum();

        match bmc_result {
            BmcResult::Safe { depth_checked } => Ok(VerificationResult::ProbabilisticallySafe {
                depth_checked,
                failure_probability: total_epsilon,
                committee_analyses: committee_summaries,
            }),
            BmcResult::Unsafe { depth, model } => {
                let trace = extract_trace(&cs, &model, depth);
                Ok(VerificationResult::Unsafe { trace })
            }
            BmcResult::Unknown { reason, .. } => Ok(VerificationResult::Unknown { reason }),
        }
    } else {
        Ok(bmc_result_to_verification(bmc_result, &cs))
    }
}

/// Run verification with adaptive CEGAR and return a stage report.
///
/// Refinements are monotone (only restrict behaviors) and are prioritized from
/// baseline counterexample signals. The schedule evaluates single refinements
/// first, then cumulative combinations; elimination cores are greedily shrunk.
pub fn verify_with_cegar_report(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
    max_refinements: usize,
) -> Result<CegarAuditReport, PipelineError> {
    with_smt_profile("verify_cegar", || {
        let started_at = Instant::now();
        reset_run_diagnostics();
        info!("Parsing {filename}...");
        let program = parse(source, filename)?;
        preflight_validate(&program, options, PipelineCommand::Verify)?;

        let deadline = deadline_from_timeout_secs(options.timeout_secs);
        let baseline_options =
            match options_with_remaining_timeout(options, deadline, "CEGAR verification") {
                Ok(adjusted) => adjusted,
                Err(_) => {
                    let baseline_result = VerificationResult::Unknown {
                        reason: timeout_unknown_reason("CEGAR verification"),
                    };
                    return Ok(CegarAuditReport {
                        max_refinements,
                        stages: vec![CegarStageReport {
                            stage: 0,
                            label: "baseline".into(),
                            refinements: Vec::new(),
                            outcome: stage_outcome_from_verification(&baseline_result),
                            note: Some("Global timeout exhausted before baseline stage.".into()),
                            model_changes: Vec::new(),
                            eliminated_traces: Vec::new(),
                            discovered_predicates: Vec::new(),
                            counterexample_analysis: None,
                            scored_predicates: Vec::new(),
                        }],
                        discovered_predicates: Vec::new(),
                        classification: "timeout".into(),
                        counterexample_analysis: None,
                        termination: cegar_build_termination(
                            "baseline_timeout",
                            max_refinements,
                            &[],
                            options.timeout_secs,
                            started_at,
                            true,
                        ),
                        final_result: baseline_result,
                    });
                }
            };

        let baseline_result = verify_program(
            &program,
            &baseline_options,
            baseline_options.dump_smt.as_deref(),
        )?;
        let (trace_signals, scoring_context) = match &baseline_result {
            VerificationResult::Unsafe { trace } => {
                let ta_for_signals = lower_with_active_controls(&program, "verify_cegar.signals")?;
                let signals = cegar_trace_signals_from_trace(&ta_for_signals, trace);
                (
                    Some(signals.clone()),
                    Some((ta_for_signals, trace.clone(), signals)),
                )
            }
            _ => (None, None),
        };
        let baseline_is_unsafe = matches!(baseline_result, VerificationResult::Unsafe { .. });
        let mut stages = vec![CegarStageReport {
            stage: 0,
            label: "baseline".into(),
            refinements: Vec::new(),
            outcome: stage_outcome_from_verification(&baseline_result),
            note: trace_signals.as_ref().and_then(cegar_signals_note),
            model_changes: Vec::new(),
            eliminated_traces: Vec::new(),
            discovered_predicates: Vec::new(),
            counterexample_analysis: cegar_stage_counterexample_analysis(
                0,
                &[],
                &baseline_result,
                baseline_is_unsafe,
                trace_signals.as_ref(),
            ),
            scored_predicates: Vec::new(),
        }];
        let mut discovered_predicates: Vec<String> = Vec::new();
        let mut saw_timeout = false;

        if !baseline_is_unsafe || max_refinements == 0 {
            let classification = if baseline_is_unsafe {
                "unsafe_unrefined"
            } else if matches!(
                baseline_result,
                VerificationResult::Safe { .. } | VerificationResult::ProbabilisticallySafe { .. }
            ) {
                "safe"
            } else {
                "inconclusive"
            };
            let termination = cegar_build_termination(
                if baseline_is_unsafe {
                    "iteration_budget_zero"
                } else {
                    "baseline_non_unsafe"
                },
                max_refinements,
                &stages,
                options.timeout_secs,
                started_at,
                false,
            );
            return Ok(CegarAuditReport {
                max_refinements,
                stages,
                discovered_predicates,
                classification: classification.into(),
                counterexample_analysis: if baseline_is_unsafe {
                    Some(CegarCounterexampleAnalysis {
                    classification: "potentially_spurious".into(),
                    rationale: "No refinement replay was performed, so the baseline UNSAFE witness is not yet confirmed under stricter assumptions.".into(),
                })
                } else {
                    None
                },
                termination,
                final_result: baseline_result,
            });
        }

        let mut final_result = baseline_result.clone();
        let mut saw_eliminated = false;
        let mut saw_inconclusive = false;
        let mut confirmed_unsafe = false;
        let mut eval_cache = CegarStageEvalCache::<VerificationResult>::default();
        let refinement_plan = cegar_refinement_plan_with_signals(
            &program,
            trace_signals.as_ref(),
            options.solver,
            options.timeout_secs,
        );

        // Pre-compute scored predicates for machine-readable reporting.
        let all_scored_predicates: Vec<CegarPredicateScore> =
            if let Some((ref ta, ref trace, ref signals)) = scoring_context {
                let mut atomics = cegar_atomic_refinements(&program);
                atomics.extend(cegar_trace_generated_refinements(&program, signals));
                let mut seen = HashSet::new();
                atomics.retain(|a| seen.insert(a.label.clone()));
                let requirements = cegar_evidence_requirements(&atomics, signals);
                let core_indices: Vec<usize> = cegar_unsat_core_seed(
                    &atomics,
                    &requirements,
                    options.solver,
                    options.timeout_secs,
                )
                .map(|seed| seed.selected_indices)
                .unwrap_or_default();
                cegar_build_scored_predicates(&atomics, signals, ta, trace, &core_indices)
            } else {
                Vec::new()
            };

        for (idx, plan_entry) in refinement_plan
            .into_iter()
            .take(max_refinements)
            .enumerate()
        {
            crate::sandbox::enforce_active_limits()?;
            let refinement = plan_entry.refinement;
            let refined_options =
                match options_with_remaining_timeout(options, deadline, "CEGAR verification") {
                    Ok(adjusted) => adjusted,
                    Err(_) => {
                        saw_timeout = true;
                        final_result = VerificationResult::Unknown {
                            reason: timeout_unknown_reason("CEGAR verification"),
                        };
                        break;
                    }
                };
            let result = eval_cache.eval(&refinement, || {
                let mut refined_program = program.clone();
                refinement.apply(&mut refined_program);
                verify_program(&refined_program, &refined_options, None)
            })?;
            let refinement_preds = sorted_unique_strings(refinement.refinements());
            let mut effective_preds = refinement_preds.clone();
            let model_changes = cegar_stage_model_changes(&program, &refinement);

            let mut note = match &result {
                VerificationResult::Unsafe { .. } => Some(
                    "Counterexample persists under this refinement; treated as concrete.".into(),
                ),
                VerificationResult::Safe { .. }
                | VerificationResult::ProbabilisticallySafe { .. } => {
                    Some("Baseline counterexample is eliminated under this refinement.".into())
                }
                VerificationResult::Unknown { .. } => {
                    Some("Refinement did not produce a decisive verdict for this stage.".into())
                }
            };
            let selection_note = format!("Selection rationale: {}", plan_entry.rationale);
            note = Some(match note {
                Some(existing) => format!("{selection_note} {existing}"),
                None => selection_note,
            });

            if !matches!(result, VerificationResult::Unsafe { .. }) && refinement.atoms.len() > 1 {
                let maybe_core = cegar_shrink_refinement_core(&refinement, |candidate| {
                    let refined_options = match options_with_remaining_timeout(
                        options,
                        deadline,
                        "CEGAR refinement-core extraction",
                    ) {
                        Ok(adjusted) => adjusted,
                        Err(_) => return Ok(None),
                    };
                    let candidate_result = eval_cache.eval(candidate, || {
                        let mut candidate_program = program.clone();
                        candidate.apply(&mut candidate_program);
                        verify_program(&candidate_program, &refined_options, None)
                    })?;
                    Ok(Some(!matches!(
                        candidate_result,
                        VerificationResult::Unsafe { .. }
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
            let stage_counterexample_analysis = cegar_stage_counterexample_analysis(
                idx + 1,
                &effective_preds,
                &result,
                baseline_is_unsafe,
                trace_signals.as_ref(),
            );
            let baseline_trace = match &stages[0].outcome {
                CegarStageOutcome::Unsafe { trace } => Some(trace),
                _ => None,
            };
            let eliminated_traces =
                cegar_stage_eliminated_traces(idx + 1, &result, baseline_trace, &effective_preds);
            let stage_discovered_predicates = if eliminated_traces.is_empty() {
                Vec::new()
            } else {
                let mut preds = effective_preds.clone();
                if let Some(core_predicate) = cegar_core_compound_predicate(&effective_preds) {
                    preds.push(core_predicate);
                }
                sorted_unique_strings(preds)
            };

            // Attach scored predicates relevant to this stage's refinements.
            let stage_scored: Vec<CegarPredicateScore> = {
                let stage_pred_set: HashSet<&str> =
                    refinement_preds.iter().map(|s| s.as_str()).collect();
                all_scored_predicates
                    .iter()
                    .filter(|sp| stage_pred_set.contains(sp.predicate.as_str()))
                    .cloned()
                    .collect()
            };

            stages.push(CegarStageReport {
                stage: idx + 1,
                label: refinement.label(),
                refinements: sorted_unique_strings(refinement_preds.clone()),
                outcome: stage_outcome_from_verification(&result),
                note,
                model_changes,
                eliminated_traces,
                discovered_predicates: stage_discovered_predicates,
                counterexample_analysis: stage_counterexample_analysis,
                scored_predicates: stage_scored,
            });

            match result {
                VerificationResult::Unsafe { .. } => {
                    final_result = result;
                    confirmed_unsafe = true;
                    break;
                }
                VerificationResult::Safe { .. }
                | VerificationResult::ProbabilisticallySafe { .. } => {
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
                VerificationResult::Unknown { .. } => {
                    saw_inconclusive = true;
                }
            }
        }
        eval_cache.emit_notes();
        discovered_predicates = sorted_unique_strings(discovered_predicates);

        if !confirmed_unsafe && saw_eliminated {
            final_result = VerificationResult::Unknown {
                reason: "CEGAR refinements eliminated the baseline counterexample, but no refined \
                     unsafe witness was found. Treat as inconclusive and inspect the CEGAR report."
                    .into(),
            };
        } else if !confirmed_unsafe && saw_timeout {
            final_result = VerificationResult::Unknown {
                reason: timeout_unknown_reason("CEGAR verification"),
            };
        } else if !confirmed_unsafe && saw_inconclusive {
            final_result = VerificationResult::Unknown {
                reason: "CEGAR refinements were inconclusive; baseline counterexample is not \
                     confirmed under refined assumptions."
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
        let counterexample_analysis = if !baseline_is_unsafe {
            None
        } else if confirmed_unsafe {
            let confirmation = stages
                .iter()
                .find(|stage| {
                    stage.stage > 0 && matches!(&stage.outcome, CegarStageOutcome::Unsafe { .. })
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
                rationale: timeout_unknown_reason("CEGAR verification"),
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
        let termination = cegar_build_termination(
            termination_reason,
            max_refinements,
            &stages,
            options.timeout_secs,
            started_at,
            saw_timeout,
        );

        Ok(CegarAuditReport {
            max_refinements,
            stages,
            discovered_predicates,
            classification: classification.into(),
            counterexample_analysis,
            termination,
            final_result,
        })
    })
}

/// Run verification with CEGAR refinement and return the final verdict.
pub fn verify_with_cegar(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
    max_refinements: usize,
) -> Result<VerificationResult, PipelineError> {
    reset_run_diagnostics();
    let report = verify_with_cegar_report(source, filename, options, max_refinements)?;
    Ok(report.final_result)
}
