//! Top-level verification entry points and CEGAR loop drivers.

use super::*;

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
        .committees
        .iter()
        .zip(committee_summaries.iter())
        .filter_map(|(spec, summary)| spec.bound_param.map(|pid| (pid, summary.b_max)))
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
                            goal_locs: sorted_goals,
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
        .committees
        .iter()
        .zip(committee_summaries.iter())
        .filter_map(|(spec, summary)| spec.bound_param.map(|pid| (pid, summary.b_max)))
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

pub(crate) fn prove_safety_for_ta(
    mut ta: ThresholdAutomaton,
    program: &ast::Program,
    options: &PipelineOptions,
) -> Result<UnboundedSafetyResult, PipelineError> {
    let committee_summaries = analyze_and_constrain_committees(&mut ta)?;
    let has_committees = !committee_summaries.is_empty();
    let committee_bounds: Vec<(usize, u64)> = ta
        .committees
        .iter()
        .zip(committee_summaries.iter())
        .filter_map(|(spec, summary)| spec.bound_param.map(|pid| (pid, summary.b_max)))
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

/// Run an unbounded safety proof attempt via k-induction.
///
/// Uses `options.max_depth` as the maximum induction depth `k`.
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
            .committees
            .iter()
            .zip(committee_summaries.iter())
            .filter_map(|(spec, summary)| spec.bound_param.map(|pid| (pid, summary.b_max)))
            .collect();

        if has_committees && committee_bounds.is_empty() {
            return Ok(baseline_result);
        }

        let property = extract_property(&ta, &program, options.soundness)?;
        let cs = abstract_to_cs(ta.clone());
        let candidate_budget = (max_refinements.max(1)) * 2;
        let candidates =
            cti_zero_location_candidates(&ta, &property, &cti_summary, candidate_budget);
        if candidates.is_empty() {
            return Ok(baseline_result);
        }

        let mut synthesized_locs = Vec::new();
        for loc in candidates {
            let synthesis_options = match options_with_remaining_timeout(
                options,
                deadline,
                "CTI predicate synthesis",
            ) {
                Ok(adjusted) => adjusted,
                Err(_) => {
                    return Ok(UnboundedSafetyResult::Unknown {
                        reason: timeout_unknown_reason("CTI predicate synthesis"),
                    });
                }
            };
            if prove_location_unreachable_for_synthesis(
                &cs,
                &synthesis_options,
                &committee_bounds,
                loc,
            )? {
                synthesized_locs.push(loc);
            }
            if synthesized_locs.len() >= max_refinements.max(1) {
                break;
            }
        }
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
                    run_unbounded_with_engine_and_location_invariants(
                        &mut solver,
                        &cs,
                        &property,
                        stage_options.max_depth,
                        &committee_bounds,
                        engine,
                        &synthesized_locs,
                        overall_timeout_duration(stage_options.timeout_secs),
                    )
                }
                SolverChoice::Cvc5 => {
                    use tarsier_smt::backends::cvc5_backend::Cvc5Solver;
                    let mut solver = Cvc5Solver::with_timeout_secs(stage_options.timeout_secs)
                        .map_err(|e| PipelineError::Solver(e.to_string()))?;
                    run_unbounded_with_engine_and_location_invariants(
                        &mut solver,
                        &cs,
                        &property,
                        stage_options.max_depth,
                        &committee_bounds,
                        engine,
                        &synthesized_locs,
                        overall_timeout_duration(stage_options.timeout_secs),
                    )
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

pub fn check_liveness(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
) -> Result<LivenessResult, PipelineError> {
    reset_run_diagnostics();
    with_smt_profile("check_liveness", || {
        push_reduction_note("encoder.structural_hashing=on");
        info!("Parsing {filename}...");
        let program = parse(source, filename)?;
        preflight_validate(&program, options, PipelineCommand::Liveness)?;

        info!("Lowering to threshold automaton...");
        let mut ta = lower_with_active_controls(&program, "check_liveness")?;
        ensure_n_parameter(&ta)?;

        // Analyze committees (if any) and derive adversary bounds
        let committee_summaries = analyze_and_constrain_committees(&mut ta)?;
        let has_committees = !committee_summaries.is_empty();

        // Collect per-committee (param_id, b_max) bounds for SMT injection
        let committee_bounds: Vec<(usize, u64)> = ta
            .committees
            .iter()
            .zip(committee_summaries.iter())
            .filter_map(|(spec, summary)| spec.bound_param.map(|pid| (pid, summary.b_max)))
            .collect();

        if has_committees && committee_bounds.is_empty() {
            return Ok(LivenessResult::Unknown {
                reason: "Committee analysis present, but no bound_param specified; \
                     probabilistic bounds are not enforced."
                    .into(),
            });
        }

        let cs = abstract_to_cs(ta.clone());
        let liveness_spec = extract_liveness_spec(&ta, &program)?;
        match liveness_spec {
            LivenessSpec::TerminationGoalLocs(goal_locs) => {
                if goal_locs.is_empty() {
                    return Err(PipelineError::Property(
                    "Liveness check requires either a `property ...: liveness { ... }` declaration or a boolean local variable named `decided`."
                        .into(),
                ));
                }

                let property = SafetyProperty::Termination { goal_locs };
                if let Some(ref path) = options.dump_smt {
                    let extra = committee_bound_assertions(&committee_bounds);
                    dump_smt_to_file(&cs, &property, options.max_depth, path, &extra);
                }
                let bmc_result = match options.solver {
                    SolverChoice::Z3 => {
                        let mut solver = Z3Solver::with_timeout_secs(options.timeout_secs);
                        run_bmc_with_committee_bounds_at_depth(
                            &mut solver,
                            &cs,
                            &property,
                            options.max_depth,
                            &committee_bounds,
                        )?
                    }
                    SolverChoice::Cvc5 => {
                        use tarsier_smt::backends::cvc5_backend::Cvc5Solver;
                        let mut solver = Cvc5Solver::with_timeout_secs(options.timeout_secs)
                            .map_err(|e| PipelineError::Solver(e.to_string()))?;
                        run_bmc_with_committee_bounds_at_depth(
                            &mut solver,
                            &cs,
                            &property,
                            options.max_depth,
                            &committee_bounds,
                        )?
                    }
                };
                match bmc_result {
                    BmcResult::Safe { depth_checked } => Ok(LivenessResult::Live { depth_checked }),
                    BmcResult::Unsafe { depth, model } => {
                        let trace = extract_trace(&cs, &model, depth);
                        Ok(LivenessResult::NotLive { trace })
                    }
                    BmcResult::Unknown { reason, .. } => Ok(LivenessResult::Unknown { reason }),
                }
            }
            LivenessSpec::Temporal {
                quantifiers,
                formula,
                ..
            } => {
                let dummy_property = SafetyProperty::Agreement {
                    conflicting_pairs: Vec::new(),
                };
                let mut encoding = encode_bmc(&cs, &dummy_property, options.max_depth);
                if !encoding.assertions.is_empty() {
                    encoding.assertions.pop();
                }
                let extra = committee_bound_assertions(&committee_bounds);
                encoding.assertions.extend(extra.iter().cloned());
                let satisfied = encode_quantified_temporal_formula_term_with_bindings(
                    &ta,
                    &quantifiers,
                    &formula,
                    0,
                    options.max_depth,
                )?;
                encoding.assertions.push(SmtTerm::not(satisfied));
                if let Some(ref path) = options.dump_smt {
                    let smt = query_to_smt2_script(&encoding.declarations, &encoding.assertions);
                    if let Err(e) = std::fs::write(path, smt) {
                        eprintln!("Warning: could not write SMT dump to {path}: {e}");
                    } else {
                        info!("SMT dump written to {path}");
                    }
                }
                let bmc_result = match options.solver {
                    SolverChoice::Z3 => {
                        let mut solver = Z3Solver::with_timeout_secs(options.timeout_secs);
                        run_single_depth_bmc_encoding(&mut solver, &encoding, options.max_depth)
                            .map_err(|e| PipelineError::Solver(e.to_string()))?
                    }
                    SolverChoice::Cvc5 => {
                        use tarsier_smt::backends::cvc5_backend::Cvc5Solver;
                        let mut solver = Cvc5Solver::with_timeout_secs(options.timeout_secs)
                            .map_err(|e| PipelineError::Solver(e.to_string()))?;
                        run_single_depth_bmc_encoding(&mut solver, &encoding, options.max_depth)
                            .map_err(|e| PipelineError::Solver(e.to_string()))?
                    }
                };
                match bmc_result {
                    BmcResult::Safe { depth_checked } => Ok(LivenessResult::Live { depth_checked }),
                    BmcResult::Unsafe { depth, model } => {
                        let trace = extract_trace(&cs, &model, depth);
                        Ok(LivenessResult::NotLive { trace })
                    }
                    BmcResult::Unknown { reason, .. } => Ok(LivenessResult::Unknown { reason }),
                }
            }
        }
    })
}

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
        let result = eval_cache.eval(&refinement, || {
            let mut refined_program = program.clone();
            refinement.apply(&mut refined_program);
            prove_fair_liveness_program_with_mode(&refined_program, &refined_options, fairness)
        })?;
        let refinement_preds = refinement.refinements();
        let mut effective_preds = refinement_preds.clone();
        match result {
            UnboundedFairLivenessResult::FairCycleFound { .. } => {
                eval_cache.emit_notes();
                return Ok(result);
            }
            UnboundedFairLivenessResult::LiveProved { .. } => {
                if refinement.atoms.len() > 1 {
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
        let result = eval_cache.eval(&refinement, || {
            let mut refined_program = program.clone();
            refinement.apply(&mut refined_program);
            prove_fair_liveness_program_with_mode(&refined_program, &refined_options, fairness)
        })?;
        let refinement_preds = sorted_unique_strings(refinement.refinements());
        let mut effective_preds = refinement_preds.clone();
        let model_changes = cegar_stage_model_changes(&program, &refinement);

        let mut note = match &result {
            UnboundedFairLivenessResult::FairCycleFound { .. } => Some(
                "Fair-cycle witness persists under this refinement; treated as concrete.".into(),
            ),
            UnboundedFairLivenessResult::LiveProved { .. } => {
                Some("Baseline fair-cycle witness is eliminated under this refinement.".into())
            }
            UnboundedFairLivenessResult::NotProved { .. }
            | UnboundedFairLivenessResult::Unknown { .. } => {
                Some("Refinement did not produce a decisive verdict for this stage.".into())
            }
        };
        let selection_note = format!("Selection rationale: {}", plan_entry.rationale);
        note = Some(match note {
            Some(existing) => format!("{selection_note} {existing}"),
            None => selection_note,
        });

        if !matches!(result, UnboundedFairLivenessResult::FairCycleFound { .. })
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
            label: refinement.label(),
            refinements: sorted_unique_strings(refinement_preds.clone()),
            outcome: stage_outcome_from_unbounded_fair_liveness(&result),
            note,
            model_changes,
            eliminated_traces,
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
        .committees
        .iter()
        .zip(committee_summaries.iter())
        .filter_map(|(spec, summary)| spec.bound_param.map(|pid| (pid, summary.b_max)))
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
            .committees
            .iter()
            .zip(committee_summaries.iter())
            .filter_map(|(spec, summary)| spec.bound_param.map(|pid| (pid, summary.b_max)))
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
