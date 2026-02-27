//! BMC execution, committee bounds, k-induction, and CTI analysis helpers.

use super::*;

pub(crate) fn with_smt_profile<T, F>(context: &str, run: F) -> Result<T, PipelineError>
where
    F: FnOnce() -> Result<T, PipelineError>,
{
    reset_smt_run_profile();
    let check_started = Instant::now();
    let result = run();
    push_phase_profile(context, "check", check_started.elapsed().as_millis());
    let profile = take_smt_run_profile();
    let has_activity = profile.encode_calls > 0
        || profile.solve_calls > 0
        || profile.assertion_candidates > 0
        || profile.assertion_unique > 0
        || profile.assertion_dedup_hits > 0;
    if has_activity {
        push_phase_profile(context, "encode", profile.encode_elapsed_ms);
        push_phase_profile(context, "solve", profile.solve_elapsed_ms);
        push_smt_profile(context, profile);
    }
    result
}

pub(crate) fn liveness_result_to_property_verification(
    result: LivenessResult,
) -> VerificationResult {
    match result {
        LivenessResult::Live { depth_checked } => VerificationResult::Safe { depth_checked },
        LivenessResult::NotLive { trace } => VerificationResult::Unsafe { trace },
        LivenessResult::Unknown { reason } => VerificationResult::Unknown { reason },
    }
}

pub(crate) fn property_constraint_trace(
    encoding: &BmcEncoding,
    committee_bounds: &[(usize, u64)],
) -> (String, String) {
    let extra = committee_bound_assertions(committee_bounds);
    let smt = encoding_to_smt2_script(encoding, &extra);
    let summary = format!(
        "depth_encoding declarations={} assertions={} committee_bounds={}",
        encoding.declarations.len(),
        encoding.assertions.len(),
        committee_bounds.len()
    );
    (summary, smt)
}

pub(crate) fn solver_choice_name(solver: SolverChoice) -> &'static str {
    match solver {
        SolverChoice::Z3 => "z3",
        SolverChoice::Cvc5 => "cvc5",
    }
}

pub(crate) fn soundness_mode_name(soundness: SoundnessMode) -> &'static str {
    match soundness {
        SoundnessMode::Strict => "strict",
        SoundnessMode::Permissive => "permissive",
    }
}

pub(crate) fn named_committee_bounds(
    ta: &ThresholdAutomaton,
    bounds: &[(usize, u64)],
) -> Vec<(String, u64)> {
    let mut named = bounds
        .iter()
        .map(|(pid, bound)| {
            let name = ta
                .parameters
                .get(*pid)
                .map(|p| p.name.clone())
                .unwrap_or_else(|| format!("param#{pid}"));
            (name, *bound)
        })
        .collect::<Vec<_>>();
    named.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    named
}

pub(crate) fn make_property_assumptions(
    ta: &ThresholdAutomaton,
    options: &PipelineOptions,
    committee_bounds: &[(usize, u64)],
    failure_probability_bound: Option<f64>,
) -> PropertyAssumptionsDiagnostic {
    PropertyAssumptionsDiagnostic {
        solver: solver_choice_name(options.solver).to_string(),
        soundness: soundness_mode_name(options.soundness).to_string(),
        max_depth: options.max_depth,
        network_semantics: network_semantics_name(ta.network_semantics).to_string(),
        committee_bounds: named_committee_bounds(ta, committee_bounds),
        failure_probability_bound,
    }
}

pub(crate) fn trace_config_at_step(
    trace: &tarsier_ir::counter_system::Trace,
    step: usize,
) -> &tarsier_ir::counter_system::Configuration {
    if step == 0 {
        &trace.initial_config
    } else {
        trace
            .steps
            .get(step.saturating_sub(1))
            .map(|s| &s.config)
            .unwrap_or_else(|| {
                trace
                    .steps
                    .last()
                    .map(|s| &s.config)
                    .unwrap_or(&trace.initial_config)
            })
    }
}

pub(crate) fn eval_quantified_atom_on_config(
    ta: &ThresholdAutomaton,
    config: &tarsier_ir::counter_system::Configuration,
    quantifier: ast::Quantifier,
    quantified_var: &str,
    role: &str,
    atom: &ast::FormulaExpr,
) -> Result<bool, PipelineError> {
    match quantifier {
        ast::Quantifier::ForAll => {
            for (loc_id, loc) in ta.locations.iter().enumerate() {
                if loc.role != role {
                    continue;
                }
                let occupants = config.kappa.get(loc_id).copied().unwrap_or(0);
                if occupants <= 0 {
                    continue;
                }
                if !eval_formula_expr_on_location(atom, quantified_var, loc)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        ast::Quantifier::Exists => {
            for (loc_id, loc) in ta.locations.iter().enumerate() {
                if loc.role != role {
                    continue;
                }
                let occupants = config.kappa.get(loc_id).copied().unwrap_or(0);
                if occupants <= 0 {
                    continue;
                }
                if eval_formula_expr_on_location(atom, quantified_var, loc)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}

pub(crate) fn temporal_monitor_trace_from_counterexample(
    ta: &ThresholdAutomaton,
    monitor: &TemporalBuchiAutomaton,
    trace: &tarsier_ir::counter_system::Trace,
) -> Result<Vec<PropertyTemporalMonitorStepDiagnostic>, PipelineError> {
    let max_step = trace.steps.len();
    let mut atom_truth_by_step: Vec<Vec<bool>> = Vec::with_capacity(max_step + 1);
    for step in 0..=max_step {
        let cfg = trace_config_at_step(trace, step);
        let mut atom_truth = Vec::with_capacity(monitor.atoms.len());
        for atom in &monitor.atoms {
            atom_truth.push(eval_quantified_atom_on_config(
                ta,
                cfg,
                monitor.quantifier,
                &monitor.quantified_var,
                &monitor.role,
                atom,
            )?);
        }
        atom_truth_by_step.push(atom_truth);
    }

    let state_matches = |state_id: usize, atom_truth: &[bool]| -> bool {
        monitor.states[state_id]
            .label_lits
            .iter()
            .all(|lit| match lit {
                TemporalAtomLit::Pos(atom_id) => atom_truth.get(*atom_id).copied().unwrap_or(false),
                TemporalAtomLit::Neg(atom_id) => {
                    !atom_truth.get(*atom_id).copied().unwrap_or(false)
                }
            })
    };

    let mut active_states: Vec<usize> = monitor
        .initial_states
        .iter()
        .copied()
        .filter(|sid| state_matches(*sid, &atom_truth_by_step[0]))
        .collect();
    active_states.sort_unstable();
    active_states.dedup();

    let mut replay = Vec::with_capacity(max_step + 1);
    for step in 0..=max_step {
        let atom_truth = &atom_truth_by_step[step];
        let true_atoms = atom_truth
            .iter()
            .enumerate()
            .filter_map(|(id, holds)| if *holds { Some(id) } else { None })
            .collect::<Vec<_>>();
        let acceptance_sets_hit = monitor
            .acceptance_sets
            .iter()
            .enumerate()
            .filter_map(|(acc_id, states)| {
                if active_states.iter().any(|sid| states.contains(sid)) {
                    Some(acc_id)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        replay.push(PropertyTemporalMonitorStepDiagnostic {
            step,
            active_states: active_states.clone(),
            true_atoms,
            acceptance_sets_hit,
        });

        if step == max_step {
            break;
        }
        let mut next_candidates = Vec::new();
        for sid in &active_states {
            next_candidates.extend(monitor.states[*sid].transitions.iter().copied());
        }
        next_candidates.sort_unstable();
        next_candidates.dedup();
        active_states = next_candidates
            .into_iter()
            .filter(|sid| state_matches(*sid, &atom_truth_by_step[step + 1]))
            .collect();
    }

    Ok(replay)
}

pub(crate) fn build_property_witness_metadata(
    ta: &ThresholdAutomaton,
    result: &VerificationResult,
    temporal_monitor: Option<&TemporalBuchiAutomaton>,
) -> Result<Option<PropertyWitnessMetadataDiagnostic>, PipelineError> {
    let VerificationResult::Unsafe { trace } = result else {
        return Ok(None);
    };
    let trace_steps = trace.steps.len();
    let mut witness = PropertyWitnessMetadataDiagnostic {
        witness_kind: "counterexample_trace".to_string(),
        trace_steps,
        violation_step: Some(trace_steps),
        temporal_monitor: None,
    };
    if let Some(monitor) = temporal_monitor {
        witness.witness_kind = "temporal_monitor_counterexample".to_string();
        witness.temporal_monitor = Some(temporal_monitor_trace_from_counterexample(
            ta, monitor, trace,
        )?);
    }
    Ok(Some(witness))
}

pub(crate) fn solver_choice_label(solver: SolverChoice) -> &'static str {
    match solver {
        SolverChoice::Z3 => "z3",
        SolverChoice::Cvc5 => "cvc5",
    }
}

pub(crate) fn proof_engine_label(engine: ProofEngine) -> &'static str {
    match engine {
        ProofEngine::KInduction => "kinduction",
        ProofEngine::Pdr => "pdr",
    }
}

pub(crate) fn fairness_mode_label(fairness: FairnessMode) -> &'static str {
    match fairness {
        FairnessMode::Weak => "weak",
        FairnessMode::Strong => "strong",
    }
}

pub(crate) fn run_bmc_for_ta(
    ta: &ThresholdAutomaton,
    property: &SafetyProperty,
    options: &PipelineOptions,
    committee_bounds: &[(usize, u64)],
    dump_smt_path: Option<&str>,
) -> Result<(BmcResult, CounterSystem), PipelineError> {
    push_reduction_note("encoder.structural_hashing=on");
    push_reduction_note("bmc.incremental_depth_reuse=on");
    let cs = abstract_to_cs(ta.clone());
    if let Some(path) = dump_smt_path {
        let extra = committee_bound_assertions(committee_bounds);
        dump_smt_to_file(&cs, property, options.max_depth, path, &extra);
    }

    let result = match options.solver {
        SolverChoice::Z3 => {
            let mut solver = Z3Solver::with_timeout_secs(options.timeout_secs);
            run_bmc_with_committee_bounds(
                &mut solver,
                &cs,
                property,
                options.max_depth,
                committee_bounds,
                overall_timeout_duration(options.timeout_secs),
            )?
        }
        SolverChoice::Cvc5 => {
            use tarsier_smt::backends::cvc5_backend::Cvc5Solver;
            let mut solver = Cvc5Solver::with_timeout_secs(options.timeout_secs)
                .map_err(|e| PipelineError::Solver(e.to_string()))?;
            run_bmc_with_committee_bounds(
                &mut solver,
                &cs,
                property,
                options.max_depth,
                committee_bounds,
                overall_timeout_duration(options.timeout_secs),
            )?
        }
    };

    Ok((result, cs))
}

pub(crate) fn safety_property_canonical(property: &SafetyProperty) -> String {
    match property {
        SafetyProperty::Agreement { conflicting_pairs } => {
            let mut pairs = conflicting_pairs.clone();
            pairs.sort_unstable();
            format!("agreement:{pairs:?}")
        }
        SafetyProperty::Invariant { bad_sets } => {
            let mut sorted_sets = bad_sets.clone();
            for set in &mut sorted_sets {
                set.sort_unstable();
            }
            sorted_sets.sort();
            format!("invariant:{sorted_sets:?}")
        }
        SafetyProperty::Termination { goal_locs } => {
            let mut locs = goal_locs.clone();
            locs.sort_unstable();
            format!("termination:{locs:?}")
        }
    }
}

pub(crate) fn encode_temporal_liveness_violation_with_bindings(
    ta: &ThresholdAutomaton,
    cs: &CounterSystem,
    quantifiers: &[ast::QuantifierBinding],
    formula: &ast::FormulaExpr,
    depth: usize,
    committee_bounds: &[(usize, u64)],
) -> Result<BmcEncoding, PipelineError> {
    let dummy_property = SafetyProperty::Agreement {
        conflicting_pairs: Vec::new(),
    };
    let mut encoding = encode_bmc(cs, &dummy_property, depth);
    if !encoding.assertions.is_empty() {
        encoding.assertions.pop();
    }
    let extra = committee_bound_assertions(committee_bounds);
    encoding.assertions.extend(extra.iter().cloned());
    let satisfied =
        encode_quantified_temporal_formula_term_with_bindings(ta, quantifiers, formula, 0, depth)?;
    encoding.assertions.push(SmtTerm::not(satisfied));
    Ok(encoding)
}

pub(crate) fn bmc_result_to_liveness_result(
    result: BmcResult,
    cs: &CounterSystem,
) -> LivenessResult {
    match result {
        BmcResult::Safe { depth_checked } => LivenessResult::Live { depth_checked },
        BmcResult::Unsafe { depth, model } => {
            let trace = extract_trace(cs, &model, depth);
            LivenessResult::NotLive { trace }
        }
        BmcResult::Unknown { reason, .. } => LivenessResult::Unknown { reason },
    }
}

pub(crate) fn run_liveness_spec_bmc(
    ta: &ThresholdAutomaton,
    cs: &CounterSystem,
    spec: &LivenessSpec,
    options: &PipelineOptions,
    committee_bounds: &[(usize, u64)],
    dump_smt_path: Option<&str>,
) -> Result<LivenessResult, PipelineError> {
    match spec {
        LivenessSpec::TerminationGoalLocs(goal_locs) => {
            let property = SafetyProperty::Termination {
                goal_locs: goal_locs.clone(),
            };
            if let Some(path) = dump_smt_path {
                let extra = committee_bound_assertions(committee_bounds);
                dump_smt_to_file(cs, &property, options.max_depth, path, &extra);
            }
            let bmc_result = match options.solver {
                SolverChoice::Z3 => {
                    let mut solver = Z3Solver::with_timeout_secs(options.timeout_secs);
                    run_bmc_with_committee_bounds_at_depth(
                        &mut solver,
                        cs,
                        &property,
                        options.max_depth,
                        committee_bounds,
                    )?
                }
                SolverChoice::Cvc5 => {
                    use tarsier_smt::backends::cvc5_backend::Cvc5Solver;
                    let mut solver = Cvc5Solver::with_timeout_secs(options.timeout_secs)
                        .map_err(|e| PipelineError::Solver(e.to_string()))?;
                    run_bmc_with_committee_bounds_at_depth(
                        &mut solver,
                        cs,
                        &property,
                        options.max_depth,
                        committee_bounds,
                    )?
                }
            };
            Ok(bmc_result_to_liveness_result(bmc_result, cs))
        }
        LivenessSpec::Temporal {
            quantifiers,
            formula,
            ..
        } => {
            let encoding = encode_temporal_liveness_violation_with_bindings(
                ta,
                cs,
                quantifiers,
                formula,
                options.max_depth,
                committee_bounds,
            )?;
            if let Some(path) = dump_smt_path {
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
            Ok(bmc_result_to_liveness_result(bmc_result, cs))
        }
    }
}

/// Run BMC with per-committee concrete bounds on adversary parameters.
pub(crate) fn run_bmc_with_committee_bounds<S: SmtSolver>(
    solver: &mut S,
    cs: &CounterSystem,
    property: &SafetyProperty,
    max_depth: usize,
    committee_bounds: &[(usize, u64)],
    overall_timeout: Option<Duration>,
) -> Result<BmcResult, PipelineError> {
    let deadline = overall_timeout.and_then(|t| Instant::now().checked_add(t));
    if !committee_bounds.is_empty() {
        let extra_assertions = committee_bound_assertions(committee_bounds);
        run_bmc_with_extra_assertions_with_deadline(
            solver,
            cs,
            property,
            max_depth,
            &extra_assertions,
            deadline,
        )
        .map_err(|e| PipelineError::Solver(e.to_string()))
    } else {
        run_bmc_with_deadline(solver, cs, property, max_depth, deadline)
            .map_err(|e| PipelineError::Solver(e.to_string()))
    }
}

/// Run BMC at a single depth with per-committee concrete bounds.
pub(crate) fn run_bmc_with_committee_bounds_at_depth<S: SmtSolver>(
    solver: &mut S,
    cs: &CounterSystem,
    property: &SafetyProperty,
    depth: usize,
    committee_bounds: &[(usize, u64)],
) -> Result<BmcResult, PipelineError> {
    if !committee_bounds.is_empty() {
        let extra_assertions = committee_bound_assertions(committee_bounds);
        run_bmc_with_extra_assertions_at_depth(solver, cs, property, depth, &extra_assertions)
            .map_err(|e| PipelineError::Solver(e.to_string()))
    } else {
        run_bmc_at_depth(solver, cs, property, depth)
            .map_err(|e| PipelineError::Solver(e.to_string()))
    }
}

/// Run unbounded safety backend with optional committee-derived parameter bounds.
pub(crate) fn run_unbounded_with_engine<S: SmtSolver>(
    solver: &mut S,
    cs: &CounterSystem,
    property: &SafetyProperty,
    max_k: usize,
    committee_bounds: &[(usize, u64)],
    engine: ProofEngine,
    overall_timeout: Option<Duration>,
) -> Result<KInductionResult, PipelineError> {
    push_reduction_note("encoder.structural_hashing=on");
    if engine == ProofEngine::Pdr {
        push_reduction_note("pdr.symmetry_generalization=on");
        push_reduction_note("pdr.incremental_query_reuse=on");
        push_reduction_note("por.stutter_time_signature_collapse=on");
    }
    let deadline = overall_timeout.and_then(|t| Instant::now().checked_add(t));
    let extra_assertions = committee_bound_assertions(committee_bounds);
    crate::sandbox::enforce_active_limits()?;
    match engine {
        ProofEngine::KInduction => {
            run_k_induction_with_deadline(solver, cs, property, max_k, &extra_assertions, deadline)
                .map_err(|e| PipelineError::Solver(e.to_string()))
        }
        ProofEngine::Pdr => {
            run_pdr_with_deadline(solver, cs, property, max_k, &extra_assertions, deadline)
                .map_err(|e| PipelineError::Solver(e.to_string()))
        }
    }
}

pub(crate) fn location_zero_assertions_for_depth(locs: &[usize], depth: usize) -> Vec<SmtTerm> {
    let mut assertions = Vec::with_capacity(locs.len() * (depth + 1));
    for step in 0..=depth {
        for loc in locs {
            assertions.push(SmtTerm::var(pdr_kappa_var(step, *loc)).eq(SmtTerm::int(0)));
        }
    }
    assertions
}

pub(crate) fn location_zero_assertions_for_step_relation(locs: &[usize]) -> Vec<SmtTerm> {
    let mut assertions = Vec::with_capacity(locs.len() * 2);
    for loc in locs {
        assertions.push(SmtTerm::var(pdr_kappa_var(0, *loc)).eq(SmtTerm::int(0)));
        assertions.push(SmtTerm::var(pdr_kappa_var(1, *loc)).eq(SmtTerm::int(0)));
    }
    assertions
}

pub(crate) fn run_k_induction_with_location_invariants<S: SmtSolver>(
    solver: &mut S,
    cs: &CounterSystem,
    property: &SafetyProperty,
    max_k: usize,
    base_extra_assertions: &[SmtTerm],
    invariant_zero_locs: &[usize],
    deadline: Option<Instant>,
) -> Result<KInductionResult, S::Error> {
    if max_k == 0 {
        return Ok(KInductionResult::NotProved { max_k, cti: None });
    }

    let mut first_cti: Option<KInductionCti> = None;

    for k in 1..=max_k {
        if crate::sandbox::enforce_active_limits().is_err() {
            return Ok(KInductionResult::Unknown {
                reason: "Sandbox resource limit exceeded during k-induction.".into(),
            });
        }
        if deadline_exceeded(deadline) {
            return Ok(KInductionResult::Unknown {
                reason: timeout_unknown_reason("k-induction"),
            });
        }
        for depth in 0..=k {
            if deadline_exceeded(deadline) {
                return Ok(KInductionResult::Unknown {
                    reason: timeout_unknown_reason("k-induction"),
                });
            }
            solver.reset()?;
            let encoding = encode_bmc(cs, property, depth);
            for (name, sort) in &encoding.declarations {
                solver.declare_var(name, sort)?;
            }
            for assertion in &encoding.assertions {
                solver.assert(assertion)?;
            }
            for extra in base_extra_assertions {
                solver.assert(extra)?;
            }
            for inv in location_zero_assertions_for_depth(invariant_zero_locs, depth) {
                solver.assert(&inv)?;
            }
            let var_refs: Vec<(&str, &SmtSort)> = encoding
                .model_vars
                .iter()
                .map(|(n, s)| (n.as_str(), s))
                .collect();
            let (sat, model) = solver.check_sat_with_model(&var_refs)?;
            match sat {
                SatResult::Sat => {
                    let Some(model) = model else {
                        return Ok(KInductionResult::Unknown {
                            reason: format!(
                                "k-induction base at depth {depth} returned SAT without a model."
                            ),
                        });
                    };
                    return Ok(KInductionResult::Unsafe { depth, model });
                }
                SatResult::Unsat => {}
                SatResult::Unknown(reason) => {
                    return Ok(KInductionResult::Unknown { reason });
                }
            }
        }

        if deadline_exceeded(deadline) {
            return Ok(KInductionResult::Unknown {
                reason: timeout_unknown_reason("k-induction"),
            });
        }
        solver.reset()?;
        let encoding = encode_k_induction_step(cs, property, k);
        for (name, sort) in &encoding.declarations {
            solver.declare_var(name, sort)?;
        }
        for assertion in &encoding.assertions {
            solver.assert(assertion)?;
        }
        for extra in base_extra_assertions {
            solver.assert(extra)?;
        }
        for inv in location_zero_assertions_for_depth(invariant_zero_locs, k) {
            solver.assert(&inv)?;
        }
        let var_refs: Vec<(&str, &SmtSort)> = encoding
            .model_vars
            .iter()
            .map(|(n, s)| (n.as_str(), s))
            .collect();
        let (sat, model) = solver.check_sat_with_model(&var_refs)?;
        match sat {
            SatResult::Unsat => {
                return Ok(KInductionResult::Proved { k });
            }
            SatResult::Sat => {
                if first_cti.is_none() {
                    let Some(model) = model else {
                        return Ok(KInductionResult::Unknown {
                            reason: format!(
                                "k-induction step at k={k} returned SAT without a model."
                            ),
                        });
                    };
                    first_cti = Some(KInductionCti { k, model });
                }
            }
            SatResult::Unknown(reason) => {
                return Ok(KInductionResult::Unknown { reason });
            }
        }
    }

    Ok(KInductionResult::NotProved {
        max_k,
        cti: first_cti,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_unbounded_with_engine_and_location_invariants<S: SmtSolver>(
    solver: &mut S,
    cs: &CounterSystem,
    property: &SafetyProperty,
    max_k: usize,
    committee_bounds: &[(usize, u64)],
    engine: ProofEngine,
    invariant_zero_locs: &[usize],
    overall_timeout: Option<Duration>,
) -> Result<KInductionResult, PipelineError> {
    push_reduction_note("encoder.structural_hashing=on");
    if engine == ProofEngine::Pdr {
        push_reduction_note("pdr.symmetry_generalization=on");
        push_reduction_note("pdr.incremental_query_reuse=on");
        push_reduction_note("por.stutter_time_signature_collapse=on");
    }
    let deadline = overall_timeout.and_then(|t| Instant::now().checked_add(t));
    let mut extra_assertions = committee_bound_assertions(committee_bounds);
    match engine {
        ProofEngine::KInduction => run_k_induction_with_location_invariants(
            solver,
            cs,
            property,
            max_k,
            &extra_assertions,
            invariant_zero_locs,
            deadline,
        )
        .map_err(|e| PipelineError::Solver(e.to_string())),
        ProofEngine::Pdr => {
            extra_assertions.extend(location_zero_assertions_for_step_relation(
                invariant_zero_locs,
            ));
            run_pdr_with_deadline(solver, cs, property, max_k, &extra_assertions, deadline)
                .map_err(|e| PipelineError::Solver(e.to_string()))
        }
    }
}

pub(crate) fn property_relevant_location_set(property: &SafetyProperty) -> HashSet<usize> {
    let mut locs = HashSet::new();
    match property {
        SafetyProperty::Agreement { conflicting_pairs } => {
            for (a, b) in conflicting_pairs {
                locs.insert(*a);
                locs.insert(*b);
            }
        }
        SafetyProperty::Invariant { bad_sets } => {
            for bad in bad_sets {
                for loc in bad {
                    locs.insert(*loc);
                }
            }
        }
        SafetyProperty::Termination { goal_locs } => {
            for loc in goal_locs {
                locs.insert(*loc);
            }
        }
    }
    locs
}

pub(crate) fn cti_zero_location_candidates(
    ta: &ThresholdAutomaton,
    property: &SafetyProperty,
    cti: &InductionCtiSummary,
    max_candidates: usize,
) -> Vec<usize> {
    if max_candidates == 0 {
        return Vec::new();
    }

    let occupied_names: HashSet<&str> = cti
        .hypothesis_locations
        .iter()
        .chain(cti.violating_locations.iter())
        .map(|(name, _)| name.as_str())
        .collect();
    let relevant = property_relevant_location_set(property);

    let mut candidates: Vec<usize> = ta
        .locations
        .iter()
        .enumerate()
        .filter(|(_, loc)| !occupied_names.contains(loc.name.as_str()))
        .map(|(id, _)| id)
        .collect();
    candidates.sort_by(|a, b| {
        let ra = relevant.contains(a);
        let rb = relevant.contains(b);
        rb.cmp(&ra)
            .then_with(|| ta.locations[*a].name.cmp(&ta.locations[*b].name))
    });
    candidates.truncate(max_candidates);
    candidates
}

pub(crate) fn prove_location_unreachable_for_synthesis(
    cs: &CounterSystem,
    options: &PipelineOptions,
    committee_bounds: &[(usize, u64)],
    loc_id: usize,
) -> Result<bool, PipelineError> {
    let candidate = SafetyProperty::Invariant {
        bad_sets: vec![vec![loc_id]],
    };
    let kind_result = match options.solver {
        SolverChoice::Z3 => {
            let mut solver = Z3Solver::with_timeout_secs(options.timeout_secs);
            run_unbounded_with_engine(
                &mut solver,
                cs,
                &candidate,
                options.max_depth,
                committee_bounds,
                ProofEngine::KInduction,
                overall_timeout_duration(options.timeout_secs),
            )?
        }
        SolverChoice::Cvc5 => {
            use tarsier_smt::backends::cvc5_backend::Cvc5Solver;
            let mut solver = Cvc5Solver::with_timeout_secs(options.timeout_secs)
                .map_err(|e| PipelineError::Solver(e.to_string()))?;
            run_unbounded_with_engine(
                &mut solver,
                cs,
                &candidate,
                options.max_depth,
                committee_bounds,
                ProofEngine::KInduction,
                overall_timeout_duration(options.timeout_secs),
            )?
        }
    };
    Ok(matches!(kind_result, KInductionResult::Proved { .. }))
}

pub(crate) fn kind_result_to_unbounded_safety(
    kind_result: KInductionResult,
    cs: &CounterSystem,
    property: &SafetyProperty,
    committee_bounds: &[(usize, u64)],
    committee_summaries: &[CommitteeAnalysisSummary],
    options: &PipelineOptions,
) -> UnboundedSafetyResult {
    let has_committees = !committee_summaries.is_empty();
    match kind_result {
        KInductionResult::Proved { k } => {
            if has_committees {
                let total_epsilon: f64 = committee_summaries.iter().map(|c| c.epsilon).sum();
                UnboundedSafetyResult::ProbabilisticallySafe {
                    induction_k: k,
                    failure_probability: total_epsilon,
                    committee_analyses: committee_summaries.to_vec(),
                }
            } else {
                UnboundedSafetyResult::Safe { induction_k: k }
            }
        }
        KInductionResult::Unsafe { depth, model } => {
            let trace = extract_trace(cs, &model, depth);
            UnboundedSafetyResult::Unsafe { trace }
        }
        KInductionResult::Unknown { reason } => UnboundedSafetyResult::Unknown { reason },
        KInductionResult::NotProved { max_k, cti } => UnboundedSafetyResult::NotProved {
            max_k,
            cti: cti.as_ref().map(|witness| {
                build_induction_cti_summary(cs, property, witness, max_k, committee_bounds, options)
            }),
        },
    }
}

pub(crate) fn committee_bound_assertions(
    committee_bounds: &[(usize, u64)],
) -> Vec<tarsier_smt::terms::SmtTerm> {
    use tarsier_smt::terms::SmtTerm;
    let mut extra = Vec::new();
    for &(param_id, b_max) in committee_bounds {
        // param <= b_max (concrete upper bound from committee analysis)
        extra.push(SmtTerm::var(format!("p_{param_id}")).le(SmtTerm::int(b_max as i64)));
        // param >= 0
        extra.push(SmtTerm::var(format!("p_{param_id}")).ge(SmtTerm::int(0)));
    }
    extra
}

pub(crate) fn bmc_result_to_verification(
    result: BmcResult,
    cs: &CounterSystem,
) -> VerificationResult {
    match result {
        BmcResult::Safe { depth_checked } => VerificationResult::Safe { depth_checked },
        BmcResult::Unsafe { depth, model } => {
            let trace = extract_trace(cs, &model, depth);
            VerificationResult::Unsafe { trace }
        }
        BmcResult::Unknown { reason, .. } => VerificationResult::Unknown { reason },
    }
}

pub(crate) fn build_induction_cti_summary(
    cs: &CounterSystem,
    property: &SafetyProperty,
    witness: &KInductionCti,
    bmc_depth_checked: usize,
    committee_bounds: &[(usize, u64)],
    options: &PipelineOptions,
) -> InductionCtiSummary {
    let ta = &cs.automaton;
    let k = witness.k;
    let model = &witness.model;

    let params: Vec<(String, i64)> = ta
        .parameters
        .iter()
        .enumerate()
        .map(|(i, p)| {
            (
                p.name.clone(),
                model.get_int(&format!("p_{i}")).unwrap_or(0),
            )
        })
        .collect();

    let pre_step = k.saturating_sub(1);
    let hypothesis_locations = collect_named_location_values(ta, model, pre_step);
    let hypothesis_shared = collect_named_shared_values(ta, model, pre_step);
    let violating_locations = collect_named_location_values(ta, model, k);
    let violating_shared = collect_named_shared_values(ta, model, k);

    let final_step_rules = if k == 0 {
        Vec::new()
    } else {
        ta.rules
            .iter()
            .enumerate()
            .filter_map(|(rule_id, rule)| {
                let delta = model
                    .get_int(&format!("delta_{}_{}", k - 1, rule_id))
                    .unwrap_or(0);
                if delta <= 0 {
                    return None;
                }
                let from = &ta.locations[rule.from].name;
                let to = &ta.locations[rule.to].name;
                Some((format!("r{rule_id} ({from} -> {to})"), delta))
            })
            .collect()
    };

    let violated_condition = summarize_property_violation(ta, property, model, k);

    // --- CTI classification ---
    // In k-induction, the BMC base case always passes at depth >= k before
    // the inductive step is checked at depth k.  If the base case verified
    // no violation is reachable up to depth `bmc_depth_checked`, then the
    // CTI's hypothesis state (at step k-1) is NOT in the set of
    // BMC-reachable states — making it likely spurious.
    let (classification, classification_evidence) = classify_cti(
        cs,
        witness,
        k,
        bmc_depth_checked,
        &hypothesis_locations,
        &params,
        ta,
        committee_bounds,
        options,
    );

    let rationale = build_cti_rationale(&classification, k, bmc_depth_checked, &violated_condition);

    InductionCtiSummary {
        k,
        params,
        hypothesis_locations,
        hypothesis_shared,
        violating_locations,
        violating_shared,
        final_step_rules,
        violated_condition,
        classification,
        classification_evidence,
        rationale,
    }
}

/// Classify a CTI as concrete or likely-spurious based on available evidence.
pub(crate) enum CtiHypothesisReachability {
    Reachable { depth: usize },
    Unreachable { depth_checked: usize },
    Unknown { reason: String },
}

pub(crate) fn cti_hypothesis_state_assertions(
    cs: &CounterSystem,
    witness: &KInductionCti,
    committee_bounds: &[(usize, u64)],
) -> Vec<SmtTerm> {
    let step = witness.k.saturating_sub(1);
    let mut assertions = committee_bound_assertions(committee_bounds);

    for loc_id in 0..cs.automaton.locations.len() {
        let value = witness
            .model
            .get_int(&format!("kappa_{step}_{loc_id}"))
            .unwrap_or(0);
        assertions.push(SmtTerm::var(format!("kappa_{step}_{loc_id}")).eq(SmtTerm::int(value)));
    }

    for var_id in 0..cs.automaton.shared_vars.len() {
        let value = witness
            .model
            .get_int(&format!("g_{step}_{var_id}"))
            .unwrap_or(0);
        assertions.push(SmtTerm::var(format!("g_{step}_{var_id}")).eq(SmtTerm::int(value)));
    }

    for param_id in 0..cs.automaton.parameters.len() {
        let value = witness.model.get_int(&format!("p_{param_id}")).unwrap_or(0);
        assertions.push(SmtTerm::var(format!("p_{param_id}")).eq(SmtTerm::int(value)));
    }

    assertions
}

pub(crate) fn check_cti_hypothesis_reachability(
    cs: &CounterSystem,
    witness: &KInductionCti,
    committee_bounds: &[(usize, u64)],
    options: &PipelineOptions,
) -> Result<CtiHypothesisReachability, PipelineError> {
    let step = witness.k.saturating_sub(1);
    let extra_assertions = cti_hypothesis_state_assertions(cs, witness, committee_bounds);
    // `bad_sets=[[]]` makes violation=true, so SAT means the transition system can
    // realize the asserted hypothesis state at the queried step.
    let reachability_probe = SafetyProperty::Invariant {
        bad_sets: vec![vec![]],
    };

    let probe_result = match options.solver {
        SolverChoice::Z3 => {
            let mut solver = Z3Solver::with_timeout_secs(options.timeout_secs);
            run_bmc_with_extra_assertions_at_depth(
                &mut solver,
                cs,
                &reachability_probe,
                step,
                &extra_assertions,
            )
            .map_err(|e| PipelineError::Solver(e.to_string()))?
        }
        SolverChoice::Cvc5 => {
            use tarsier_smt::backends::cvc5_backend::Cvc5Solver;
            let mut solver = Cvc5Solver::with_timeout_secs(options.timeout_secs)
                .map_err(|e| PipelineError::Solver(e.to_string()))?;
            run_bmc_with_extra_assertions_at_depth(
                &mut solver,
                cs,
                &reachability_probe,
                step,
                &extra_assertions,
            )
            .map_err(|e| PipelineError::Solver(e.to_string()))?
        }
    };

    Ok(match probe_result {
        BmcResult::Unsafe { depth, .. } => CtiHypothesisReachability::Reachable { depth },
        BmcResult::Safe { depth_checked } => {
            CtiHypothesisReachability::Unreachable { depth_checked }
        }
        BmcResult::Unknown { reason, .. } => CtiHypothesisReachability::Unknown { reason },
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn classify_cti(
    cs: &CounterSystem,
    witness: &KInductionCti,
    cti_k: usize,
    bmc_depth_checked: usize,
    hypothesis_locations: &[(String, i64)],
    params: &[(String, i64)],
    ta: &ThresholdAutomaton,
    committee_bounds: &[(usize, u64)],
    options: &PipelineOptions,
) -> (CtiClassification, Vec<String>) {
    let mut evidence = Vec::new();
    let mut structural_impossibility = false;

    // Evidence 1: BMC base case coverage
    if cti_k <= bmc_depth_checked {
        evidence.push(format!(
            "BMC base case verified no reachable violation through depth {}; \
             CTI classification therefore requires an explicit reachability replay for \
             hypothesis step {}.",
            bmc_depth_checked,
            cti_k.saturating_sub(1),
        ));
    }

    // Evidence 2: Check population consistency (location counters should sum to n)
    let n_value = params.iter().find(|(name, _)| name == "n").map(|(_, v)| *v);
    if let Some(n) = n_value {
        let hyp_loc_sum: i64 = hypothesis_locations.iter().map(|(_, v)| *v).sum();
        // The counter system may have locations not in hypothesis_locations (with value 0),
        // so we only flag if sum > n (overpopulation is structurally impossible).
        if hyp_loc_sum > n {
            structural_impossibility = true;
            evidence.push(format!(
                "Hypothesis location counter sum ({}) exceeds population parameter n = {}; \
                 state is structurally unreachable.",
                hyp_loc_sum, n,
            ));
        }
    }

    // Evidence 3: Check for negative counter values (impossible in real executions)
    let neg_locs: Vec<&str> = hypothesis_locations
        .iter()
        .filter(|(_, v)| *v < 0)
        .map(|(name, _)| name.as_str())
        .collect();
    if !neg_locs.is_empty() {
        structural_impossibility = true;
        evidence.push(format!(
            "Hypothesis state contains negative location counters ({}); \
             these are structurally impossible in valid executions.",
            neg_locs.join(", "),
        ));
    }

    // Evidence 4: Check initial location occupancy
    // If the initial location has counter = 0 and we're at step 0, that's suspicious.
    let init_location_names: Vec<&str> = ta
        .initial_locations
        .iter()
        .filter_map(|&loc_id| ta.locations.get(loc_id).map(|loc| loc.name.as_str()))
        .collect();
    if !init_location_names.is_empty() {
        let hyp_names: std::collections::HashMap<&str, i64> = hypothesis_locations
            .iter()
            .map(|(name, v)| (name.as_str(), *v))
            .collect();
        let all_init_zero = init_location_names
            .iter()
            .all(|name| hyp_names.get(name).copied().unwrap_or(0) == 0);
        if all_init_zero && cti_k <= 1 {
            evidence.push(format!(
                "All initial locations ({}) have zero occupancy at step {}; \
                 at low depth this is inconsistent with reachable initial configuration.",
                init_location_names.join(", "),
                cti_k.saturating_sub(1),
            ));
        }
    }

    let reachability = check_cti_hypothesis_reachability(cs, witness, committee_bounds, options);
    let classification = if structural_impossibility {
        evidence.push(
            "Structural impossibility evidence takes precedence; classify as likely-spurious."
                .to_string(),
        );
        CtiClassification::LikelySpurious
    } else {
        match reachability {
            Ok(CtiHypothesisReachability::Reachable { depth }) => {
                evidence.push(format!(
                    "Independent reachability replay is SAT: the CTI hypothesis state is \
                     reachable at depth {} under the current solver/model assumptions.",
                    depth
                ));
                CtiClassification::Concrete
            }
            Ok(CtiHypothesisReachability::Unreachable { depth_checked }) => {
                evidence.push(format!(
                    "Independent reachability replay is UNSAT through depth {}; the CTI \
                     hypothesis state is unreachable under current assumptions.",
                    depth_checked
                ));
                CtiClassification::LikelySpurious
            }
            Ok(CtiHypothesisReachability::Unknown { reason }) => {
                evidence.push(format!(
                    "Independent reachability replay returned unknown ({}); \
                     conservatively classifying as likely-spurious.",
                    reason
                ));
                CtiClassification::LikelySpurious
            }
            Err(err) => {
                evidence.push(format!(
                    "Independent reachability replay failed ({}); \
                     conservatively classifying as likely-spurious.",
                    err
                ));
                CtiClassification::LikelySpurious
            }
        }
    };

    (classification, evidence)
}

/// Build a human-readable rationale explaining the CTI and its classification.
pub(crate) fn build_cti_rationale(
    classification: &CtiClassification,
    cti_k: usize,
    bmc_depth_checked: usize,
    violated_condition: &str,
) -> String {
    match classification {
        CtiClassification::LikelySpurious => {
            format!(
                "The inductive step failed at k = {cti_k}: the solver found an arbitrary state \
                 satisfying the property for k-1 steps from which one more transition violates \
                 it ({violated_condition}). However, BMC verified that no reachable state up \
                 to depth {bmc_depth_checked} leads to a violation. This means the hypothesis \
                 state is likely unreachable from the initial configuration — the property may \
                 be safe but requires a stronger inductive invariant to prove. Consider: \
                 (1) increasing the induction depth, (2) enabling CEGAR refinement, or \
                 (3) adding auxiliary invariants.",
            )
        }
        CtiClassification::Concrete => {
            format!(
                "The inductive step failed at k = {cti_k} and the hypothesis state appears \
                 reachable from initial states. The violation ({violated_condition}) represents \
                 a genuine safety issue in the protocol.",
            )
        }
    }
}

/// Return positive location counters from one model step as `(location_name, value)`.
pub(crate) fn collect_named_location_values(
    ta: &ThresholdAutomaton,
    model: &Model,
    step: usize,
) -> Vec<(String, i64)> {
    ta.locations
        .iter()
        .enumerate()
        .filter_map(|(loc_id, loc)| {
            let value = model
                .get_int(&format!("kappa_{step}_{loc_id}"))
                .unwrap_or(0);
            (value > 0).then(|| (loc.name.clone(), value))
        })
        .collect()
}

/// Return positive shared-variable values from one model step as `(var_name, value)`.
pub(crate) fn collect_named_shared_values(
    ta: &ThresholdAutomaton,
    model: &Model,
    step: usize,
) -> Vec<(String, i64)> {
    ta.shared_vars
        .iter()
        .enumerate()
        .filter_map(|(var_id, var)| {
            let value = model.get_int(&format!("g_{step}_{var_id}")).unwrap_or(0);
            (value > 0).then(|| (var.name.clone(), value))
        })
        .collect()
}

/// Build a concise, user-facing explanation of which safety clause is violated at `step`.
pub(crate) fn summarize_property_violation(
    ta: &ThresholdAutomaton,
    property: &SafetyProperty,
    model: &Model,
    step: usize,
) -> String {
    match property {
        SafetyProperty::Agreement { conflicting_pairs } => {
            let mut violated_pairs = Vec::new();
            for &(a, b) in conflicting_pairs {
                let ka = model.get_int(&format!("kappa_{step}_{a}")).unwrap_or(0);
                let kb = model.get_int(&format!("kappa_{step}_{b}")).unwrap_or(0);
                if ka > 0 && kb > 0 {
                    violated_pairs.push(format!(
                        "{} and {} both occupied",
                        ta.locations[a].name, ta.locations[b].name
                    ));
                }
            }
            if violated_pairs.is_empty() {
                "step state satisfies induction hypotheses on 0..k-1 but violates agreement at k"
                    .into()
            } else {
                format!("agreement violated: {}", violated_pairs.join("; "))
            }
        }
        SafetyProperty::Invariant { bad_sets } => {
            let mut witnesses = Vec::new();
            for bad_set in bad_sets {
                let occupied: Vec<usize> = bad_set
                    .iter()
                    .copied()
                    .filter(|loc| model.get_int(&format!("kappa_{step}_{loc}")).unwrap_or(0) > 0)
                    .collect();
                if occupied.len() == bad_set.len() {
                    let names = occupied
                        .iter()
                        .map(|loc| ta.locations[*loc].name.clone())
                        .collect::<Vec<_>>()
                        .join(", ");
                    witnesses.push(format!("all of {{{names}}} occupied"));
                }
            }
            if witnesses.is_empty() {
                "step state satisfies induction hypotheses on 0..k-1 but violates invariant at k"
                    .into()
            } else {
                format!("invariant violated: {}", witnesses.join("; "))
            }
        }
        SafetyProperty::Termination { goal_locs } => {
            let goal_set: HashSet<usize> = goal_locs.iter().copied().collect();
            let still_active = ta
                .locations
                .iter()
                .enumerate()
                .filter_map(|(loc_id, loc)| {
                    if goal_set.contains(&loc_id) {
                        return None;
                    }
                    let value = model
                        .get_int(&format!("kappa_{step}_{loc_id}"))
                        .unwrap_or(0);
                    (value > 0).then(|| format!("{}={}", loc.name, value))
                })
                .collect::<Vec<_>>();
            if still_active.is_empty() {
                "termination violated at step k".into()
            } else {
                format!(
                    "termination violated: non-goal locations still populated ({})",
                    still_active.join(", ")
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solver_choice_name_z3() {
        assert_eq!(solver_choice_name(SolverChoice::Z3), "z3");
    }

    #[test]
    fn solver_choice_name_cvc5() {
        assert_eq!(solver_choice_name(SolverChoice::Cvc5), "cvc5");
    }

    #[test]
    fn soundness_mode_name_strict() {
        assert_eq!(soundness_mode_name(SoundnessMode::Strict), "strict");
    }

    #[test]
    fn soundness_mode_name_permissive() {
        assert_eq!(soundness_mode_name(SoundnessMode::Permissive), "permissive");
    }

    #[test]
    fn solver_choice_label_matches_name() {
        assert_eq!(solver_choice_label(SolverChoice::Z3), "z3");
        assert_eq!(solver_choice_label(SolverChoice::Cvc5), "cvc5");
    }

    #[test]
    fn proof_engine_label_values() {
        assert_eq!(proof_engine_label(ProofEngine::KInduction), "kinduction");
        assert_eq!(proof_engine_label(ProofEngine::Pdr), "pdr");
    }

    #[test]
    fn fairness_mode_label_values() {
        assert_eq!(fairness_mode_label(FairnessMode::Weak), "weak");
        assert_eq!(fairness_mode_label(FairnessMode::Strong), "strong");
    }

    #[test]
    fn committee_bound_assertions_empty() {
        let result = committee_bound_assertions(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn committee_bound_assertions_single_bound() {
        let result = committee_bound_assertions(&[(0, 42)]);
        assert_eq!(result.len(), 2);
        // First: p_0 <= 42
        let expected_le = SmtTerm::var("p_0".to_string()).le(SmtTerm::int(42));
        assert_eq!(result[0], expected_le);
        // Second: p_0 >= 0
        let expected_ge = SmtTerm::var("p_0".to_string()).ge(SmtTerm::int(0));
        assert_eq!(result[1], expected_ge);
    }

    #[test]
    fn committee_bound_assertions_multiple_bounds() {
        let result = committee_bound_assertions(&[(0, 10), (2, 20)]);
        assert_eq!(result.len(), 4);
    }

    #[test]
    fn location_zero_assertions_for_depth_correct_count() {
        let locs = vec![2, 5];
        let depth = 3;
        let result = location_zero_assertions_for_depth(&locs, depth);
        // 2 locations * (depth+1=4) steps = 8 assertions
        assert_eq!(result.len(), 8);
    }

    #[test]
    fn location_zero_assertions_for_depth_content() {
        let locs = vec![3];
        let depth = 1;
        let result = location_zero_assertions_for_depth(&locs, depth);
        assert_eq!(result.len(), 2);
        // step 0: kappa_0_3 = 0
        assert_eq!(
            result[0],
            SmtTerm::var("kappa_0_3".to_string()).eq(SmtTerm::int(0))
        );
        // step 1: kappa_1_3 = 0
        assert_eq!(
            result[1],
            SmtTerm::var("kappa_1_3".to_string()).eq(SmtTerm::int(0))
        );
    }

    #[test]
    fn location_zero_assertions_for_step_relation_count() {
        let locs = vec![1, 2, 3];
        let result = location_zero_assertions_for_step_relation(&locs);
        // 3 locations * 2 steps (0 and 1) = 6 assertions
        assert_eq!(result.len(), 6);
    }

    #[test]
    fn location_zero_assertions_for_step_relation_content() {
        let locs = vec![5];
        let result = location_zero_assertions_for_step_relation(&locs);
        assert_eq!(result.len(), 2);
        assert_eq!(
            result[0],
            SmtTerm::var("kappa_0_5".to_string()).eq(SmtTerm::int(0))
        );
        assert_eq!(
            result[1],
            SmtTerm::var("kappa_1_5".to_string()).eq(SmtTerm::int(0))
        );
    }

    #[test]
    fn safety_property_canonical_agreement_sorted() {
        let prop = SafetyProperty::Agreement {
            conflicting_pairs: vec![(2, 3), (0, 1)],
        };
        let canon = safety_property_canonical(&prop);
        // Pairs should be sorted
        assert_eq!(canon, "agreement:[(0, 1), (2, 3)]");
    }

    #[test]
    fn safety_property_canonical_agreement_empty() {
        let prop = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };
        let canon = safety_property_canonical(&prop);
        assert_eq!(canon, "agreement:[]");
    }

    #[test]
    fn safety_property_canonical_invariant() {
        let prop = SafetyProperty::Invariant {
            bad_sets: vec![vec![2, 1], vec![0]],
        };
        let canon = safety_property_canonical(&prop);
        // Inner sets sorted, outer sorted
        assert_eq!(canon, "invariant:[[0], [1, 2]]");
    }

    #[test]
    fn safety_property_canonical_termination() {
        let prop = SafetyProperty::Termination {
            goal_locs: vec![3, 1, 2],
        };
        let canon = safety_property_canonical(&prop);
        assert_eq!(canon, "termination:[1, 2, 3]");
    }

    #[test]
    fn property_relevant_location_set_agreement() {
        let prop = SafetyProperty::Agreement {
            conflicting_pairs: vec![(0, 1), (2, 3)],
        };
        let locs = property_relevant_location_set(&prop);
        assert_eq!(locs.len(), 4);
        assert!(locs.contains(&0));
        assert!(locs.contains(&1));
        assert!(locs.contains(&2));
        assert!(locs.contains(&3));
    }

    #[test]
    fn property_relevant_location_set_invariant() {
        let prop = SafetyProperty::Invariant {
            bad_sets: vec![vec![5, 6], vec![7]],
        };
        let locs = property_relevant_location_set(&prop);
        assert_eq!(locs.len(), 3);
        assert!(locs.contains(&5));
        assert!(locs.contains(&6));
        assert!(locs.contains(&7));
    }

    #[test]
    fn property_relevant_location_set_termination() {
        let prop = SafetyProperty::Termination {
            goal_locs: vec![10, 20],
        };
        let locs = property_relevant_location_set(&prop);
        assert_eq!(locs.len(), 2);
        assert!(locs.contains(&10));
        assert!(locs.contains(&20));
    }

    /// Helper: build a minimal ThresholdAutomaton with the given parameters.
    fn make_ta_with_params(params: &[&str]) -> ThresholdAutomaton {
        ThresholdAutomaton {
            parameters: params
                .iter()
                .map(|name| tarsier_ir::threshold_automaton::Parameter {
                    name: name.to_string(),
                })
                .collect(),
            ..ThresholdAutomaton::default()
        }
    }

    #[test]
    fn named_committee_bounds_with_params() {
        let ta = make_ta_with_params(&["n", "t", "b"]);
        let bounds = vec![(2, 61), (0, 100)];
        let named = named_committee_bounds(&ta, &bounds);
        // Should be sorted by name: b, n
        assert_eq!(named, vec![("b".into(), 61), ("n".into(), 100)]);
    }

    #[test]
    fn named_committee_bounds_missing_param() {
        let ta = make_ta_with_params(&["n"]);
        // param_id=5 is out of bounds
        let bounds = vec![(5, 42)];
        let named = named_committee_bounds(&ta, &bounds);
        assert_eq!(named, vec![("param#5".into(), 42)]);
    }

    #[test]
    fn liveness_result_to_property_verification_live() {
        let result =
            liveness_result_to_property_verification(LivenessResult::Live { depth_checked: 10 });
        match result {
            VerificationResult::Safe { depth_checked } => assert_eq!(depth_checked, 10),
            _ => panic!("Expected Safe variant"),
        }
    }

    #[test]
    fn liveness_result_to_property_verification_unknown() {
        let result = liveness_result_to_property_verification(LivenessResult::Unknown {
            reason: "timeout".into(),
        });
        match result {
            VerificationResult::Unknown { reason } => assert_eq!(reason, "timeout"),
            _ => panic!("Expected Unknown variant"),
        }
    }

    #[test]
    fn build_cti_rationale_likely_spurious() {
        let rationale = build_cti_rationale(
            &CtiClassification::LikelySpurious,
            3,
            10,
            "agreement violated",
        );
        assert!(rationale.contains("k = 3"));
        assert!(rationale.contains("depth 10"));
        assert!(rationale.contains("agreement violated"));
        assert!(rationale.contains("likely unreachable"));
    }

    #[test]
    fn build_cti_rationale_concrete() {
        let rationale =
            build_cti_rationale(&CtiClassification::Concrete, 2, 5, "invariant violated");
        assert!(rationale.contains("k = 2"));
        assert!(rationale.contains("invariant violated"));
        assert!(rationale.contains("genuine safety issue"));
    }
}
