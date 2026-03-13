//! Bounded liveness entry points.

use crate::pipeline::verification::*;
use crate::pipeline::*;

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
            .constraints
            .committees
            .iter()
            .zip(committee_summaries.iter())
            .filter_map(|(spec, summary)| {
                spec.bound_param.map(|pid| (pid.as_usize(), summary.b_max))
            })
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

                let property = SafetyProperty::Termination {
                    goal_locs: goal_locs.iter().copied().map(Into::into).collect(),
                };
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
                        tracing::warn!("could not write SMT dump to {path}: {e}");
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
