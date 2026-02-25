//! Certificate generation, proof bundle management.

#![allow(unused_imports)]

use std::collections::HashSet;
use std::time::Instant;

use tarsier_dsl::ast;
use tarsier_ir::counter_system::CounterSystem;
use tarsier_ir::properties::SafetyProperty;
use tarsier_ir::threshold_automaton::ThresholdAutomaton;
use tarsier_smt::backends::z3_backend::Z3Solver;
use tarsier_smt::bmc::{
    run_k_induction_with_deadline, run_pdr_with_certificate_with_deadline, KInductionResult,
    PdrInvariantCertificate,
};
use tarsier_smt::encoder::encode_bmc;
use tarsier_smt::solver::SmtSolver;
use tarsier_smt::sorts::SmtSort;
use tarsier_smt::terms::SmtTerm;

use super::analysis::{analyze_and_constrain_committees, ensure_n_parameter};
use super::diagnostics::{push_phase_profile, push_reduction_note};
use super::property::{
    extract_liveness_spec, extract_property, fair_liveness_target_from_spec, LivenessSpec,
};
use super::verification::{
    build_fair_lasso_encoding, committee_bound_assertions, deadline_from_timeout_secs,
    lower_with_active_controls, preflight_validate, run_bmc_with_committee_bounds,
    run_unbounded_fair_pdr_with_certificate, FairPdrInvariantCertificate, PipelineCommand,
};
use super::*;

pub fn generate_kinduction_safety_certificate(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
) -> Result<SafetyProofCertificate, PipelineError> {
    reset_run_diagnostics();
    info!("Parsing {filename}...");
    let program = parse(source, filename)?;
    preflight_validate(&program, options, PipelineCommand::Verify)?;

    info!("Lowering to threshold automaton...");
    let mut ta = lower_with_active_controls(&program, "certify_safety_kinduction")?;
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
        return Err(PipelineError::Validation(
            "Cannot certify safety: committee analysis present, but no bound_param is specified."
                .into(),
        ));
    }

    let property = extract_property(&ta, &program, options.soundness)?;
    let cs = abstract_to_cs(ta.clone());
    let extra_assertions = committee_bound_assertions(&committee_bounds);

    let kind_result = match options.solver {
        SolverChoice::Z3 => {
            let mut solver = Z3Solver::with_timeout_secs(options.timeout_secs);
            run_k_induction_with_deadline(
                &mut solver,
                &cs,
                &property,
                options.max_depth,
                &extra_assertions,
                deadline_from_timeout_secs(options.timeout_secs),
            )
            .map_err(|e| PipelineError::Solver(e.to_string()))?
        }
        SolverChoice::Cvc5 => {
            use tarsier_smt::backends::cvc5_backend::Cvc5Solver;
            let mut solver = Cvc5Solver::with_timeout_secs(options.timeout_secs)
                .map_err(|e| PipelineError::Solver(e.to_string()))?;
            run_k_induction_with_deadline(
                &mut solver,
                &cs,
                &property,
                options.max_depth,
                &extra_assertions,
                deadline_from_timeout_secs(options.timeout_secs),
            )
            .map_err(|e| PipelineError::Solver(e.to_string()))?
        }
    };

    let induction_k = match kind_result {
        KInductionResult::Proved { k } => k,
        KInductionResult::Unsafe { .. } => {
            return Err(PipelineError::Validation(
                "Cannot certify safety: protocol is unsafe (counterexample found).".into(),
            ));
        }
        KInductionResult::NotProved { max_k, .. } => {
            return Err(PipelineError::Validation(format!(
                "Cannot certify safety: k-induction did not close up to k = {max_k}."
            )));
        }
        KInductionResult::Unknown { reason } => {
            return Err(PipelineError::Solver(format!(
                "Cannot certify safety: k-induction returned unknown ({reason})."
            )));
        }
    };

    let base_case = encode_bmc(&cs, &property, induction_k);
    let step_case = encode_k_induction_step(&cs, &property, induction_k);
    let committee_bound_names: Vec<(String, u64)> = committee_bounds
        .iter()
        .map(|(pid, b)| (ta.parameters[*pid].name.clone(), *b))
        .collect();

    Ok(SafetyProofCertificate {
        protocol_file: filename.to_string(),
        proof_engine: ProofEngine::KInduction,
        induction_k: Some(induction_k),
        solver_used: options.solver,
        soundness: options.soundness,
        committee_bounds: committee_bound_names,
        obligations: vec![
            SafetyProofObligation {
                name: "base_case".into(),
                expected: "unsat".into(),
                smt2: encoding_to_smt2_script(&base_case, &extra_assertions),
            },
            SafetyProofObligation {
                name: "inductive_step".into(),
                expected: "unsat".into(),
                smt2: encoding_to_smt2_script(&step_case, &extra_assertions),
            },
        ],
    })
}

/// Generate an independently checkable IC3/PDR invariant certificate for safety.
pub fn generate_pdr_safety_certificate(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
) -> Result<SafetyProofCertificate, PipelineError> {
    reset_run_diagnostics();
    push_reduction_note("encoder.structural_hashing=on");
    push_reduction_note("pdr.symmetry_generalization=on");
    push_reduction_note("pdr.incremental_query_reuse=on");
    push_reduction_note("por.stutter_time_signature_collapse=on");
    info!("Parsing {filename}...");
    let program = parse(source, filename)?;
    preflight_validate(&program, options, PipelineCommand::Verify)?;

    info!("Lowering to threshold automaton...");
    let mut ta = lower_with_active_controls(&program, "certify_safety_pdr")?;
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
        return Err(PipelineError::Validation(
            "Cannot certify safety: committee analysis present, but no bound_param is specified."
                .into(),
        ));
    }

    let property = extract_property(&ta, &program, options.soundness)?;
    let cs = abstract_to_cs(ta.clone());
    let extra_assertions = committee_bound_assertions(&committee_bounds);
    let committee_bound_names: Vec<(String, u64)> = committee_bounds
        .iter()
        .map(|(pid, b)| (ta.parameters[*pid].name.clone(), *b))
        .collect();

    let (result, cert) = match options.solver {
        SolverChoice::Z3 => {
            let mut solver = Z3Solver::with_timeout_secs(options.timeout_secs);
            run_pdr_with_certificate_with_deadline(
                &mut solver,
                &cs,
                &property,
                options.max_depth,
                &extra_assertions,
                deadline_from_timeout_secs(options.timeout_secs),
            )
            .map_err(|e| PipelineError::Solver(e.to_string()))?
        }
        SolverChoice::Cvc5 => {
            use tarsier_smt::backends::cvc5_backend::Cvc5Solver;
            let mut solver = Cvc5Solver::with_timeout_secs(options.timeout_secs)
                .map_err(|e| PipelineError::Solver(e.to_string()))?;
            run_pdr_with_certificate_with_deadline(
                &mut solver,
                &cs,
                &property,
                options.max_depth,
                &extra_assertions,
                deadline_from_timeout_secs(options.timeout_secs),
            )
            .map_err(|e| PipelineError::Solver(e.to_string()))?
        }
    };

    let frame = match result {
        KInductionResult::Proved { k } => k,
        KInductionResult::Unsafe { .. } => {
            return Err(PipelineError::Validation(
                "Cannot certify safety: protocol is unsafe (counterexample found).".into(),
            ));
        }
        KInductionResult::NotProved { max_k, .. } => {
            return Err(PipelineError::Validation(format!(
                "Cannot certify safety: PDR did not converge up to k = {max_k}."
            )));
        }
        KInductionResult::Unknown { reason } => {
            return Err(PipelineError::Solver(format!(
                "Cannot certify safety: PDR returned unknown ({reason})."
            )));
        }
    };

    let cert = cert.ok_or_else(|| {
        PipelineError::Solver(
            "Cannot certify safety: PDR proved safety but did not return an invariant certificate."
                .into(),
        )
    })?;

    Ok(SafetyProofCertificate {
        protocol_file: filename.to_string(),
        proof_engine: ProofEngine::Pdr,
        induction_k: Some(frame),
        solver_used: options.solver,
        soundness: options.soundness,
        committee_bounds: committee_bound_names,
        obligations: pdr_certificate_to_obligations(&cert, &extra_assertions),
    })
}

/// Generate a safety certificate using the selected proof engine in options.
pub fn generate_safety_certificate(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
) -> Result<SafetyProofCertificate, PipelineError> {
    reset_run_diagnostics();
    match options.proof_engine {
        ProofEngine::KInduction => {
            generate_kinduction_safety_certificate(source, filename, options)
        }
        ProofEngine::Pdr => generate_pdr_safety_certificate(source, filename, options),
    }
}

/// Generate an independently checkable fair-liveness proof certificate.
pub fn generate_fair_liveness_certificate_with_mode(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
    fairness: FairnessMode,
) -> Result<FairLivenessProofCertificate, PipelineError> {
    reset_run_diagnostics();
    push_reduction_note("encoder.structural_hashing=on");
    push_reduction_note("pdr.symmetry_generalization=on");
    push_reduction_note("pdr.incremental_query_reuse=on");
    push_reduction_note("por.stutter_time_signature_collapse=on");
    info!("Parsing {filename}...");
    let program = parse(source, filename)?;
    preflight_validate(&program, options, PipelineCommand::Liveness)?;

    info!("Lowering to threshold automaton...");
    let mut ta = lower_with_active_controls(&program, "certify_fair_liveness")?;
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
        return Err(PipelineError::Validation(
            "Cannot certify fair-liveness: committee analysis present, but no bound_param is specified."
                .into(),
        ));
    }

    let liveness_spec = extract_liveness_spec(&ta, &program)?;
    if matches!(&liveness_spec, LivenessSpec::TerminationGoalLocs(goal_locs) if goal_locs.is_empty())
    {
        return Err(PipelineError::Property(
            "Fair-liveness certificate requires either a `property ...: liveness { ... }` declaration or a boolean local variable named `decided`."
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
    let extra_assertions = committee_bound_assertions(&committee_bounds);
    let committee_bound_names: Vec<(String, u64)> = committee_bounds
        .iter()
        .map(|(pid, b)| (ta.parameters[*pid].name.clone(), *b))
        .collect();

    let (result, cert) = match options.solver {
        SolverChoice::Z3 => {
            let mut solver = Z3Solver::with_timeout_secs(options.timeout_secs);
            run_unbounded_fair_pdr_with_certificate(
                &mut solver,
                &cs,
                options.max_depth,
                &target,
                &committee_bounds,
                fairness,
                overall_timeout,
            )?
        }
        SolverChoice::Cvc5 => {
            use tarsier_smt::backends::cvc5_backend::Cvc5Solver;
            let mut solver = Cvc5Solver::with_timeout_secs(options.timeout_secs)
                .map_err(|e| PipelineError::Solver(e.to_string()))?;
            run_unbounded_fair_pdr_with_certificate(
                &mut solver,
                &cs,
                options.max_depth,
                &target,
                &committee_bounds,
                fairness,
                overall_timeout,
            )?
        }
    };

    let frame = match result {
        UnboundedFairLivenessResult::LiveProved { frame } => frame,
        UnboundedFairLivenessResult::FairCycleFound { .. } => {
            return Err(PipelineError::Validation(
                "Cannot certify fair-liveness: protocol has a fair non-terminating counterexample."
                    .into(),
            ));
        }
        UnboundedFairLivenessResult::NotProved { max_k } => {
            return Err(PipelineError::Validation(format!(
                "Cannot certify fair-liveness: proof did not converge up to frame {max_k}."
            )));
        }
        UnboundedFairLivenessResult::Unknown { reason } => {
            return Err(PipelineError::Solver(format!(
                "Cannot certify fair-liveness: solver returned unknown ({reason})."
            )));
        }
    };

    let cert = cert.ok_or_else(|| {
        PipelineError::Solver(
            "Cannot certify fair-liveness: proof converged but invariant certificate was not produced."
                .into(),
        )
    })?;
    if cert.frame != frame {
        return Err(PipelineError::Solver(
            "Cannot certify fair-liveness: internal proof frame mismatch.".into(),
        ));
    }

    Ok(FairLivenessProofCertificate {
        protocol_file: filename.to_string(),
        fairness,
        proof_engine: ProofEngine::Pdr,
        frame,
        solver_used: options.solver,
        soundness: options.soundness,
        committee_bounds: committee_bound_names,
        obligations: fair_pdr_certificate_to_obligations(&cert, &extra_assertions),
    })
}

/// Generate an independently checkable fair-liveness certificate under weak fairness.
pub fn generate_fair_liveness_certificate(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
) -> Result<FairLivenessProofCertificate, PipelineError> {
    reset_run_diagnostics();
    generate_fair_liveness_certificate_with_mode(source, filename, options, FairnessMode::Weak)
}

/// Dump the SMT encoding of a bounded model check to a file for debugging.
pub(super) fn dump_smt_to_file(
    cs: &CounterSystem,
    property: &SafetyProperty,
    max_depth: usize,
    path: &str,
    extra_assertions: &[tarsier_smt::terms::SmtTerm],
) {
    use tarsier_smt::encoder::encode_bmc;

    let encoding = encode_bmc(cs, property, max_depth);
    let smt = encoding_to_smt2_script(&encoding, extra_assertions);

    if let Err(e) = std::fs::write(path, smt) {
        eprintln!("Warning: could not write SMT dump to {path}: {e}");
    } else {
        info!("SMT dump written to {path}");
    }
}

pub(super) fn encoding_to_smt2_script(
    encoding: &tarsier_smt::encoder::BmcEncoding,
    extra_assertions: &[tarsier_smt::terms::SmtTerm],
) -> String {
    let mut assertions = encoding.assertions.clone();
    assertions.extend(extra_assertions.iter().cloned());
    query_to_smt2_script(&encoding.declarations, &assertions)
}

/// Render declarations and assertions as a standalone SMT-LIB script.
pub(super) fn query_to_smt2_script(
    declarations: &[(String, SmtSort)],
    assertions: &[SmtTerm],
) -> String {
    use tarsier_smt::backends::smtlib_printer::{sort_to_smtlib, to_smtlib};

    let mut smt = String::new();
    smt.push_str("(set-logic QF_LIA)\n");
    for (name, sort) in declarations {
        smt.push_str(&format!(
            "(declare-const {} {})\n",
            name,
            sort_to_smtlib(sort)
        ));
    }
    for assertion in assertions {
        smt.push_str(&format!("(assert {})\n", to_smtlib(assertion)));
    }
    smt.push_str("(check-sat)\n");
    smt.push_str("(exit)\n");
    smt
}

/// Convert a PDR invariant certificate into independent UNSAT obligations.
pub(super) fn pdr_certificate_to_obligations(
    cert: &PdrInvariantCertificate,
    extra_assertions: &[SmtTerm],
) -> Vec<SafetyProofObligation> {
    let inv_pre = if cert.invariant_pre.is_empty() {
        SmtTerm::bool(true)
    } else {
        SmtTerm::and(cert.invariant_pre.clone())
    };
    let inv_post = if cert.invariant_post.is_empty() {
        SmtTerm::bool(true)
    } else {
        SmtTerm::and(cert.invariant_post.clone())
    };

    let mut init_to_inv = cert.init_assertions.clone();
    init_to_inv.extend(extra_assertions.iter().cloned());
    init_to_inv.push(inv_pre.clone().not());

    let mut consecution = cert.invariant_pre.clone();
    consecution.extend(cert.transition_assertions.iter().cloned());
    consecution.extend(extra_assertions.iter().cloned());
    consecution.push(inv_post.not());

    let mut inv_to_safe = cert.invariant_pre.clone();
    inv_to_safe.extend(extra_assertions.iter().cloned());
    inv_to_safe.push(cert.bad_pre.clone());

    vec![
        SafetyProofObligation {
            name: "init_implies_inv".into(),
            expected: "unsat".into(),
            smt2: query_to_smt2_script(&cert.declarations, &init_to_inv),
        },
        SafetyProofObligation {
            name: "inv_and_transition_implies_inv_prime".into(),
            expected: "unsat".into(),
            smt2: query_to_smt2_script(&cert.declarations, &consecution),
        },
        SafetyProofObligation {
            name: "inv_implies_safe".into(),
            expected: "unsat".into(),
            smt2: query_to_smt2_script(&cert.declarations, &inv_to_safe),
        },
    ]
}

/// Convert a fair-PDR certificate into independent UNSAT obligations.
pub(super) fn fair_pdr_certificate_to_obligations(
    cert: &FairPdrInvariantCertificate,
    extra_assertions: &[SmtTerm],
) -> Vec<SafetyProofObligation> {
    let inv_pre = if cert.invariant_pre.is_empty() {
        SmtTerm::bool(true)
    } else {
        SmtTerm::and(cert.invariant_pre.clone())
    };
    let inv_post = if cert.invariant_post.is_empty() {
        SmtTerm::bool(true)
    } else {
        SmtTerm::and(cert.invariant_post.clone())
    };

    let mut init_to_inv = cert.init_assertions.clone();
    init_to_inv.extend(extra_assertions.iter().cloned());
    init_to_inv.push(inv_pre.clone().not());

    let mut consecution = cert.invariant_pre.clone();
    consecution.extend(cert.transition_assertions.iter().cloned());
    consecution.extend(extra_assertions.iter().cloned());
    consecution.push(inv_post.not());

    let mut inv_to_no_fair_bad = cert.invariant_pre.clone();
    inv_to_no_fair_bad.extend(extra_assertions.iter().cloned());
    inv_to_no_fair_bad.push(cert.bad_pre.clone());

    vec![
        SafetyProofObligation {
            name: "init_implies_inv".into(),
            expected: "unsat".into(),
            smt2: query_to_smt2_script(&cert.declarations, &init_to_inv),
        },
        SafetyProofObligation {
            name: "inv_and_transition_implies_inv_prime".into(),
            expected: "unsat".into(),
            smt2: query_to_smt2_script(&cert.declarations, &consecution),
        },
        SafetyProofObligation {
            name: "inv_implies_no_fair_bad".into(),
            expected: "unsat".into(),
            smt2: query_to_smt2_script(&cert.declarations, &inv_to_no_fair_bad),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tarsier_ir::counter_system::CounterSystem;
    use tarsier_ir::threshold_automaton::{Guard, Location, Parameter, Rule, ThresholdAutomaton};
    use tarsier_smt::bmc::PdrInvariantCertificate;
    use tarsier_smt::encoder::encode_bmc;
    use tarsier_smt::sorts::SmtSort;
    use tarsier_smt::terms::SmtTerm;

    fn tiny_counter_system() -> CounterSystem {
        let mut ta = ThresholdAutomaton::new();
        ta.parameters.push(Parameter {
            name: "n".to_string(),
        });
        ta.locations.push(Location {
            name: "Init".to_string(),
            role: "R".to_string(),
            phase: "p".to_string(),
            local_vars: Default::default(),
        });
        ta.initial_locations = vec![0];
        ta.rules.push(Rule {
            from: 0,
            to: 0,
            guard: Guard::trivial(),
            updates: vec![],
        });
        CounterSystem::new(ta)
    }

    #[test]
    fn query_to_smt2_script_emits_declarations_assertions_and_footer() {
        let script = query_to_smt2_script(
            &[
                ("x".to_string(), SmtSort::Int),
                ("flag".to_string(), SmtSort::Bool),
            ],
            &[
                SmtTerm::var("x").ge(SmtTerm::int(0)),
                SmtTerm::var("flag").eq(SmtTerm::bool(true)),
            ],
        );

        assert!(script.contains("(set-logic QF_LIA)"));
        assert!(script.contains("(declare-const x Int)"));
        assert!(script.contains("(declare-const flag Bool)"));
        assert!(script.contains("(assert (>= x 0))"));
        assert!(script.contains("(check-sat)"));
        assert!(script.contains("(exit)"));
    }

    #[test]
    fn encoding_to_smt2_script_appends_extra_assertions() {
        let cs = tiny_counter_system();
        let property = SafetyProperty::Termination { goal_locs: vec![0] };
        let encoding = encode_bmc(&cs, &property, 0);

        let script = encoding_to_smt2_script(
            &encoding,
            &[SmtTerm::var("extra_guard").ge(SmtTerm::int(1))],
        );
        assert!(script.contains("extra_guard"));
        assert!(script.contains("(check-sat)"));
    }

    #[test]
    fn dump_smt_to_file_writes_query_script() {
        let cs = tiny_counter_system();
        let property = SafetyProperty::Termination { goal_locs: vec![0] };
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be available")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "tarsier-certification-dump-{}-{stamp}.smt2",
            std::process::id()
        ));
        let path_string = path
            .to_str()
            .expect("temporary path should be valid utf-8")
            .to_string();

        dump_smt_to_file(&cs, &property, 0, &path_string, &[]);
        let written = std::fs::read_to_string(&path).expect("dumped smt file should be readable");
        assert!(written.contains("(set-logic QF_LIA)"));
        assert!(written.contains("(check-sat)"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn pdr_certificate_to_obligations_generates_three_named_unsat_checks() {
        let cert = PdrInvariantCertificate {
            frame: 3,
            declarations: vec![
                ("x".to_string(), SmtSort::Int),
                ("xp".to_string(), SmtSort::Int),
            ],
            init_assertions: vec![SmtTerm::var("x").eq(SmtTerm::int(0))],
            transition_assertions: vec![
                SmtTerm::var("xp").eq(SmtTerm::var("x").add(SmtTerm::int(1)))
            ],
            bad_pre: SmtTerm::var("x").gt(SmtTerm::int(10)),
            invariant_pre: vec![SmtTerm::var("x").ge(SmtTerm::int(0))],
            invariant_post: vec![SmtTerm::var("xp").ge(SmtTerm::int(0))],
        };

        let obligations =
            pdr_certificate_to_obligations(&cert, &[SmtTerm::var("x").ge(SmtTerm::int(0))]);
        assert_eq!(obligations.len(), 3);
        assert_eq!(obligations[0].name, "init_implies_inv");
        assert_eq!(obligations[1].name, "inv_and_transition_implies_inv_prime");
        assert_eq!(obligations[2].name, "inv_implies_safe");
        assert!(obligations.iter().all(|o| o.expected == "unsat"));
        assert!(obligations.iter().all(|o| o.smt2.contains("(check-sat)")));
    }

    #[test]
    fn pdr_certificate_to_obligations_uses_true_for_empty_invariants() {
        let cert = PdrInvariantCertificate {
            frame: 1,
            declarations: vec![("x".to_string(), SmtSort::Int)],
            init_assertions: vec![],
            transition_assertions: vec![],
            bad_pre: SmtTerm::var("x").gt(SmtTerm::int(0)),
            invariant_pre: vec![],
            invariant_post: vec![],
        };

        let obligations = pdr_certificate_to_obligations(&cert, &[]);
        assert_eq!(obligations.len(), 3);
        assert!(
            obligations[0].smt2.contains("(assert (not true))")
                || obligations[0].smt2.contains("(assert false)"),
            "empty invariant should render as a negated `true` implication witness"
        );
    }

    #[test]
    fn fair_pdr_certificate_to_obligations_uses_no_fair_bad_label() {
        let cert = FairPdrInvariantCertificate {
            frame: 4,
            declarations: vec![
                ("x".to_string(), SmtSort::Int),
                ("xp".to_string(), SmtSort::Int),
            ],
            init_assertions: vec![SmtTerm::var("x").eq(SmtTerm::int(0))],
            transition_assertions: vec![SmtTerm::var("xp").ge(SmtTerm::var("x"))],
            bad_pre: SmtTerm::var("x").gt(SmtTerm::int(5)),
            invariant_pre: vec![SmtTerm::var("x").ge(SmtTerm::int(0))],
            invariant_post: vec![SmtTerm::var("xp").ge(SmtTerm::int(0))],
        };

        let obligations = fair_pdr_certificate_to_obligations(&cert, &[]);
        assert_eq!(obligations.len(), 3);
        assert_eq!(obligations[0].name, "init_implies_inv");
        assert_eq!(obligations[1].name, "inv_and_transition_implies_inv_prime");
        assert_eq!(obligations[2].name, "inv_implies_no_fair_bad");
        assert!(obligations[2].smt2.contains("(check-sat)"));
    }
}
