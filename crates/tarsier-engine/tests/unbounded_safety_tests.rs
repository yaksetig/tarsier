mod common;

use tarsier_engine::pipeline::{PipelineOptions, ProofEngine, SolverChoice, SoundnessMode};
use tarsier_engine::result::UnboundedSafetyResult;

#[test]
fn prove_unbounded_safety_trivial_invariant() {
    let source = r#"
protocol TrivialSafe {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
    property inv: invariant {
        forall p: R. p.decided == false
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 4,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };
    let result = tarsier_engine::pipeline::prove_safety(source, "trivial_safe.trs", &options)
        .expect("prove should succeed");
    match result {
        UnboundedSafetyResult::Safe { induction_k } => assert!(induction_k >= 1),
        other => panic!("Expected unbounded safe, got: {other}"),
    }
}

#[test]
fn prove_unbounded_safety_reports_real_counterexample() {
    let source = r#"
protocol TrivialUnsafe {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    message M;
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 0 M => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property inv: invariant {
        forall p: R. p.decided == false
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 4,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };
    let result = tarsier_engine::pipeline::prove_safety(source, "trivial_unsafe.trs", &options)
        .expect("prove should complete");
    match result {
        UnboundedSafetyResult::Unsafe { trace } => {
            assert!(!trace.param_values.is_empty());
        }
        other => panic!("Expected unsafe, got: {other}"),
    }
}

#[test]
fn prove_unbounded_safety_with_pdr_engine_safe() {
    let source = r#"
protocol TrivialSafePdr {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
    property inv: invariant {
        forall p: R. p.decided == false
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 4,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::Pdr,
    };
    let result = tarsier_engine::pipeline::prove_safety(source, "trivial_safe_pdr.trs", &options)
        .expect("prove should succeed");
    match result {
        UnboundedSafetyResult::Safe { induction_k } => assert!(induction_k >= 1),
        other => panic!("Expected unbounded safe, got: {other}"),
    }
}

#[test]
fn prove_unbounded_safety_with_pdr_engine_unsafe() {
    let source = r#"
protocol TrivialUnsafePdr {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    message M;
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 0 M => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property inv: invariant {
        forall p: R. p.decided == false
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 4,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::Pdr,
    };
    let result = tarsier_engine::pipeline::prove_safety(source, "trivial_unsafe_pdr.trs", &options)
        .expect("prove should complete");
    match result {
        UnboundedSafetyResult::Unsafe { trace } => {
            assert!(!trace.param_values.is_empty());
        }
        other => panic!("Expected unsafe, got: {other}"),
    }
}

#[test]
fn prove_unbounded_safety_not_proved_reports_induction_cti() {
    let source = r#"
protocol NeedsStrengthening {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: crash; bound: f; }
    message Prepare;
    role R {
        var decided: bool = false;
        init start;
        phase start {
            when received >= 1 Prepare => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property inv: invariant {
        forall p: R. p.decided == false
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 3,
        timeout_secs: 2,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };
    let result =
        tarsier_engine::pipeline::prove_safety(source, "needs_strengthening.trs", &options)
            .expect("prove should complete");
    match result {
        UnboundedSafetyResult::NotProved {
            max_k,
            cti: Some(cti),
        } => {
            assert_eq!(max_k, 3);
            assert!((1..=3).contains(&cti.k));
            assert!(!cti.violating_locations.is_empty());
            assert!(cti.violated_condition.contains("invariant violated"));
        }
        other => panic!("Expected not proved with CTI, got: {other}"),
    }
}

#[test]
fn prove_with_cegar_auto_synthesizes_predicates_from_cti() {
    let source = r#"
protocol NeedsStrengtheningCegar {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: crash; bound: f; }
    message Prepare;
    role R {
        var decided: bool = false;
        init start;
        phase start {
            when received >= 1 Prepare => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property inv: invariant {
        forall p: R. p.decided == false
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 3,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };
    let result = tarsier_engine::pipeline::prove_safety_with_cegar(
        source,
        "needs_strengthening_cegar.trs",
        &options,
        2,
    )
    .expect("prove with CEGAR should complete");
    match result {
        UnboundedSafetyResult::Safe { .. }
        | UnboundedSafetyResult::ProbabilisticallySafe { .. } => {}
        UnboundedSafetyResult::NotProved { cti: Some(cti), .. } => {
            assert!(
                cti.violated_condition
                    .contains("auto-synthesized predicates"),
                "expected synthesized predicate note, got: {}",
                cti.violated_condition
            );
        }
        UnboundedSafetyResult::Unknown { reason } => {
            assert!(
                reason.contains("Auto-synthesized predicates")
                    || reason.contains("CEGAR refinements"),
                "expected synthesis/refinement note, got: {reason}"
            );
        }
        other => panic!("Unexpected CEGAR prove result: {other}"),
    }
}
