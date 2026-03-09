mod common;

use tarsier_engine::pipeline::{
    FairnessMode, PipelineOptions, ProofEngine, SolverChoice, SoundnessMode,
};
use tarsier_engine::result::{FairLivenessResult, LivenessResult, UnboundedFairLivenessResult};

#[test]
fn bounded_liveness_uses_explicit_liveness_property() {
    let source = r#"
protocol CustomLiveness {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var done: bool = false;
        init s;
        phase s {
            when received >= 0 Tick => {
                done = true;
                goto phase done_phase;
            }
        }
        phase done_phase {}
    }
    message Tick;
    property term: liveness {
        forall p: R. p.done == true
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 1,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };
    let result = tarsier_engine::pipeline::check_liveness(source, "custom_liveness.trs", &options)
        .expect("liveness check should complete");
    match result {
        LivenessResult::NotLive { .. } | LivenessResult::Live { .. } => {}
        other => panic!("Expected concrete bounded liveness result, got: {other}"),
    }
}

#[test]
fn bounded_liveness_supports_temporal_always_operator() {
    let source = r#"
protocol TemporalAlways {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var safe: bool = true;
        init s;
        phase s {}
    }
    property live: liveness {
        forall p: R. [] (p.safe == true)
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
    let result = tarsier_engine::pipeline::check_liveness(source, "temporal_always.trs", &options)
        .expect("temporal liveness check should complete");
    match result {
        LivenessResult::Live { depth_checked } => assert_eq!(depth_checked, 3),
        other => panic!("Expected LIVE temporal result, got: {other}"),
    }
}

#[test]
fn bounded_liveness_supports_temporal_next_operator() {
    let source = r#"
protocol TemporalNext {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var ready: bool = false;
        init s;
        phase s {}
    }
    property live: liveness {
        forall p: R. X (p.ready == true)
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 1,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };
    let result = tarsier_engine::pipeline::check_liveness(source, "temporal_next.trs", &options)
        .expect("temporal next liveness check should complete");
    match result {
        LivenessResult::NotLive { .. } => {}
        other => panic!("Expected NOT LIVE temporal-next result, got: {other}"),
    }
}

#[test]
fn bounded_liveness_supports_temporal_leads_to_operator() {
    let source = r#"
protocol TemporalLeadsTo {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    message Tick;
    role R {
        var flag: bool = false;
        init s0;
        phase s0 {
            when received >= 0 Tick => {
                flag = true;
                goto phase s1;
            }
        }
        phase s1 {}
    }
    property live: liveness {
        forall p: R. (p.flag == true) ~> <> (p.flag == false)
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 1,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };
    let result =
        tarsier_engine::pipeline::check_liveness(source, "temporal_leads_to.trs", &options)
            .expect("temporal liveness check should complete");
    match result {
        LivenessResult::NotLive { .. } => {}
        other => panic!("Expected NOT LIVE temporal result, got: {other}"),
    }
}

#[test]
fn fair_liveness_finds_nonterminating_lasso() {
    let source = r#"
protocol FairNonTerminating {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = false;
        init s;
        phase s {}
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
    let result =
        tarsier_engine::pipeline::check_fair_liveness(source, "fair_nonterminating.trs", &options)
            .expect("fair liveness search should complete");
    match result {
        FairLivenessResult::FairCycleFound {
            depth, loop_start, ..
        } => {
            assert!(depth >= 1);
            assert!(loop_start < depth);
        }
        other => panic!("Expected fair cycle, got: {other}"),
    }
}

#[test]
fn fair_liveness_supports_unbounded_temporal_formula() {
    let source = r#"
protocol FairTemporalUnsupported {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
    property live: liveness {
        forall p: R. [] (p.decided == false)
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
    let result =
        tarsier_engine::pipeline::check_fair_liveness(source, "fair_temporal.trs", &options)
            .expect("fair-liveness should support temporal operators");
    match result {
        FairLivenessResult::NoFairCycleUpTo { depth_checked } => assert_eq!(depth_checked, 3),
        other => panic!("Expected no fair cycle for satisfied temporal property, got: {other}"),
    }
}

#[test]
fn fair_liveness_supports_unbounded_temporal_next_operator() {
    let source = r#"
protocol FairTemporalNext {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
    property live: liveness {
        forall p: R. [] (X (p.decided == false))
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
    let result =
        tarsier_engine::pipeline::check_fair_liveness(source, "fair_temporal_next.trs", &options)
            .expect("fair-liveness should support temporal next operator");
    match result {
        FairLivenessResult::NoFairCycleUpTo { depth_checked } => assert_eq!(depth_checked, 3),
        other => panic!("Expected no fair cycle for temporal-next property, got: {other}"),
    }
}

#[test]
fn fair_liveness_supports_all_unbounded_temporal_infix_operators() {
    let source = r#"
protocol FairTemporalInfixOps {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
    property live: liveness {
        forall p: R.
            ((p.decided == false) U (p.decided == false)) &&
            ((p.decided == false) W (p.decided == true)) &&
            ((p.decided == false) R (p.decided == false)) &&
            ((p.decided == true) ~> <> (p.decided == false))
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
    let result = tarsier_engine::pipeline::check_fair_liveness(
        source,
        "fair_temporal_infix_ops.trs",
        &options,
    )
    .expect("fair-liveness should support all infix temporal operators");
    match result {
        FairLivenessResult::NoFairCycleUpTo { depth_checked } => assert_eq!(depth_checked, 3),
        other => panic!("Expected no fair cycle for satisfied temporal formula, got: {other}"),
    }
}

#[test]
fn prove_fair_liveness_accepts_temporal_formula() {
    let source = r#"
protocol FairTemporalCounterexample {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
    property live: liveness {
        forall p: R. <> (p.decided == true)
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 5,
        timeout_secs: 2,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::Pdr,
    };
    let result =
        tarsier_engine::pipeline::prove_fair_liveness(source, "fair_temporal_cex.trs", &options)
            .expect("prove-fair should support temporal operators");
    match result {
        UnboundedFairLivenessResult::FairCycleFound { .. }
        | UnboundedFairLivenessResult::LiveProved { .. }
        | UnboundedFairLivenessResult::NotProved { .. }
        | UnboundedFairLivenessResult::Unknown { .. } => {}
    }
}

#[test]
fn prove_fair_liveness_accepts_all_temporal_infix_operators() {
    let source = r#"
protocol FairTemporalInfixProof {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
    property live: liveness {
        forall p: R.
            ((p.decided == false) U (p.decided == false)) &&
            ((p.decided == false) W (p.decided == true)) &&
            ((p.decided == false) R (p.decided == false)) &&
            ((p.decided == true) ~> <> (p.decided == false))
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 5,
        timeout_secs: 2,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::Pdr,
    };
    let result = tarsier_engine::pipeline::prove_fair_liveness(
        source,
        "fair_temporal_infix_proof.trs",
        &options,
    )
    .expect("prove-fair should support all infix temporal operators");
    match result {
        UnboundedFairLivenessResult::FairCycleFound { .. }
        | UnboundedFairLivenessResult::LiveProved { .. }
        | UnboundedFairLivenessResult::NotProved { .. }
        | UnboundedFairLivenessResult::Unknown { .. } => {}
    }
}

#[test]
fn fair_liveness_no_counterexample_when_already_decided() {
    let source = r#"
protocol FairAlreadyDecided {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = true;
        init s;
        phase s {}
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
    let result =
        tarsier_engine::pipeline::check_fair_liveness(source, "fair_already_decided.trs", &options)
            .expect("fair liveness search should complete");
    match result {
        FairLivenessResult::NoFairCycleUpTo { depth_checked } => {
            assert_eq!(depth_checked, 3);
        }
        other => panic!("Expected no fair cycle up to bound, got: {other}"),
    }
}

#[test]
fn fair_liveness_strong_mode_finds_counterexample() {
    let source = r#"
protocol FairNonTerminatingStrong {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = false;
        init s;
        phase s {}
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

    let strong = tarsier_engine::pipeline::check_fair_liveness_with_mode(
        source,
        "fair_nonterminating_strong.trs",
        &options,
        FairnessMode::Strong,
    )
    .expect("strong fair liveness should complete");
    match strong {
        FairLivenessResult::FairCycleFound { .. } => {}
        other => panic!("Expected strong fairness cycle, got: {other}"),
    }
}

#[test]
fn fair_liveness_partial_synchrony_ignores_pre_gst_only_cycles() {
    let source = r#"
protocol FairAfterGst {
    params n, t, f, gst;
    resilience: n > 3*t;
    adversary { model: omission; bound: f; timing: partial_synchrony; gst: gst; }
    message Tick;
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 0 Tick => {
                send Tick;
                goto phase s;
            }
            when received >= 1 Tick => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 6,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };
    let result = tarsier_engine::pipeline::check_fair_liveness_with_mode(
        source,
        "fair_after_gst.trs",
        &options,
        FairnessMode::Weak,
    )
    .expect("fair-liveness search should complete");
    match result {
        FairLivenessResult::NoFairCycleUpTo { depth_checked } => assert_eq!(depth_checked, 6),
        other => panic!("Expected no fair cycle after GST, got: {other}"),
    }
}

#[test]
fn prove_fair_liveness_reports_counterexample() {
    let source = r#"
protocol FairNonTerminatingProof {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 3,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::Pdr,
    };
    let result = tarsier_engine::pipeline::prove_fair_liveness(
        source,
        "fair_nonterminating_proof.trs",
        &options,
    )
    .expect("unbounded fair liveness proof should complete");
    match result {
        UnboundedFairLivenessResult::FairCycleFound {
            depth, loop_start, ..
        } => {
            assert!(depth >= 1);
            assert!(loop_start < depth);
        }
        other => panic!("Expected fair cycle counterexample, got: {other}"),
    }
}

#[test]
fn prove_fair_liveness_with_strong_mode_reports_counterexample() {
    let source = r#"
protocol FairNonTerminatingProofStrong {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 3,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::Pdr,
    };
    let result = tarsier_engine::pipeline::prove_fair_liveness_with_mode(
        source,
        "fair_nonterminating_proof_strong.trs",
        &options,
        FairnessMode::Strong,
    )
    .expect("unbounded fair liveness proof should complete");
    match result {
        UnboundedFairLivenessResult::FairCycleFound {
            depth, loop_start, ..
        } => {
            assert!(depth >= 1);
            assert!(loop_start < depth);
        }
        other => panic!("Expected strong-fair cycle counterexample, got: {other}"),
    }
}

#[test]
fn prove_fair_liveness_with_cegar_report_exposes_controls_and_machine_readable_status() {
    let source = r#"
protocol FairNonTerminatingProofReport {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 3,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::Pdr,
    };

    let report = tarsier_engine::pipeline::prove_fair_liveness_with_cegar_report(
        source,
        "fair_nonterminating_proof_report.trs",
        &options,
        FairnessMode::Strong,
        1,
    )
    .expect("fair-liveness CEGAR proof report should complete");

    assert_eq!(report.controls.max_refinements, 1);
    assert_eq!(report.controls.timeout_secs, 30);
    assert_eq!(report.controls.solver, "z3");
    assert_eq!(report.controls.proof_engine.as_deref(), Some("pdr"));
    assert_eq!(report.controls.fairness.as_deref(), Some("strong"));
    assert_eq!(report.stages.len(), 2);
    assert_eq!(report.stages[0].stage, 0);
    assert_eq!(report.stages[1].stage, 1);
    assert_eq!(report.stages[0].label, "baseline");
    assert!(report.stages[1]
        .note
        .as_deref()
        .unwrap_or_default()
        .contains("Selection rationale"));
    assert!(matches!(
        report.baseline_result,
        UnboundedFairLivenessResult::FairCycleFound { .. }
    ));
    assert!(matches!(
        report.final_result,
        UnboundedFairLivenessResult::FairCycleFound { .. }
    ));
    assert_eq!(report.classification, "fair_cycle_confirmed");
    let analysis = report
        .counterexample_analysis
        .expect("counterexample analysis should exist");
    assert_eq!(analysis.classification, "concrete");
}

#[test]
fn prove_fair_liveness_proves_already_decided_protocol() {
    let source = r#"
protocol FairAlreadyDecidedProof {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = true;
        init s;
        phase s {}
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 3,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::Pdr,
    };
    let result = tarsier_engine::pipeline::prove_fair_liveness(
        source,
        "fair_already_decided_proof.trs",
        &options,
    )
    .expect("unbounded fair liveness proof should complete");
    match result {
        UnboundedFairLivenessResult::LiveProved { frame } => assert!(frame <= 3),
        other => panic!("Expected proved fair liveness, got: {other}"),
    }
}

#[test]
fn prove_fair_liveness_k_zero_runs_unbounded_until_result() {
    let source = r#"
protocol FairNonTerminatingUnbounded {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 0,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::Pdr,
    };
    let result = tarsier_engine::pipeline::prove_fair_liveness(
        source,
        "fair_nonterminating_unbounded.trs",
        &options,
    )
    .expect("unbounded fair liveness proof should complete");
    match result {
        UnboundedFairLivenessResult::FairCycleFound { .. } => {}
        other => panic!("Expected fair cycle for unbounded k=0 run, got: {other}"),
    }
}
