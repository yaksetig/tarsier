use std::env;

use tarsier_engine::pipeline::{
    self, FairnessMode, PipelineOptions, ProofEngine, SolverChoice, SoundnessMode,
};
use tarsier_engine::result::FairLivenessResult;

const LIVE_PROTOCOL: &str = r#"
protocol MultiQuantTemporalLiveMatrix {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }

    role R {
        var done: bool = true;
        init s;
        phase s {}
    }

    property progress: liveness {
        forall p: R. exists q: R. [] (p.done == q.done)
    }
}
"#;

const BUGGY_PROTOCOL: &str = r#"
protocol MultiQuantTemporalBugMatrix {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }

    role R {
        var done: bool = false;
        init s;
        phase s {}
    }

    property progress: liveness {
        forall p: R. exists q: R. <> ((p.done == true) && (q.done == true))
    }
}
"#;

fn matrix_solver_choice() -> SolverChoice {
    let raw = env::var("TARSIER_MATRIX_SOLVER").unwrap_or_else(|_| "z3".to_string());
    match raw.trim().to_ascii_lowercase().as_str() {
        "z3" => SolverChoice::Z3,
        "cvc5" => SolverChoice::Cvc5,
        other => {
            panic!("unsupported TARSIER_MATRIX_SOLVER value: '{other}' (expected 'z3' or 'cvc5')")
        }
    }
}

fn matrix_fairness_mode() -> FairnessMode {
    let raw = env::var("TARSIER_MATRIX_FAIRNESS").unwrap_or_else(|_| "weak".to_string());
    match raw.trim().to_ascii_lowercase().as_str() {
        "weak" => FairnessMode::Weak,
        "strong" => FairnessMode::Strong,
        other => panic!(
            "unsupported TARSIER_MATRIX_FAIRNESS value: '{other}' (expected 'weak' or 'strong')"
        ),
    }
}

fn matrix_pipeline_options() -> PipelineOptions {
    PipelineOptions {
        solver: matrix_solver_choice(),
        max_depth: 4,
        timeout_secs: 60,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    }
}

fn solver_label(solver: SolverChoice) -> &'static str {
    match solver {
        SolverChoice::Z3 => "z3",
        SolverChoice::Cvc5 => "cvc5",
    }
}

fn fairness_label(mode: FairnessMode) -> &'static str {
    match mode {
        FairnessMode::Weak => "weak",
        FairnessMode::Strong => "strong",
    }
}

#[test]
fn matrix_multi_quant_temporal_live_case_has_no_fair_cycle() {
    let opts = matrix_pipeline_options();
    let fairness = matrix_fairness_mode();

    eprintln!(
        "Running multi-quant temporal live matrix test (solver={}, fairness={})",
        solver_label(opts.solver),
        fairness_label(fairness)
    );

    let result = pipeline::check_fair_liveness_with_mode(
        LIVE_PROTOCOL,
        "multi_quant_temporal_live_matrix.trs",
        &opts,
        fairness,
    )
    .expect("multi-quant temporal live matrix check should complete");

    match result {
        FairLivenessResult::NoFairCycleUpTo { depth_checked } => {
            assert_eq!(depth_checked, opts.max_depth);
        }
        FairLivenessResult::FairCycleFound { .. } => {
            panic!("expected no fair cycle for live matrix protocol, got fair-cycle witness")
        }
        FairLivenessResult::Unknown { reason } => panic!(
            "unexpected inconclusive multi-quant temporal live matrix result \
             (solver={}, fairness={}): {}",
            solver_label(opts.solver),
            fairness_label(fairness),
            reason
        ),
    }
}

#[test]
fn matrix_multi_quant_temporal_bug_case_finds_fair_cycle() {
    let opts = matrix_pipeline_options();
    let fairness = matrix_fairness_mode();

    eprintln!(
        "Running multi-quant temporal bug matrix test (solver={}, fairness={})",
        solver_label(opts.solver),
        fairness_label(fairness)
    );

    let result = pipeline::check_fair_liveness_with_mode(
        BUGGY_PROTOCOL,
        "multi_quant_temporal_bug_matrix.trs",
        &opts,
        fairness,
    )
    .expect("multi-quant temporal bug matrix check should complete");

    match result {
        FairLivenessResult::FairCycleFound {
            depth, loop_start, ..
        } => {
            assert!(depth >= 1);
            assert!(loop_start < depth);
        }
        FairLivenessResult::NoFairCycleUpTo { depth_checked } => panic!(
            "expected a fair-cycle witness for bug matrix protocol \
             (solver={}, fairness={}), but search returned no cycle up to depth {}",
            solver_label(opts.solver),
            fairness_label(fairness),
            depth_checked
        ),
        FairLivenessResult::Unknown { reason } => panic!(
            "unexpected inconclusive multi-quant temporal bug matrix result \
             (solver={}, fairness={}): {}",
            solver_label(opts.solver),
            fairness_label(fairness),
            reason
        ),
    }
}
