//! Timed fair-liveness solver matrix + perf smoke tests (X-04).
//!
//! This suite mirrors the multi-quant temporal matrix style, but targets the
//! timeout/clock liveness path introduced by TIME-* tasks.

use std::{env, time::Instant};

use tarsier_engine::pipeline::{
    self, FairnessMode, PipelineOptions, ProofEngine, SolverChoice, SoundnessMode,
};
use tarsier_engine::result::{FairLivenessResult, UnboundedFairLivenessResult};

const TIMED_FAIR_CYCLE: &str = r#"
protocol TimedFairCycleMatrix {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    clock deadline;

    role R {
        var decided: bool = false;
        init s;
        phase s {
            when timeout deadline >= 1 => {
                goto phase s;
            }
        }
    }
}
"#;

fn matrix_solver_choice() -> SolverChoice {
    let raw = env::var("TARSIER_MATRIX_SOLVER").unwrap_or_else(|_| "z3".to_string());
    match raw.to_ascii_lowercase().as_str() {
        "z3" => SolverChoice::Z3,
        "cvc5" => SolverChoice::Cvc5,
        other => {
            panic!("unsupported TARSIER_MATRIX_SOLVER value: '{other}' (expected 'z3' or 'cvc5')")
        }
    }
}

fn matrix_fairness_mode() -> FairnessMode {
    let raw = env::var("TARSIER_MATRIX_FAIRNESS").unwrap_or_else(|_| "weak".to_string());
    match raw.to_ascii_lowercase().as_str() {
        "weak" => FairnessMode::Weak,
        "strong" => FairnessMode::Strong,
        other => panic!(
            "unsupported TARSIER_MATRIX_FAIRNESS value: '{other}' (expected 'weak' or 'strong')"
        ),
    }
}

fn matrix_options(engine: ProofEngine) -> PipelineOptions {
    PipelineOptions {
        solver: matrix_solver_choice(),
        max_depth: 4,
        timeout_secs: 60,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: engine,
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
fn timed_fair_cycle_bounded_matrix() {
    let opts = matrix_options(ProofEngine::KInduction);
    let fairness = matrix_fairness_mode();
    eprintln!(
        "Running timed fair-cycle bounded matrix test (solver={}, fairness={})",
        solver_label(opts.solver),
        fairness_label(fairness)
    );

    let start = Instant::now();
    let result = pipeline::check_fair_liveness_with_mode(
        TIMED_FAIR_CYCLE,
        "timed_fair_cycle_matrix.trs",
        &opts,
        fairness,
    )
    .expect("timed fair-liveness check should complete");
    let elapsed = start.elapsed();

    match result {
        FairLivenessResult::FairCycleFound {
            depth, loop_start, ..
        } => {
            assert!(depth >= 1);
            assert!(loop_start < depth);
        }
        other => panic!("expected fair-cycle witness for timed matrix protocol, got: {other}"),
    }

    assert!(
        elapsed.as_secs() < 20,
        "timed fair-liveness bounded matrix took {:.2}s (limit 20s, solver={}, fairness={})",
        elapsed.as_secs_f64(),
        solver_label(opts.solver),
        fairness_label(fairness)
    );
}

#[test]
fn timed_fair_cycle_unbounded_matrix() {
    let opts = matrix_options(ProofEngine::Pdr);
    let fairness = matrix_fairness_mode();
    eprintln!(
        "Running timed fair-cycle unbounded matrix test (solver={}, fairness={})",
        solver_label(opts.solver),
        fairness_label(fairness)
    );

    let start = Instant::now();
    let result = pipeline::prove_fair_liveness_with_mode(
        TIMED_FAIR_CYCLE,
        "timed_fair_cycle_matrix_proof.trs",
        &opts,
        fairness,
    )
    .expect("timed unbounded fair-liveness proof should complete");
    let elapsed = start.elapsed();

    match result {
        UnboundedFairLivenessResult::FairCycleFound {
            depth, loop_start, ..
        } => {
            assert!(depth >= 1);
            assert!(loop_start < depth);
        }
        other => panic!("expected timed fair-cycle proof witness, got: {other}"),
    }

    assert!(
        elapsed.as_secs() < 30,
        "timed fair-liveness unbounded matrix took {:.2}s (limit 30s, solver={}, fairness={})",
        elapsed.as_secs_f64(),
        solver_label(opts.solver),
        fairness_label(fairness)
    );
}

/// Protocol with a timeout that leads to a decision -- fair cycle found because
/// counter-abstraction cannot track per-process decided state precisely.
const TIMED_DECIDED: &str = r#"
protocol TimedDecidedMatrix {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    clock deadline;

    role R {
        var decided: bool = false;
        init s;
        phase s {
            when timeout deadline >= 1 => {
                decide 0;
                goto phase done;
            }
        }
        phase done {}
    }

    property termination: liveness {
        forall p: R. <> (p.decided == true)
    }
}
"#;

#[test]
fn timed_decided_bounded_finds_fair_cycle() {
    let opts = matrix_options(ProofEngine::KInduction);
    let fairness = matrix_fairness_mode();

    let result = pipeline::check_fair_liveness_with_mode(
        TIMED_DECIDED,
        "timed_decided_matrix.trs",
        &opts,
        fairness,
    )
    .expect("timed decided check should complete");

    match result {
        FairLivenessResult::FairCycleFound {
            depth, loop_start, ..
        } => {
            assert!(depth >= 1);
            assert!(loop_start < depth);
        }
        other => panic!("expected fair-cycle witness for timed decided protocol, got: {other}"),
    }
}

/// Protocol with no exit from initial phase (always loops) should find fair cycle.
const TIMED_STUCK: &str = r#"
protocol TimedStuckMatrix {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    clock deadline;

    role R {
        var decided: bool = false;
        init s;
        phase s {
            when timeout deadline >= 1 => {
                goto phase s;
            }
        }
    }

    property progress: liveness {
        forall p: R. <> (p.decided == true)
    }
}
"#;

#[test]
fn timed_stuck_bounded_finds_fair_cycle() {
    let opts = matrix_options(ProofEngine::KInduction);
    let fairness = matrix_fairness_mode();

    let result = pipeline::check_fair_liveness_with_mode(
        TIMED_STUCK,
        "timed_stuck_matrix.trs",
        &opts,
        fairness,
    )
    .expect("timed stuck check should complete");

    match result {
        FairLivenessResult::FairCycleFound {
            depth, loop_start, ..
        } => {
            assert!(depth >= 1);
            assert!(loop_start < depth);
        }
        other => panic!("expected fair-cycle witness for timed stuck protocol, got: {other}"),
    }
}

/// Timed protocol with always-true invariant liveness -- trivially live.
const TIMED_TRIVIAL_LIVE: &str = r#"
protocol TimedTrivialLiveMatrix {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    clock deadline;

    role R {
        var done: bool = true;
        init s;
        phase s {
            when timeout deadline >= 1 => {
                goto phase s;
            }
        }
    }

    property progress: liveness {
        forall p: R. [] (p.done == true)
    }
}
"#;

#[test]
fn timed_trivial_live_bounded_no_fair_cycle() {
    let opts = matrix_options(ProofEngine::KInduction);
    let fairness = matrix_fairness_mode();

    let result = pipeline::check_fair_liveness_with_mode(
        TIMED_TRIVIAL_LIVE,
        "timed_trivial_live_matrix.trs",
        &opts,
        fairness,
    )
    .expect("timed trivial live check should complete");

    match result {
        FairLivenessResult::NoFairCycleUpTo { depth_checked } => {
            assert_eq!(depth_checked, opts.max_depth);
        }
        other => panic!("expected no fair cycle for trivially live timed protocol, got: {other}"),
    }
}
