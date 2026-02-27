//! Performance regression tests for the multi-quantifier temporal encoding path.
//!
//! These tests assert wall-clock time stays within generous bounds. They are
//! deliberately lenient (10-60s) to avoid flaking on CI, while still catching
//! order-of-magnitude regressions.

use std::time::Instant;

use tarsier_engine::pipeline::{
    self, FairnessMode, PipelineOptions, ProofEngine, SolverChoice, SoundnessMode,
};

const TEMPORAL_LIVENESS: &str = include_str!("../../../examples/temporal_liveness.trs");

const MULTI_QUANT_TEMPORAL: &str = r#"
protocol MultiQuantPerf {
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

fn options(depth: usize) -> PipelineOptions {
    PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: depth,
        timeout_secs: 60,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    }
}

#[test]
fn temporal_liveness_depth3_under_10s() {
    let opts = options(3);
    let start = Instant::now();
    let result = pipeline::check_liveness(TEMPORAL_LIVENESS, "temporal_liveness.trs", &opts);
    let elapsed = start.elapsed();

    assert!(
        result.is_ok(),
        "temporal liveness check should succeed: {:?}",
        result.err()
    );
    assert!(
        elapsed.as_secs() < 10,
        "temporal liveness depth-3 took {:.1}s (limit 10s)",
        elapsed.as_secs_f64()
    );
}

#[test]
fn multi_quant_temporal_fair_liveness_depth3_under_30s() {
    let opts = options(3);
    let start = Instant::now();
    let result = pipeline::check_fair_liveness_with_mode(
        MULTI_QUANT_TEMPORAL,
        "multi_quant_perf.trs",
        &opts,
        FairnessMode::Weak,
    );
    let elapsed = start.elapsed();

    assert!(
        result.is_ok(),
        "multi-quant fair liveness check should succeed: {:?}",
        result.err()
    );
    assert!(
        elapsed.as_secs() < 30,
        "multi-quant fair liveness depth-3 took {:.1}s (limit 30s)",
        elapsed.as_secs_f64()
    );
}

#[test]
fn multi_quant_temporal_fair_liveness_depth5_under_60s() {
    let opts = options(5);
    let start = Instant::now();
    let result = pipeline::check_fair_liveness_with_mode(
        MULTI_QUANT_TEMPORAL,
        "multi_quant_perf.trs",
        &opts,
        FairnessMode::Weak,
    );
    let elapsed = start.elapsed();

    assert!(
        result.is_ok(),
        "multi-quant fair liveness check should succeed: {:?}",
        result.err()
    );
    assert!(
        elapsed.as_secs() < 60,
        "multi-quant fair liveness depth-5 took {:.1}s (limit 60s)",
        elapsed.as_secs_f64()
    );
}
