//! PDR/IC3 performance regression benchmarks (PDR-05).
//!
//! Tracks fair-liveness PDR convergence time on reference protocols.
//! Regressions are caught by the criterion + github-action-benchmark pipeline
//! (115% alert threshold).

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::time::Duration;
use tarsier_engine::pipeline::{
    self, FairnessMode, PipelineOptions, ProofEngine, SolverChoice, SoundnessMode,
};

const TRIVIAL_LIVE: &str = include_str!("../../../examples/library/trivial_live.trs");
const RB_SAFE_LIVE: &str =
    include_str!("../../../examples/library/reliable_broadcast_safe_live.trs");
const RB_LIVE_BUGGY: &str =
    include_str!("../../../examples/library/reliable_broadcast_live_buggy.trs");
const PBFT_LIVE_SAFE: &str = include_str!("../../../examples/library/pbft_liveness_safe_ci.trs");
const PBFT_LIVE_BUGGY: &str = include_str!("../../../examples/library/pbft_liveness_buggy_ci.trs");

fn pdr_options(depth: usize) -> PipelineOptions {
    PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: depth,
        timeout_secs: 120,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::Pdr,
    }
}

// ---------------------------------------------------------------------------
// Bounded fair-liveness (lasso search)
// ---------------------------------------------------------------------------

fn bench_bounded_trivial_live(c: &mut Criterion) {
    let opts = pdr_options(4);
    let mut group = c.benchmark_group("pdr_bounded");
    group.measurement_time(Duration::from_secs(20));
    group.bench_function("trivial_live_weak", |b| {
        b.iter(|| {
            pipeline::check_fair_liveness_with_mode(
                black_box(TRIVIAL_LIVE),
                "trivial_live.trs",
                black_box(&opts),
                FairnessMode::Weak,
            )
            .unwrap()
        })
    });
    group.finish();
}

fn bench_bounded_rb_safe_live(c: &mut Criterion) {
    let opts = pdr_options(4);
    let mut group = c.benchmark_group("pdr_bounded");
    group.measurement_time(Duration::from_secs(30));
    group.bench_function("rb_safe_live_weak", |b| {
        b.iter(|| {
            pipeline::check_fair_liveness_with_mode(
                black_box(RB_SAFE_LIVE),
                "reliable_broadcast_safe_live.trs",
                black_box(&opts),
                FairnessMode::Weak,
            )
            .unwrap()
        })
    });
    group.finish();
}

fn bench_bounded_rb_live_buggy(c: &mut Criterion) {
    let opts = pdr_options(4);
    let mut group = c.benchmark_group("pdr_bounded");
    group.measurement_time(Duration::from_secs(30));
    group.bench_function("rb_live_buggy_weak", |b| {
        b.iter(|| {
            pipeline::check_fair_liveness_with_mode(
                black_box(RB_LIVE_BUGGY),
                "reliable_broadcast_live_buggy.trs",
                black_box(&opts),
                FairnessMode::Weak,
            )
            .unwrap()
        })
    });
    group.finish();
}

// ---------------------------------------------------------------------------
// Unbounded fair-liveness (PDR proof / counterexample)
// ---------------------------------------------------------------------------

fn bench_unbounded_trivial_live(c: &mut Criterion) {
    let opts = pdr_options(8);
    let mut group = c.benchmark_group("pdr_unbounded");
    group.measurement_time(Duration::from_secs(30));
    group.bench_function("trivial_live_weak", |b| {
        b.iter(|| {
            pipeline::prove_fair_liveness_with_mode(
                black_box(TRIVIAL_LIVE),
                "trivial_live.trs",
                black_box(&opts),
                FairnessMode::Weak,
            )
            .unwrap()
        })
    });
    group.finish();
}

fn bench_unbounded_rb_live_buggy(c: &mut Criterion) {
    let opts = pdr_options(8);
    let mut group = c.benchmark_group("pdr_unbounded");
    group.measurement_time(Duration::from_secs(30));
    group.bench_function("rb_live_buggy_weak", |b| {
        b.iter(|| {
            pipeline::prove_fair_liveness_with_mode(
                black_box(RB_LIVE_BUGGY),
                "reliable_broadcast_live_buggy.trs",
                black_box(&opts),
                FairnessMode::Weak,
            )
            .unwrap()
        })
    });
    group.finish();
}

fn bench_unbounded_pbft_safe(c: &mut Criterion) {
    let opts = pdr_options(8);
    let mut group = c.benchmark_group("pdr_unbounded");
    group.measurement_time(Duration::from_secs(60));
    group.sample_size(10);
    group.bench_function("pbft_safe_weak", |b| {
        b.iter(|| {
            pipeline::prove_fair_liveness_with_mode(
                black_box(PBFT_LIVE_SAFE),
                "pbft_liveness_safe_ci.trs",
                black_box(&opts),
                FairnessMode::Weak,
            )
            .unwrap()
        })
    });
    group.finish();
}

fn bench_unbounded_pbft_buggy(c: &mut Criterion) {
    let opts = pdr_options(8);
    let mut group = c.benchmark_group("pdr_unbounded");
    group.measurement_time(Duration::from_secs(60));
    group.sample_size(10);
    group.bench_function("pbft_buggy_weak", |b| {
        b.iter(|| {
            pipeline::prove_fair_liveness_with_mode(
                black_box(PBFT_LIVE_BUGGY),
                "pbft_liveness_buggy_ci.trs",
                black_box(&opts),
                FairnessMode::Weak,
            )
            .unwrap()
        })
    });
    group.finish();
}

// ---------------------------------------------------------------------------
// Strong fairness variants (catch regressions in fairness mode switching)
// ---------------------------------------------------------------------------

fn bench_bounded_rb_safe_live_strong(c: &mut Criterion) {
    let opts = pdr_options(4);
    let mut group = c.benchmark_group("pdr_bounded_strong");
    group.measurement_time(Duration::from_secs(30));
    group.bench_function("rb_safe_live_strong", |b| {
        b.iter(|| {
            pipeline::check_fair_liveness_with_mode(
                black_box(RB_SAFE_LIVE),
                "reliable_broadcast_safe_live.trs",
                black_box(&opts),
                FairnessMode::Strong,
            )
            .unwrap()
        })
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_bounded_trivial_live,
    bench_bounded_rb_safe_live,
    bench_bounded_rb_live_buggy,
    bench_unbounded_trivial_live,
    bench_unbounded_rb_live_buggy,
    bench_unbounded_pbft_safe,
    bench_unbounded_pbft_buggy,
    bench_bounded_rb_safe_live_strong,
);
criterion_main!(benches);
