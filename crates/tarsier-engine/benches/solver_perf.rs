use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tarsier_engine::pipeline::{PipelineOptions, ProofEngine, SolverChoice, SoundnessMode};

const RELIABLE_BROADCAST: &str =
    include_str!("../../../examples/library/reliable_broadcast_safe.trs");

fn bmc_options(depth: usize) -> PipelineOptions {
    PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: depth,
        timeout_secs: 120,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    }
}

// ---------------------------------------------------------------------------
// BMC solver performance at increasing depths
// ---------------------------------------------------------------------------

fn bench_bmc_rb_depth1(c: &mut Criterion) {
    let options = bmc_options(1);
    c.bench_function("solver_bmc_reliable_broadcast_depth1", |b| {
        b.iter(|| {
            tarsier_engine::pipeline::verify(
                black_box(RELIABLE_BROADCAST),
                "reliable_broadcast_safe.trs",
                black_box(&options),
            )
            .unwrap()
        })
    });
}

fn bench_bmc_rb_depth2(c: &mut Criterion) {
    let options = bmc_options(2);
    c.bench_function("solver_bmc_reliable_broadcast_depth2", |b| {
        b.iter(|| {
            tarsier_engine::pipeline::verify(
                black_box(RELIABLE_BROADCAST),
                "reliable_broadcast_safe.trs",
                black_box(&options),
            )
            .unwrap()
        })
    });
}

fn bench_bmc_rb_depth3(c: &mut Criterion) {
    let options = bmc_options(3);
    c.bench_function("solver_bmc_reliable_broadcast_depth3", |b| {
        b.iter(|| {
            tarsier_engine::pipeline::verify(
                black_box(RELIABLE_BROADCAST),
                "reliable_broadcast_safe.trs",
                black_box(&options),
            )
            .unwrap()
        })
    });
}

// ---------------------------------------------------------------------------
// K-induction proof (full pipeline including solver)
// ---------------------------------------------------------------------------

fn bench_kinduction_rb(c: &mut Criterion) {
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 10,
        timeout_secs: 120,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };
    c.bench_function("solver_kinduction_reliable_broadcast", |b| {
        b.iter(|| {
            tarsier_engine::pipeline::verify(
                black_box(RELIABLE_BROADCAST),
                "reliable_broadcast_safe.trs",
                black_box(&options),
            )
            .unwrap()
        })
    });
}

criterion_group!(
    benches,
    bench_bmc_rb_depth1,
    bench_bmc_rb_depth2,
    bench_bmc_rb_depth3,
    bench_kinduction_rb,
);
criterion_main!(benches);
