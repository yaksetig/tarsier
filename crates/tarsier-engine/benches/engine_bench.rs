use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tarsier_engine::pipeline::{PipelineOptions, ProofEngine, SolverChoice, SoundnessMode};

const TRIVIAL_LIVE: &str = include_str!("../../../examples/library/trivial_live.trs");
const PBFT_CORE: &str = include_str!("../../../examples/library/pbft_core.trs");

fn bench_options(depth: usize) -> PipelineOptions {
    PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: depth,
        timeout_secs: 60,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    }
}

// ---------------------------------------------------------------------------
// Lowering + encoding (individual pipeline stages)
// ---------------------------------------------------------------------------

fn bench_lower_and_encode_trivial(c: &mut Criterion) {
    let program = tarsier_dsl::parse(TRIVIAL_LIVE, "trivial_live.trs").unwrap();
    c.bench_function("engine_lower_and_encode_trivial", |b| {
        b.iter(|| {
            let ta = tarsier_ir::lowering::lower(black_box(&program)).unwrap();
            let cs = tarsier_ir::counter_system::CounterSystem::new(ta);
            let property = tarsier_ir::properties::extract_agreement_property(&cs.automaton);
            tarsier_smt::encoder::encode_bmc(black_box(&cs), black_box(&property), 3)
        })
    });
}

fn bench_lower_and_encode_pbft(c: &mut Criterion) {
    let program = tarsier_dsl::parse(PBFT_CORE, "pbft_core.trs").unwrap();
    c.bench_function("engine_lower_and_encode_pbft", |b| {
        b.iter(|| {
            let ta = tarsier_ir::lowering::lower(black_box(&program)).unwrap();
            let cs = tarsier_ir::counter_system::CounterSystem::new(ta);
            let property = tarsier_ir::properties::extract_agreement_property(&cs.automaton);
            tarsier_smt::encoder::encode_bmc(black_box(&cs), black_box(&property), 3)
        })
    });
}

// ---------------------------------------------------------------------------
// Full verification pipeline (parse -> lower -> encode -> solve)
// ---------------------------------------------------------------------------

fn bench_verify_trivial_depth3(c: &mut Criterion) {
    let options = bench_options(3);
    c.bench_function("engine_verify_trivial_depth3", |b| {
        b.iter(|| {
            tarsier_engine::pipeline::verify(
                black_box(TRIVIAL_LIVE),
                "trivial_live.trs",
                black_box(&options),
            )
            .unwrap()
        })
    });
}

fn bench_verify_pbft_depth3(c: &mut Criterion) {
    let options = bench_options(3);
    c.bench_function("engine_verify_pbft_depth3", |b| {
        b.iter(|| {
            tarsier_engine::pipeline::verify(
                black_box(PBFT_CORE),
                "pbft_core.trs",
                black_box(&options),
            )
            .unwrap()
        })
    });
}

fn bench_verify_pbft_depth5(c: &mut Criterion) {
    let options = bench_options(5);
    c.bench_function("engine_verify_pbft_depth5", |b| {
        b.iter(|| {
            tarsier_engine::pipeline::verify(
                black_box(PBFT_CORE),
                "pbft_core.trs",
                black_box(&options),
            )
            .unwrap()
        })
    });
}

criterion_group!(
    benches,
    bench_lower_and_encode_trivial,
    bench_lower_and_encode_pbft,
    bench_verify_trivial_depth3,
    bench_verify_pbft_depth3,
    bench_verify_pbft_depth5,
);
criterion_main!(benches);
