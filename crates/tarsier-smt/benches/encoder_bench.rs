use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tarsier_ir::counter_system::CounterSystem;
use tarsier_ir::properties::extract_agreement_property;

const TRIVIAL_LIVE: &str = include_str!("../../../examples/library/trivial_live.trs");
const PBFT_CORE: &str = include_str!("../../../examples/library/pbft_core.trs");

fn parse_and_lower(source: &str, filename: &str) -> CounterSystem {
    let program = tarsier_dsl::parse(source, filename).unwrap();
    let ta = tarsier_ir::lowering::lower(&program).unwrap();
    CounterSystem::new(ta)
}

fn bench_encode_bmc_trivial_depth3(c: &mut Criterion) {
    let cs = parse_and_lower(TRIVIAL_LIVE, "trivial_live.trs");
    let property = extract_agreement_property(&cs.automaton);
    c.bench_function("encode_bmc_trivial_depth3", |b| {
        b.iter(|| tarsier_smt::encoder::encode_bmc(black_box(&cs), black_box(&property), 3))
    });
}

fn bench_encode_bmc_pbft_depth3(c: &mut Criterion) {
    let cs = parse_and_lower(PBFT_CORE, "pbft_core.trs");
    let property = extract_agreement_property(&cs.automaton);
    c.bench_function("encode_bmc_pbft_depth3", |b| {
        b.iter(|| tarsier_smt::encoder::encode_bmc(black_box(&cs), black_box(&property), 3))
    });
}

fn bench_encode_bmc_pbft_depth5(c: &mut Criterion) {
    let cs = parse_and_lower(PBFT_CORE, "pbft_core.trs");
    let property = extract_agreement_property(&cs.automaton);
    c.bench_function("encode_bmc_pbft_depth5", |b| {
        b.iter(|| tarsier_smt::encoder::encode_bmc(black_box(&cs), black_box(&property), 5))
    });
}

criterion_group!(
    benches,
    bench_encode_bmc_trivial_depth3,
    bench_encode_bmc_pbft_depth3,
    bench_encode_bmc_pbft_depth5
);
criterion_main!(benches);
