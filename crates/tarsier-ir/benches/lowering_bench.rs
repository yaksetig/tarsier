use criterion::{black_box, criterion_group, criterion_main, Criterion};

const TRIVIAL_LIVE: &str = include_str!("../../../examples/library/trivial_live.trs");
const PBFT_CORE: &str = include_str!("../../../examples/library/pbft_core.trs");
const HOTSTUFF_CHAINED: &str = include_str!("../../../examples/library/hotstuff_chained.trs");

fn bench_lower_trivial(c: &mut Criterion) {
    let program = tarsier_dsl::parse(TRIVIAL_LIVE, "trivial_live.trs").unwrap();
    c.bench_function("lower_trivial", |b| {
        b.iter(|| tarsier_ir::lowering::lower(black_box(&program)).unwrap())
    });
}

fn bench_lower_pbft(c: &mut Criterion) {
    let program = tarsier_dsl::parse(PBFT_CORE, "pbft_core.trs").unwrap();
    c.bench_function("lower_pbft", |b| {
        b.iter(|| tarsier_ir::lowering::lower(black_box(&program)).unwrap())
    });
}

fn bench_lower_hotstuff(c: &mut Criterion) {
    let program = tarsier_dsl::parse(HOTSTUFF_CHAINED, "hotstuff_chained.trs").unwrap();
    c.bench_function("lower_hotstuff", |b| {
        b.iter(|| tarsier_ir::lowering::lower(black_box(&program)).unwrap())
    });
}

criterion_group!(
    benches,
    bench_lower_trivial,
    bench_lower_pbft,
    bench_lower_hotstuff
);
criterion_main!(benches);
