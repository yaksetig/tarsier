use criterion::{black_box, criterion_group, criterion_main, Criterion};

const TRIVIAL_LIVE: &str = include_str!("../../../examples/library/trivial_live.trs");
const PBFT_CORE: &str = include_str!("../../../examples/library/pbft_core.trs");
const HOTSTUFF_CHAINED: &str = include_str!("../../../examples/library/hotstuff_chained.trs");

fn bench_parse_trivial(c: &mut Criterion) {
    c.bench_function("parse_trivial", |b| {
        b.iter(|| tarsier_dsl::parse(black_box(TRIVIAL_LIVE), "trivial_live.trs").unwrap())
    });
}

fn bench_parse_pbft(c: &mut Criterion) {
    c.bench_function("parse_pbft", |b| {
        b.iter(|| tarsier_dsl::parse(black_box(PBFT_CORE), "pbft_core.trs").unwrap())
    });
}

fn bench_parse_hotstuff(c: &mut Criterion) {
    c.bench_function("parse_hotstuff", |b| {
        b.iter(|| tarsier_dsl::parse(black_box(HOTSTUFF_CHAINED), "hotstuff_chained.trs").unwrap())
    });
}

criterion_group!(
    benches,
    bench_parse_trivial,
    bench_parse_pbft,
    bench_parse_hotstuff
);
criterion_main!(benches);
