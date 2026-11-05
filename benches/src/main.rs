mod cfg;
mod common;
mod disassembly;
mod flirt;
mod pipeline;
mod rules;

use cfg::bench_cfg;
use criterion::{criterion_group, criterion_main};
use disassembly::bench_disassembly;
use flirt::bench_flirt;
use pipeline::bench_pipeline;
use rules::bench_rules;

criterion_group!(
    benches,
    bench_disassembly,
    bench_cfg,
    bench_rules,
    bench_flirt,
    bench_pipeline,
);
criterion_main!(benches);
