use crate::common::{load_sample, parse_sample_context};
use criterion::{Criterion, Throughput};
use rbat::core::{cfg::ControlFlowGraph, disassembler::IcedBackend, traits::Disassembler};

fn bench_cfg_sample(
    c: &mut Criterion,
    group_name: &str,
    sample_file: &str,
    sample_size: Option<usize>,
) {
    let mut group = c.benchmark_group(group_name);
    if let Some(size) = sample_size {
        group.sample_size(size);
    }
    let buffer = load_sample(sample_file);
    let ctx = parse_sample_context(&buffer);
    let backend = IcedBackend;
    let instructions = backend
        .disassemble(&ctx.text_bytes, ctx.entry_addr, ctx.arch, &ctx.iat_map)
        .expect("Disassembly failed");

    let instr_count = instructions.len() as u64;
    group.throughput(Throughput::Elements(instr_count));

    group.bench_function("build", |b| {
        b.iter(|| ControlFlowGraph::new(instructions.clone(), &ctx.arch))
    });

    let cfg = ControlFlowGraph::new(instructions.clone(), &ctx.arch);
    group.bench_function("to_petgraph", |b| b.iter(|| cfg.to_petgraph()));
    group.bench_function("to_dot", |b| b.iter(|| cfg.to_dot()));
    group.bench_function("function_traversal", |b| {
        b.iter(|| {
            let mut total_insns = 0;
            for func in cfg.functions.values() {
                total_insns += cfg.as_function_instr(func).count();
            }
            total_insns
        })
    });
    group.finish();
}

pub fn bench_cfg(c: &mut Criterion) {
    // 1. Small CFG benchmark (al-khaser_x86.exe_)
    bench_cfg_sample(c, "cfg_small", "al-khaser_x86.exe_", None);

    // 2. Large CFG benchmark (112f9f0e8d349858a80dd8c14190e620.exe_)
    bench_cfg_sample(
        c,
        "cfg_large",
        "112f9f0e8d349858a80dd8c14190e620.exe_",
        Some(10),
    );
}
