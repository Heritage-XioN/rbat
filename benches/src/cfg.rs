use crate::common::{load_sample, parse_sample_context};
use criterion::{Criterion, Throughput};
use rbat::core::cfg::ControlFlowGraph;
use rbat::core::disassembler::IcedBackend;
use rbat::core::traits::Disassembler;

pub fn bench_cfg(c: &mut Criterion) {
    let mut group = c.benchmark_group("cfg");

    // Load and disassemble al-khaser_x86.exe_ once for CFG benchmarking
    let buffer = load_sample("al-khaser_x86.exe_");
    let ctx = parse_sample_context(&buffer);
    let backend = IcedBackend;
    let instructions = backend
        .disassemble(&ctx.text_bytes, ctx.entry_addr, ctx.arch, &ctx.iat_map)
        .expect("Disassembly failed");

    let instr_count = instructions.len() as u64;
    group.throughput(Throughput::Elements(instr_count));

    // 1. CFG Construction (leaders, blocks, edges, function partitioning)
    group.bench_function("build", |b| {
        b.iter(|| ControlFlowGraph::new(instructions.clone(), &ctx.arch))
    });

    let cfg = ControlFlowGraph::new(instructions.clone(), &ctx.arch);

    // 2. Petgraph graph representation conversion
    group.bench_function("to_petgraph", |b| b.iter(|| cfg.to_petgraph()));

    // 3. DOT format generation
    group.bench_function("to_dot", |b| b.iter(|| cfg.to_dot()));

    // 4. Function traversal and instruction enumeration
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
