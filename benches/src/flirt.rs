use crate::common::{load_sample, parse_sample_context};
use criterion::{Criterion, Throughput};
use rbat::core::{
    cfg::ControlFlowGraph, disassembler::IcedBackend, flirt::FlirtMatcher, traits::Disassembler,
};

pub fn bench_flirt(c: &mut Criterion) {
    let mut group = c.benchmark_group("flirt");

    // 1. Loading & parsing embedded signature database
    group.bench_function("load_embedded", |b| b.iter(FlirtMatcher::load_embedded));

    let matcher = FlirtMatcher::embedded_shared();

    // 2. Matching function bytes across all functions extracted from al-khaser_x86.exe_
    let buffer = load_sample("al-khaser_x86.exe_");
    let ctx = parse_sample_context(&buffer);
    let backend = IcedBackend;
    let instructions = backend
        .disassemble(&ctx.text_bytes, ctx.entry_addr, ctx.arch, &ctx.iat_map)
        .expect("Disassembly failed");
    let cfg = ControlFlowGraph::new(instructions, &ctx.arch);

    // Collect function byte slices
    let function_entries: Vec<u64> = cfg.functions.keys().copied().collect();
    let num_functions = function_entries.len() as u64;

    group.throughput(Throughput::Elements(num_functions));

    // Extract function bytes (up to 128 bytes from function entry)
    let function_byte_slices: Vec<Vec<u8>> = function_entries
        .iter()
        .filter_map(|&addr| {
            if addr >= ctx.entry_addr {
                let offset = (addr - ctx.entry_addr) as usize;
                if offset < ctx.text_bytes.len() {
                    let end = (offset + 128).min(ctx.text_bytes.len());
                    return Some(ctx.text_bytes[offset..end].to_vec());
                }
            }
            None
        })
        .collect();

    group.bench_function("match_function_prologues", |b| {
        b.iter(|| {
            let mut matches = 0;
            for slice in &function_byte_slices {
                if matcher.match_bytes(slice).is_some() {
                    matches += 1;
                }
            }
            matches
        })
    });

    group.finish();
}
