use crate::common::{load_sample, parse_sample_context};
use criterion::{BenchmarkId, Criterion, Throughput};
#[cfg(feature = "backend-capstone")]
use rbat::core::disassembler::CapstoneBackend;
#[cfg(feature = "backend-iced")]
use rbat::core::disassembler::IcedBackend;
#[cfg(any(feature = "backend-capstone", feature = "backend-iced"))]
use rbat::core::traits::Disassembler;

pub fn bench_disassembly(c: &mut Criterion) {
    let mut group = c.benchmark_group("disassembly");

    // 1. x86 32-bit disassembly benchmark (al-khaser_x86.exe_)
    let x86_buffer = load_sample("al-khaser_x86.exe_");
    let x86_ctx = parse_sample_context(&x86_buffer);
    let x86_bytes_len = x86_ctx.text_bytes.len() as u64;

    group.throughput(Throughput::Bytes(x86_bytes_len));

    #[cfg(feature = "backend-iced")]
    group.bench_function(BenchmarkId::new("x86_32", "iced"), |b| {
        let backend = IcedBackend;
        b.iter(|| {
            backend
                .disassemble(
                    &x86_ctx.text_bytes,
                    x86_ctx.entry_addr,
                    x86_ctx.arch,
                    &x86_ctx.iat_map,
                )
                .expect("Iced disassembly failed")
        });
    });

    #[cfg(feature = "backend-capstone")]
    group.bench_function(BenchmarkId::new("x86_32", "capstone"), |b| {
        let backend = CapstoneBackend;
        b.iter(|| {
            backend
                .disassemble(
                    &x86_ctx.text_bytes,
                    x86_ctx.entry_addr,
                    x86_ctx.arch,
                    &x86_ctx.iat_map,
                )
                .expect("Capstone disassembly failed")
        });
    });

    // 2. x86_64 64-bit disassembly benchmark (kernel32-64.dll_)
    let x64_buffer = load_sample("kernel32-64.dll_");
    let x64_ctx = parse_sample_context(&x64_buffer);
    let x64_bytes_len = x64_ctx.text_bytes.len() as u64;

    group.throughput(Throughput::Bytes(x64_bytes_len));

    #[cfg(feature = "backend-iced")]
    group.bench_function(BenchmarkId::new("x86_64", "iced"), |b| {
        let backend = IcedBackend;
        b.iter(|| {
            backend
                .disassemble(
                    &x64_ctx.text_bytes,
                    x64_ctx.entry_addr,
                    x64_ctx.arch,
                    &x64_ctx.iat_map,
                )
                .expect("Iced disassembly failed")
        });
    });

    #[cfg(feature = "backend-capstone")]
    group.bench_function(BenchmarkId::new("x86_64", "capstone"), |b| {
        let backend = CapstoneBackend;
        b.iter(|| {
            backend
                .disassemble(
                    &x64_ctx.text_bytes,
                    x64_ctx.entry_addr,
                    x64_ctx.arch,
                    &x64_ctx.iat_map,
                )
                .expect("Capstone disassembly failed")
        });
    });

    group.finish();
}
