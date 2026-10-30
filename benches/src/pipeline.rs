use crate::common::load_sample;
use criterion::{Criterion, Throughput};
use rbat::core::analyzer::Analyzer;
#[cfg(any(feature = "backend-capstone", feature = "backend-iced"))]
use rbat::core::disassembler::DisassemblerBackend;
use std::sync::atomic::{AtomicUsize, Ordering};

pub fn bench_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("pipeline");

    let buffer = load_sample("al-khaser_x86.exe_");
    let sample_len = buffer.len() as u64;

    group.throughput(Throughput::Bytes(sample_len));

    // 1. Full batch analysis with Iced backend
    #[cfg(feature = "backend-iced")]
    {
        let analyzer = Analyzer::builder()
            .with_backend(DisassemblerBackend::Iced)
            .build();
        group.bench_function("batch_iced", |b| {
            b.iter(|| analyzer.batch(&buffer).expect("Iced batch analysis failed"));
        });
    }

    // 2. Full batch analysis with Capstone backend
    #[cfg(feature = "backend-capstone")]
    {
        let analyzer = Analyzer::builder()
            .with_backend(DisassemblerBackend::Capstone)
            .build();
        group.bench_function("batch_capstone", |b| {
            b.iter(|| {
                analyzer
                    .batch(&buffer)
                    .expect("Capstone batch analysis failed")
            });
        });
    }

    // 3. Streaming analysis with callback events
    {
        let analyzer = Analyzer::builder().build();
        group.bench_function("streaming", |b| {
            b.iter(|| {
                let progress_count = AtomicUsize::new(0);
                analyzer
                    .streaming(&buffer, |_progress| {
                        progress_count.fetch_add(1, Ordering::Relaxed);
                    })
                    .expect("Streaming analysis failed");
                progress_count.load(Ordering::Relaxed)
            });
        });
    }

    // 4. Report JSON serialization throughput
    {
        let analyzer = Analyzer::builder().build();
        let (analysis_result, assessment) = analyzer
            .batch(&buffer)
            .expect("Analysis failed for report serialization");

        group.bench_function("json_serialization", |b| {
            b.iter(|| {
                serde_json::to_string(&serde_json::json!({
                    "risk_assessment": &assessment,
                    "analysis_details": &analysis_result,
                }))
                .expect("JSON serialization failed")
            });
        });
    }

    group.finish();
}
