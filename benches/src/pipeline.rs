use crate::common::load_sample;
use criterion::{Criterion, Throughput};
use rbat::core::analyzer::Analyzer;
#[cfg(any(feature = "backend-capstone", feature = "backend-iced"))]
use rbat::core::disassembler::DisassemblerBackend;
use std::sync::atomic::{AtomicUsize, Ordering};

fn bench_pipeline_sample(
    c: &mut Criterion,
    group_name: &str,
    sample_file: &str,
    sample_size: Option<usize>,
    bench_serialization: bool,
) {
    let mut group = c.benchmark_group(group_name);
    if let Some(size) = sample_size {
        group.sample_size(size);
    }
    let buffer = load_sample(sample_file);
    let sample_len = buffer.len() as u64;
    group.throughput(Throughput::Bytes(sample_len));

    #[cfg(feature = "backend-iced")]
    {
        let analyzer = Analyzer::builder()
            .with_backend(DisassemblerBackend::Iced)
            .build();
        group.bench_function("batch_iced", |b| {
            b.iter(|| analyzer.batch(&buffer).expect("Iced batch analysis failed"));
        });
    }

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

    if bench_serialization {
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

pub fn bench_pipeline(c: &mut Criterion) {
    // 1. Small pipeline (al-khaser_x86.exe_)
    bench_pipeline_sample(c, "pipeline_small", "al-khaser_x86.exe_", None, true);

    // 2. Large pipeline (112f9f0e8d349858a80dd8c14190e620.exe_, 9.19MB)
    bench_pipeline_sample(
        c,
        "pipeline_large",
        "112f9f0e8d349858a80dd8c14190e620.exe_",
        Some(10),
        false,
    );
}
