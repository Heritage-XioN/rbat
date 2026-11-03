use crate::common::load_sample;
use criterion::{Criterion, Throughput};
use rbat::core::analyzer::Analyzer;
use rbat::core::features::FeatureSet;
use rbat::core::needle::NeedleIndex;
use rbat::core::rule::Rule;

pub fn bench_rules(c: &mut Criterion) {
    let rules = Rule::load_embedded();
    let rules_count = rules.len() as u64;

    // --- 1. NeedleIndex Construction ---
    {
        let mut group = c.benchmark_group("needle_index");
        group.throughput(Throughput::Elements(rules_count));
        group.bench_function("build", |b| b.iter(|| NeedleIndex::new(&rules)));
        group.finish();
    }

    let needle = NeedleIndex::new(&rules);

    // --- 2. Multi-Pattern Buffer Scanning (ASCII + UTF-16LE) ---
    {
        let mut group = c.benchmark_group("needle_scan");

        // Small 4KB buffer
        let small_buf = vec![0x90u8; 4096];
        group.throughput(Throughput::Bytes(4096));
        group.bench_function("synthetic_4kb", |b| {
            b.iter(|| needle.scan_buffer(&small_buf))
        });

        // Realistic 438KB binary sample
        let sample = load_sample("al-khaser_x86.exe_");
        let sample_len = sample.len() as u64;
        group.throughput(Throughput::Bytes(sample_len));
        group.bench_function("al_khaser_438kb", |b| {
            b.iter(|| needle.scan_buffer(&sample))
        });

        group.finish();
    }

    // --- 3. Rule Evaluation over Extracted Features ---
    {
        let mut group = c.benchmark_group("rule_eval");
        group.throughput(Throughput::Elements(rules_count));

        // Small sample: al-khaser_x86.exe_
        let buffer = load_sample("al-khaser_x86.exe_");
        let analyzer = Analyzer::builder().build();
        let (analysis_result, _) = analyzer
            .batch(&buffer)
            .expect("Batch analysis failed to generate test features");

        let features = FeatureSet::new(&analysis_result, &buffer);

        group.bench_function("small/evaluate", |b| {
            b.iter(|| Rule::evaluate(&features, &rules, &needle))
        });

        // Large sample: 112f9f0e8d349858a80dd8c14190e620.exe_ (9.19MB)
        let large_buffer = load_sample("112f9f0e8d349858a80dd8c14190e620.exe_");
        let (large_analysis_result, _) = analyzer
            .batch(&large_buffer)
            .expect("Batch analysis failed to generate test features");
        let large_features = FeatureSet::new(&large_analysis_result, &large_buffer);

        group.sample_size(10);
        group.bench_function("large/evaluate", |b| {
            b.iter(|| Rule::evaluate(&large_features, &rules, &needle))
        });

        group.finish();
    }
}
