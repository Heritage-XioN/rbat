//! # Determinism Regression Tests
//!
//! Verifies that analysis results are fully deterministic across multiple runs.
//! This guards against non-determinism from hash-map iteration order,
//! parallel scheduling, and pattern index assignment.

use rbat::core::analyzer::Analyzer;
use std::path::PathBuf;

/// Helper to get the absolute path to a sample in capa-testfiles.
fn get_sample_path(filename: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/capa-testfiles");
    path.push(filename);
    path
}

/// Number of repeated runs to verify determinism.
const DETERMINISM_RUNS: usize = 3;

/// Asserts that multiple full batch analyses of the same binary produce
/// identical scores, findings, and category breakdowns every time.
fn assert_deterministic(filename: &str) {
    let sample_path = get_sample_path(filename);
    if !sample_path.exists() {
        println!(
            "Skipping determinism test: capa-testfiles submodule not found at {:?}",
            sample_path
        );
        return;
    }

    let buffer = std::fs::read(&sample_path)
        .unwrap_or_else(|e| panic!("Failed to read test sample {}: {}", filename, e));

    // Collect results from N independent analysis runs, each with a freshly
    // built Analyzer (and therefore a fresh NeedleIndex, Aho-Corasick automaton,
    // and rayon thread pool scope).
    let mut scores: Vec<u32> = Vec::with_capacity(DETERMINISM_RUNS);
    let mut severities: Vec<String> = Vec::with_capacity(DETERMINISM_RUNS);
    let mut finding_names: Vec<Vec<String>> = Vec::with_capacity(DETERMINISM_RUNS);
    let mut hashes: Vec<String> = Vec::with_capacity(DETERMINISM_RUNS);
    let mut category_breakdowns: Vec<Vec<(String, u8)>> = Vec::with_capacity(DETERMINISM_RUNS);

    for run in 0..DETERMINISM_RUNS {
        let analyzer = Analyzer::builder()
            .build()
            .unwrap_or_else(|e| panic!("Failed to build analyzer on run {}: {}", run, e));

        let (analysis, assessment) = analyzer
            .batch(&buffer)
            .unwrap_or_else(|e| panic!("Failed to analyze {} on run {}: {}", filename, run, e));

        scores.push(assessment.score);
        severities.push(assessment.severity.clone());
        hashes.push(analysis.hashes.sha256.clone());

        let mut names: Vec<String> = assessment
            .findings
            .iter()
            .map(|f| f.indicator.clone())
            .collect();
        names.sort();
        finding_names.push(names);

        let mut categories: Vec<(String, u8)> = assessment
            .category_breakdown
            .iter()
            .map(|c| (c.category.clone(), c.score))
            .collect();
        categories.sort();
        category_breakdowns.push(categories);
    }

    // All runs must produce identical results
    let baseline_score = &scores[0];
    let baseline_severity = &severities[0];
    let baseline_findings = &finding_names[0];
    let baseline_hash = &hashes[0];
    let baseline_categories = &category_breakdowns[0];

    for run in 1..DETERMINISM_RUNS {
        assert_eq!(
            &scores[run], baseline_score,
            "[{}] Score diverged on run {}: got {}, expected {}",
            filename, run, scores[run], baseline_score,
        );
        assert_eq!(
            &severities[run], baseline_severity,
            "[{}] Severity diverged on run {}: got {:?}, expected {:?}",
            filename, run, severities[run], baseline_severity,
        );
        assert_eq!(
            &hashes[run], baseline_hash,
            "[{}] Hash diverged on run {} (should be impossible)",
            filename, run,
        );
        assert_eq!(
            &finding_names[run], baseline_findings,
            "[{}] Findings diverged on run {}:\n  got:      {:?}\n  expected: {:?}",
            filename, run, finding_names[run], baseline_findings,
        );
        assert_eq!(
            &category_breakdowns[run], baseline_categories,
            "[{}] Category breakdown diverged on run {}",
            filename, run,
        );
    }
}

// ── PE Samples ──────────────────────────────────────────────────────────────

#[test]
fn test_determinism_pe_al_khaser_x86() {
    assert_deterministic("al-khaser_x86.exe_");
}

#[test]
fn test_determinism_pe_mimikatz() {
    assert_deterministic("mimikatz.exe_");
}

#[test]
fn test_determinism_pe_packed_upx() {
    assert_deterministic("Practical Malware Analysis Lab 01-02.exe_");
}

// ── ELF Samples ─────────────────────────────────────────────────────────────

#[test]
fn test_determinism_elf_microsocks() {
    assert_deterministic("microsocks.elf_");
}

// ── DLL Samples ─────────────────────────────────────────────────────────────

#[test]
fn test_determinism_dll_kernel32_64() {
    assert_deterministic("kernel32-64.dll_");
}

#[test]
fn test_determinism_dll_kernel32() {
    assert_deterministic("kernel32.dll_");
}
