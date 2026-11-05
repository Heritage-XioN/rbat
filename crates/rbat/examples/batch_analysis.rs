//! # Batch Analysis Example
//!
//! demonstrates programmatic batch analysis using `rbat::core::analyzer::Analyzer::batch`.

use rbat::core::analyzer::Analyzer;

// Include a lightweight test ELF binary from the test suite at compile-time
const SAMPLE_ELF: &[u8] = include_bytes!("../tests/capa-testfiles/microsocks.elf_");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize Analyzer with embedded Capa rules, FLIRT signatures, and severity classifier
    let analyzer = Analyzer::builder().build();

    // 2. Execute static binary analysis
    let (analysis_result, risk_assessment) = analyzer.batch(SAMPLE_ELF)?;

    // 3. Inspect header metadata
    println!("Binary Type:   {}", analysis_result.metadata.binary_type);
    println!(
        "Architecture:  {}",
        analysis_result.metadata.architecture_name()
    );
    println!(
        "Entry Point:   0x{:08x}",
        analysis_result.metadata.entry_point
    );
    println!(
        "Analysis Time: {} ms",
        analysis_result.total_analysis_time_ms
    );

    // 4. Inspect hashes
    println!("\nHashes:");
    println!("  SHA-256: {}", analysis_result.hashes.sha256);
    println!("  TLSH:    {}", analysis_result.hashes.tlsh);
    println!("  SSDEEP:  {}", analysis_result.hashes.ssdeep);

    // 5. Inspect section entropy
    println!("\nSection Entropy:");
    for (section, entropy) in &analysis_result.section_entropy {
        println!("  {:<16} => {:.4}", section, entropy);
    }

    // 6. Inspect Control Flow Graph summary
    if let Some(ref cfg) = analysis_result.cfg {
        println!("\nControl Flow Graph:");
        println!("  Basic Blocks: {}", cfg.blocks.len());
        println!("  Functions:    {}", cfg.functions.len());
    }

    // 7. Inspect Bayesian risk assessment and matched capabilities
    println!("\nThreat Assessment:");
    println!("  Risk Score: {}/100", risk_assessment.score);
    println!("  Severity:   {}", risk_assessment.severity);
    println!("  Findings:   {}", risk_assessment.findings.len());

    for finding in &risk_assessment.findings {
        println!("  [{:?}] {}", finding.severity_class, finding.indicator);
        if !finding.attack_ids.is_empty() {
            println!("    MITRE ATT&CK: {:?}", finding.attack_ids);
        }
        if !finding.mbc_ids.is_empty() {
            println!("    MBC:          {:?}", finding.mbc_ids);
        }
    }

    Ok(())
}
