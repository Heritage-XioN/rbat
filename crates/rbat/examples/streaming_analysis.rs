//! # Streaming Analysis Example
//!
//! demonstrates programmatic streaming analysis with real-time callbacks using
//! `rbat::core::analyzer::Analyzer::streaming`.

use rbat::core::analyzer::Analyzer;
use rbat::core::types::analysis::AnalysisProgress;

// Include a lightweight test ELF binary from the test suite at compile-time
const SAMPLE_ELF: &[u8] = include_bytes!("../tests/capa-testfiles/microsocks.elf_");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize Analyzer
    let analyzer = Analyzer::builder().build();

    println!("Starting streaming static binary analysis...\n");

    // 2. Execute streaming analysis with an inline closure callback
    analyzer.streaming(SAMPLE_ELF, |event| match event {
        AnalysisProgress::BinaryMetadata(meta) => {
            println!(
                "[Progress] Header: format={} arch={} entry=0x{:08x}",
                meta.binary_type,
                meta.architecture_name(),
                meta.entry_point
            );
        }
        AnalysisProgress::Hashes(hashes) => {
            println!("[Progress] Hashes: SHA-256={}", hashes.sha256);
        }
        AnalysisProgress::Entropy(ref entropy) => {
            println!("[Progress] Entropy: evaluated {} sections", entropy.len());
        }
        AnalysisProgress::Disassembly(ref instructions) => {
            println!(
                "[Progress] Disassembly: decoded {} instructions",
                instructions.len()
            );
        }
        AnalysisProgress::CFG(ref cfg) => {
            println!(
                "[Progress] CFG: {} basic blocks, {} intra-procedural functions",
                cfg.blocks.len(),
                cfg.functions.len()
            );
        }
        AnalysisProgress::Strings(ref strings) => {
            println!(
                "[Progress] Strings: matched {} suspicious pattern groups",
                strings.len()
            );
        }
        AnalysisProgress::LibraryFunctions(ref funcs) => {
            println!(
                "[Progress] FLIRT: recognized {} compiler runtime functions",
                funcs.len()
            );
        }
        _ => {}
    })?;

    println!("\nStreaming analysis completed successfully.");
    Ok(())
}
