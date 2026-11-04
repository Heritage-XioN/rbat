//! # Custom Disassembler Backend Example
//!
//! demonstrates how to implement the `rbat::core::traits::Disassembler`
//! trait and register a custom instruction decoding engine via `DisassemblerBackend::custom`.

use std::sync::Arc;

use rbat::core::analyzer::AnalyzerBuilder;
use rbat::core::disassembler::{DisassemblerBackend, InstructionInfo};
use rbat::core::parser::{BinaryArch, IatMap};
use rbat::core::traits::Disassembler;
use rbat::core::types::result::RbatResult;

// Include a lightweight test ELF binary from the test suite at compile-time
const SAMPLE_ELF: &[u8] = include_bytes!("../tests/capa-testfiles/microsocks.elf_");

/// A lightweight custom disassembler demonstrating trait implementation.
#[derive(Debug)]
struct SimpleDecoder {
    name: &'static str,
}

impl SimpleDecoder {
    pub fn new() -> Self {
        Self {
            name: "simple-custom-decoder",
        }
    }
}

impl Disassembler for SimpleDecoder {
    fn disassemble(
        &self,
        text_bytes: &[u8],
        entry_addr: u64,
        arch: BinaryArch,
        _iat_map: &IatMap,
    ) -> RbatResult<Arc<[InstructionInfo]>> {
        let mut instructions = Vec::new();
        let mut offset = 0;

        // Custom decoding loop (simple single/multi-byte pattern matching)
        while offset < text_bytes.len() {
            let addr = entry_addr + offset as u64;
            let byte = text_bytes[offset];

            let (mnemonic, op_str, size) = match byte {
                0x90 => ("nop", "", 1),
                0xc3 => ("ret", "", 1),
                0xcc => ("int3", "", 1),
                0x31 if offset + 1 < text_bytes.len() && text_bytes[offset + 1] == 0xc0 => {
                    ("xor", "eax, eax", 2)
                }
                0x31 if offset + 1 < text_bytes.len() && text_bytes[offset + 1] == 0xff => {
                    ("xor", "edi, edi", 2)
                }
                0xb8 if offset + 4 < text_bytes.len() => ("mov", "eax, imm32", 5),
                0x0f if offset + 1 < text_bytes.len() && text_bytes[offset + 1] == 0x05 => {
                    ("syscall", "", 2)
                }
                _ => ("db", "raw", 1),
            };

            let insn = InstructionInfo::with_classified_flow(addr, mnemonic, op_str, &arch, None);

            instructions.push(insn);
            offset += size;
        }

        Ok(instructions.into())
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Instantiate the custom disassembler engine
    let custom_decoder = Arc::new(SimpleDecoder::new());
    let custom_backend = DisassemblerBackend::custom(custom_decoder);

    println!(
        "Registered custom disassembler backend: {}",
        custom_backend.name()
    );

    // 2. Build Analyzer with the custom disassembler backend
    let analyzer = AnalyzerBuilder::new().with_backend(custom_backend).build();

    // 3. Run analysis
    let (analysis_result, risk_assessment) = analyzer.batch(SAMPLE_ELF)?;

    // 4. Output results
    println!("\nAnalysis Results with Custom Disassembler:");
    println!("  Binary Format: {}", analysis_result.metadata.binary_type);
    println!(
        "  Architecture:  {}",
        analysis_result.metadata.architecture_name()
    );
    println!(
        "  Entry Point:   0x{:08x}",
        analysis_result.metadata.entry_point
    );
    if let Some(ref cfg) = analysis_result.cfg {
        println!("  CFG Blocks:    {}", cfg.blocks.len());
        println!("  Functions:     {}", cfg.functions.len());
    }
    println!(
        "  Risk Score:    {}/100 ({})",
        risk_assessment.score, risk_assessment.severity
    );

    Ok(())
}
