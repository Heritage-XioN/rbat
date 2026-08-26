//! # Heuristic Analysis Plugins
//!
//! This module implements modular static analysis analyzers as individual plugins
//! implementing the [`HeuristicPlugin`] trait. This enables parallelized analysis execution.
//!
//! # Architecture
//! Every heuristic task (such as disassembly, entropy estimation, signature matches)
//! is encapsulated in its own plugin structure. These plugins take a shared read-only
//! references context ([`AnalysisContext`]) and run concurrently.
//!
//! # Example
//! ```rust
//! use std::path::Path;
//! use object::File;
//! use rbat::core::{AnalysisContext, BinaryArch, BinaryOS, AnalysisProgress};
//! use rbat::core::plugins::MetadataPlugin;
//! use rbat::core::traits::HeuristicPlugin;
//! use std::sync::Arc;
//! use rbat::core::types::NeedleIndex;
//!
//! # fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let buffer = vec![0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 62, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 56, 0, 1, 0, 64, 0, 0, 0, 0, 0];
//! let obj = File::parse(buffer.as_slice())?;
//! let section_ranges = vec![];
//!
//! let needle = Arc::new(NeedleIndex::build_from_rules(&[]));
//! let ctx = AnalysisContext {
//!     buffer: &buffer,
//!     binary_object: &obj,
//!     section_ranges: &section_ranges,
//!     os: BinaryOS::Linux,
//!     arch: BinaryArch::X64,
//!     text_bytes: &buffer,
//!     entry_addr: 0x1000,
//!     instructions: &[],
//!     needle: needle.clone(),
//! };
//!
//! let progress = MetadataPlugin.run(&ctx)?;
//! match progress {
//!     AnalysisProgress::BinaryMetadata(meta) => {
//!         println!("Detected: {}", meta.binary_type);
//!     }
//!     _ => {}
//! }
//! # Ok(())
//! # }
//! ```

use crate::core::heuristics::disassemble_section;
use crate::core::traits::HeuristicPlugin;
use crate::core::{AnalysisContext, AnalysisProgress, Result, parser::Parser};
use crate::core::{packer_sig_check, string_check};
use crate::utils::get_metadata::get_binary_metadata;
use crate::utils::hashing::compute_hashes;

/// A plugin that computes cryptographic digests (MD5, SHA-1, SHA-256) and
/// similarity hashes (SSDEEP, TLSH) over the raw binary buffer, producing the
/// identifier set used by triage platforms (VirusTotal, MalwareBazaar).
pub struct HashingPlugin;

impl HeuristicPlugin for HashingPlugin {
    fn name(&self) -> &'static str {
        "hashing"
    }

    fn run<'buf, 'ctx>(&self, ctx: &AnalysisContext<'buf, 'ctx>) -> Result<AnalysisProgress<'buf>> {
        Ok(AnalysisProgress::Hashes(compute_hashes(ctx.buffer)))
    }
}

/// A plugin that performs instruction disassembly using Capstone.
/// Detects code caves (NOP runs, zero/trap padding runs) and anti-analysis/evasion instruction mnemonics.
pub struct DisassemblyPlugin;

impl HeuristicPlugin for DisassemblyPlugin {
    fn name(&self) -> &'static str {
        "disassembly"
    }

    fn run<'buf, 'ctx>(&self, ctx: &AnalysisContext<'buf, 'ctx>) -> Result<AnalysisProgress<'buf>> {
        let code_cave = disassemble_section(ctx.instructions, ctx.text_bytes, ctx.entry_addr)?;
        Ok(AnalysisProgress::Disassembly(code_cave))
    }
}

/// A plugin that performs YARA scanning on strings in the binary.
/// Flags common indicator rules or obfuscated content strings.
pub struct StringCheckPlugin;

impl HeuristicPlugin for StringCheckPlugin {
    fn name(&self) -> &'static str {
        "string_check"
    }

    fn run<'buf, 'ctx>(&self, ctx: &AnalysisContext<'buf, 'ctx>) -> Result<AnalysisProgress<'buf>> {
        let results = string_check(ctx.buffer, ctx.section_ranges)?;
        Ok(AnalysisProgress::Strings(results))
    }
}

/// A plugin that checks the binary's byte structures against packer, cryptor, or compiler signatures.
pub struct PackerSigCheckPlugin;

impl HeuristicPlugin for PackerSigCheckPlugin {
    fn name(&self) -> &'static str {
        "packer_sig_check"
    }

    fn run<'buf, 'ctx>(&self, ctx: &AnalysisContext<'buf, 'ctx>) -> Result<AnalysisProgress<'buf>> {
        let results = packer_sig_check(ctx.buffer, ctx.section_ranges)?;
        Ok(AnalysisProgress::PackerSigs(results))
    }
}

/// A plugin that computes entropy metrics across individual binary section ranges to detect packed, encrypted, or compressed payloads.
pub struct EntropyPlugin;

impl HeuristicPlugin for EntropyPlugin {
    fn name(&self) -> &'static str {
        "entropy"
    }

    fn run<'buf, 'ctx>(&self, ctx: &AnalysisContext<'buf, 'ctx>) -> Result<AnalysisProgress<'buf>> {
        let parser = Parser::new(ctx.binary_object);
        let results = parser.evaluate_section_entropy()?;
        Ok(AnalysisProgress::Entropy(results))
    }
}

/// A plugin that extracts imported functions and symbols.
pub struct ImportsPlugin;

impl HeuristicPlugin for ImportsPlugin {
    fn name(&self) -> &'static str {
        "imports"
    }

    fn run<'buf, 'ctx>(&self, ctx: &AnalysisContext<'buf, 'ctx>) -> Result<AnalysisProgress<'buf>> {
        let parser = Parser::new(ctx.binary_object);
        let mut matched = Vec::new();
        if let Ok(imports) = parser.extract_imports() {
            for raw_import in imports {
                for mat in ctx.needle.automaton.find_overlapping_iter(raw_import) {
                    let pat_idx = mat.pattern().as_usize();
                    matched.push(pat_idx);
                    ctx.needle.present[pat_idx].store(true, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
        Ok(AnalysisProgress::Imports(matched))
    }
}

/// A plugin that extracts exported functions and symbols.
pub struct ExportsPlugin;

impl HeuristicPlugin for ExportsPlugin {
    fn name(&self) -> &'static str {
        "exports"
    }

    fn run<'buf, 'ctx>(&self, ctx: &AnalysisContext<'buf, 'ctx>) -> Result<AnalysisProgress<'buf>> {
        let parser = Parser::new(ctx.binary_object);
        let mut matched = Vec::new();
        if let Ok(exports) = parser.extract_exports() {
            for raw_export in exports {
                for mat in ctx.needle.automaton.find_overlapping_iter(raw_export) {
                    let pat_idx = mat.pattern().as_usize();
                    matched.push(pat_idx);
                    ctx.needle.present[pat_idx].store(true, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
        Ok(AnalysisProgress::Exports(matched))
    }
}

/// A plugin that extracts basic format metadata from binary headers (e.g. entry points, machine CPU, type strings).
pub struct MetadataPlugin;

impl HeuristicPlugin for MetadataPlugin {
    fn name(&self) -> &'static str {
        "metadata"
    }

    fn run<'buf, 'ctx>(&self, ctx: &AnalysisContext<'buf, 'ctx>) -> Result<AnalysisProgress<'buf>> {
        let results = get_binary_metadata(ctx.binary_object)?;
        Ok(AnalysisProgress::BinaryMetadata(results))
    }
}

/// A plugin that reconstructs the Control Flow Graph (CFG) from the disassembled binary section.
pub struct CfgPlugin;

impl HeuristicPlugin for CfgPlugin {
    fn name(&self) -> &'static str {
        "cfg"
    }

    fn run<'buf, 'ctx>(&self, ctx: &AnalysisContext<'buf, 'ctx>) -> Result<AnalysisProgress<'buf>> {
        let cfg = crate::core::cfg::ControlFlowGraph::new(ctx.instructions, &ctx.arch);
        Ok(AnalysisProgress::CFG(cfg))
    }
}

#[cfg(all(test, feature = "backend-capstone"))]
mod tests {
    use super::*;
    use crate::core::{BinaryArch, BinaryOS};
    use crate::utils::test_helpers::test_helpers;
    use object::File;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_metadata_plugin() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("mock_elf");
        test_helpers::generate_elf(&path);

        let buffer = fs::read(&path).unwrap();
        let obj = File::parse(buffer.as_slice()).unwrap();
        let section_ranges = crate::utils::section_offset::build_section_map(&obj).unwrap();

        let ctx = AnalysisContext {
            buffer: &buffer,
            binary_object: &obj,
            section_ranges: &section_ranges,
            os: BinaryOS::Linux,
            arch: BinaryArch::X64,
            text_bytes: &[],
            entry_addr: 0x1000,
            instructions: &[],
            needle: std::sync::Arc::new(crate::core::types::NeedleIndex::build_from_rules(&[])),
        };

        let result = MetadataPlugin.run(&ctx).unwrap();
        match result {
            AnalysisProgress::BinaryMetadata(meta) => {
                assert_eq!(meta.binary_type, "Linux ELF");
            }
            _ => panic!("Expected BinaryMetadata progress"),
        }
    }

    #[test]
    fn test_entropy_plugin() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("mock_elf");
        test_helpers::generate_elf(&path);

        let buffer = fs::read(&path).unwrap();
        let obj = File::parse(buffer.as_slice()).unwrap();
        let section_ranges = crate::utils::section_offset::build_section_map(&obj).unwrap();

        let ctx = AnalysisContext {
            buffer: &buffer,
            binary_object: &obj,
            section_ranges: &section_ranges,
            os: BinaryOS::Linux,
            arch: BinaryArch::X64,
            text_bytes: &[],
            entry_addr: 0x1000,
            instructions: &[],
            needle: std::sync::Arc::new(crate::core::types::NeedleIndex::build_from_rules(&[])),
        };

        let result = EntropyPlugin.run(&ctx).unwrap();
        match result {
            AnalysisProgress::Entropy(entropy) => {
                assert!(!entropy.is_empty());
            }
            _ => panic!("Expected Entropy progress"),
        }
    }

    #[test]
    fn test_disassembly_plugin() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("mock_elf");
        test_helpers::generate_elf(&path);

        let buffer = fs::read(&path).unwrap();
        let obj = File::parse(buffer.as_slice()).unwrap();
        let section_ranges = crate::utils::section_offset::build_section_map(&obj).unwrap();

        let text_bytes = vec![0x90; 128];
        let instructions = vec![
            crate::core::disassembler::InstructionInfo {
                address: 0x1000,
                mnemonic: "nop".into(),
                op_str: "".into(),
                api_resolution: None,
                matched: smallvec::SmallVec::new(),
            };
            128
        ];

        let ctx = AnalysisContext {
            buffer: &buffer,
            binary_object: &obj,
            section_ranges: &section_ranges,
            os: BinaryOS::Linux,
            arch: BinaryArch::X64,
            text_bytes: &text_bytes,
            entry_addr: 0x1000,
            instructions: &instructions,
            needle: std::sync::Arc::new(crate::core::types::NeedleIndex::build_from_rules(&[])),
        };

        let result = DisassemblyPlugin.run(&ctx).unwrap();
        match result {
            AnalysisProgress::Disassembly(code_cave) => {
                assert!(code_cave.contains_key("nop_addr"));
                assert_eq!(code_cave.get("nop_addr").unwrap().len(), 128);
            }
            _ => panic!("Expected Disassembly progress"),
        }
    }
}
