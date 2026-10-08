//! # Heuristic Analysis Plugins
//!
//! This module implements modular static analysis analyzers as individual plugins
//! implementing the `HeuristicPlugin` trait. This enables parallelized analysis execution.
//!
//! # Architecture
//! Every heuristic task (such as disassembly, entropy estimation, signature matches)
//! is encapsulated in its own plugin structure. These plugins take a shared read-only
//! context (`AnalysisContext`) and run concurrently.
//!
//! # Example
//! ```rust,ignore
//! use object::File;
//! use rbat::core::types::{AnalysisContext, AnalysisProgress};
//! use rbat::core::parser::BinaryArch;
//! use rbat::core::parser::BinaryOS;
//! use rbat::core::plugins::MetadataPlugin;
//! use rbat::core::traits::HeuristicPlugin;
//! use std::sync::Arc;
//! use rbat::core::types::NeedleIndex;
//! use rbat::core::flirt::FlirtMatcher;
//!
//! # fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let buffer = vec![0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 62, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 56, 0, 1, 0, 64, 0, 0, 0, 0, 0];
//! let obj = File::parse(buffer.as_slice())?;
//! let section_ranges = vec![];
//! let entry_points = FlirtMatcher::collect_entry_points(&obj, &[], &BinaryArch::X64, 0x1000);
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
//!     instructions: Arc::from([]),
//!     needle: needle.clone(),
//!     entry_points,
//!     custom_flirt: &None,
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

use std::sync::Arc;

use crate::{
    core::{
        heuristics::{disassemble_section, packer_sig_check, string_check},
        parser::Parser,
        traits::HeuristicPlugin,
        types::{
            analysis::{AnalysisContext, AnalysisProgress, BinaryMetadata},
            result::RbatResult,
        },
    },
    utils::hashing::compute_hashes,
};

/// A plugin that computes cryptographic digests (MD5, SHA-1, SHA-256) and
/// similarity hashes (SSDEEP, TLSH) over the raw binary buffer, producing the
/// identifier set used by triage platforms (VirusTotal, MalwareBazaar).
pub(crate) struct HashingPlugin;

impl HeuristicPlugin for HashingPlugin {
    fn run<'buf, 'ctx>(
        &self,
        ctx: &AnalysisContext<'buf, 'ctx>,
    ) -> RbatResult<AnalysisProgress<'buf>> {
        Ok(AnalysisProgress::Hashes(compute_hashes(ctx.buffer)))
    }
}

/// A plugin that scans pre-disassembled instructions for code caves
/// (NOP runs, zero/trap padding runs) and anti-analysis/evasion instruction mnemonics.
pub(crate) struct DisassemblyPlugin;

impl HeuristicPlugin for DisassemblyPlugin {
    fn run<'buf, 'ctx>(
        &self,
        ctx: &AnalysisContext<'buf, 'ctx>,
    ) -> RbatResult<AnalysisProgress<'buf>> {
        let code_cave = disassemble_section(&ctx.instructions, ctx.text_bytes, ctx.entry_addr)?;
        Ok(AnalysisProgress::Disassembly(code_cave))
    }
}

/// A plugin that performs YARA scanning on strings in the binary.
/// Flags common indicator rules or obfuscated content strings.
pub(crate) struct StringCheckPlugin;

impl HeuristicPlugin for StringCheckPlugin {
    fn run<'buf, 'ctx>(
        &self,
        ctx: &AnalysisContext<'buf, 'ctx>,
    ) -> RbatResult<AnalysisProgress<'buf>> {
        let results = string_check(ctx.buffer, ctx.section_ranges)?;
        for matches in results.values() {
            for m in matches {
                for mat in ctx.needle.automaton.find_overlapping_iter(m.data.as_ref()) {
                    let pat_idx = mat.pattern().as_usize();
                    ctx.needle.present[pat_idx].store(true, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
        Ok(AnalysisProgress::Strings(results))
    }
}

/// A plugin that checks the binary's byte structures against packer, cryptor, or compiler signatures.
pub(crate) struct PackerSigCheckPlugin;

impl HeuristicPlugin for PackerSigCheckPlugin {
    fn run<'buf, 'ctx>(
        &self,
        ctx: &AnalysisContext<'buf, 'ctx>,
    ) -> RbatResult<AnalysisProgress<'buf>> {
        let results = packer_sig_check(ctx.buffer, ctx.section_ranges)?;
        Ok(AnalysisProgress::PackerSigs(results))
    }
}

/// A plugin for identifying library known functions within a binary.
pub(crate) struct LibraryFunctionsPlugin;

impl HeuristicPlugin for LibraryFunctionsPlugin {
    fn run<'buf, 'ctx>(
        &self,
        ctx: &AnalysisContext<'buf, 'ctx>,
    ) -> RbatResult<AnalysisProgress<'buf>> {
        let library_functions = ctx.custom_flirt.identify_library_functions(
            &ctx.entry_points,
            ctx.text_bytes,
            ctx.entry_addr,
        );
        Ok(AnalysisProgress::LibraryFunctions(library_functions))
    }
}

/// A plugin that computes entropy metrics across individual binary section ranges to detect packed, encrypted, or compressed payloads.
pub(crate) struct EntropyPlugin;

impl HeuristicPlugin for EntropyPlugin {
    fn run<'buf, 'ctx>(
        &self,
        ctx: &AnalysisContext<'buf, 'ctx>,
    ) -> RbatResult<AnalysisProgress<'buf>> {
        let parser = Parser::new(ctx.binary_object);
        let results = parser.evaluate_section_entropy()?;
        Ok(AnalysisProgress::Entropy(results))
    }
}

/// A plugin that extracts imported functions and symbols.
pub(crate) struct ImportsPlugin;

impl HeuristicPlugin for ImportsPlugin {
    fn run<'buf, 'ctx>(
        &self,
        ctx: &AnalysisContext<'buf, 'ctx>,
    ) -> RbatResult<AnalysisProgress<'buf>> {
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
pub(crate) struct ExportsPlugin;

impl HeuristicPlugin for ExportsPlugin {
    fn run<'buf, 'ctx>(
        &self,
        ctx: &AnalysisContext<'buf, 'ctx>,
    ) -> RbatResult<AnalysisProgress<'buf>> {
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
pub(crate) struct MetadataPlugin;

impl HeuristicPlugin for MetadataPlugin {
    fn run<'buf, 'ctx>(
        &self,
        ctx: &AnalysisContext<'buf, 'ctx>,
    ) -> RbatResult<AnalysisProgress<'buf>> {
        let results = BinaryMetadata::from_object(ctx.binary_object)?;
        Ok(AnalysisProgress::BinaryMetadata(results))
    }
}

/// A plugin that reconstructs the Control Flow Graph (CFG) from the disassembled binary section.
pub(crate) struct CfgPlugin;

impl HeuristicPlugin for CfgPlugin {
    fn run<'buf, 'ctx>(
        &self,
        ctx: &AnalysisContext<'buf, 'ctx>,
    ) -> RbatResult<AnalysisProgress<'buf>> {
        let cfg = crate::core::cfg::ControlFlowGraph::new(Arc::clone(&ctx.instructions), &ctx.arch);
        Ok(AnalysisProgress::CFG(cfg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{
        flirt::FlirtMatcher,
        needle::NeedleIndex,
        parser::{BinaryArch, BinaryOS},
        types::analysis::SectionRange,
    };
    use crate::utils::test_helpers;
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
        let section_ranges = SectionRange::build_map(&obj).unwrap();
        let entry_points = FlirtMatcher::collect_entry_points(&obj, &[], &BinaryArch::X64, 0x1000);

        let ctx = AnalysisContext {
            buffer: &buffer,
            binary_object: &obj,
            section_ranges: &section_ranges,
            os: BinaryOS::Linux,
            arch: BinaryArch::X64,
            text_bytes: &[],
            entry_addr: 0x1000,
            instructions: Arc::from([]),
            needle: std::sync::Arc::new(NeedleIndex::build_from_rules(&[])),
            entry_points,
            custom_flirt: &FlirtMatcher::load_embedded(),
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
        let section_ranges = SectionRange::build_map(&obj).unwrap();
        let entry_points = FlirtMatcher::collect_entry_points(&obj, &[], &BinaryArch::X64, 0x1000);

        let ctx = AnalysisContext {
            buffer: &buffer,
            binary_object: &obj,
            section_ranges: &section_ranges,
            os: BinaryOS::Linux,
            arch: BinaryArch::X64,
            text_bytes: &[],
            entry_addr: 0x1000,
            instructions: Arc::from([]),
            needle: std::sync::Arc::new(NeedleIndex::build_from_rules(&[])),
            entry_points,
            custom_flirt: &FlirtMatcher::load_embedded(),
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
        let section_ranges = SectionRange::build_map(&obj).unwrap();

        let text_bytes = vec![0x90; 128];
        let instructions = vec![
            crate::core::disassembler::InstructionInfo {
                address: 0x1000,
                mnemonic: "nop".into(),
                op_str: "".into(),
                api_resolution: None,
                matched: smallvec::SmallVec::new(),
                inst_class: Default::default(),
            };
            128
        ];

        let entry_points =
            FlirtMatcher::collect_entry_points(&obj, &instructions, &BinaryArch::X64, 0x1000);

        let ctx = AnalysisContext {
            buffer: &buffer,
            binary_object: &obj,
            section_ranges: &section_ranges,
            os: BinaryOS::Linux,
            arch: BinaryArch::X64,
            text_bytes: &text_bytes,
            entry_addr: 0x1000,
            instructions: instructions.into(),
            needle: std::sync::Arc::new(NeedleIndex::build_from_rules(&[])),
            entry_points,
            custom_flirt: &FlirtMatcher::load_embedded(),
        };

        let result = DisassemblyPlugin.run(&ctx).unwrap();
        match result {
            AnalysisProgress::Disassembly(code_cave) => {
                assert_eq!(code_cave.nop_sleds.len(), 128);
            }
            _ => panic!("Expected Disassembly progress"),
        }
    }
}
