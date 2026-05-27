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
//! use goblin::Object;
//! use rbat::core::{AnalysisContext, BinaryArch, BinaryOS, AnalysisProgress};
//! use rbat::core::plugins::MetadataPlugin;
//! use rbat::core::traits::HeuristicPlugin;
//!
//! # fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let path = Path::new("test_elf");
//! let buffer = vec![0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 62, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 56, 0, 1, 0, 64, 0, 0, 0, 0, 0];
//! let obj = Object::parse(&buffer)?;
//! let section_ranges = vec![];
//!
//! let ctx = AnalysisContext {
//!     path: &path,
//!     buffer: &buffer,
//!     binary_object: &obj,
//!     section_ranges: &section_ranges,
//!     os: BinaryOS::Linux,
//!     arch: BinaryArch::X64,
//!     text_bytes: &buffer,
//!     entry_addr: 0x1000,
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

/// A plugin that performs instruction disassembly using Capstone.
/// Detects code caves (NOP runs, zero/trap padding runs) and anti-analysis/evasion instruction mnemonics.
pub struct DisassemblyPlugin;

impl HeuristicPlugin for DisassemblyPlugin {
    fn name(&self) -> &'static str {
        "disassembly"
    }

    fn run(&self, ctx: &AnalysisContext) -> Result<AnalysisProgress> {
        let (code_cave, blacklisted_mnemonics) =
            disassemble_section(ctx.text_bytes, &ctx.entry_addr, &ctx.os, &ctx.arch)?;
        Ok(AnalysisProgress::Disassembly((
            code_cave,
            blacklisted_mnemonics,
        )))
    }
}

/// A plugin that performs YARA scanning on strings in the binary.
/// Flags common indicator rules or obfuscated content strings.
pub struct StringCheckPlugin;

impl HeuristicPlugin for StringCheckPlugin {
    fn name(&self) -> &'static str {
        "string_check"
    }

    fn run(&self, ctx: &AnalysisContext) -> Result<AnalysisProgress> {
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

    fn run(&self, ctx: &AnalysisContext) -> Result<AnalysisProgress> {
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

    fn run(&self, ctx: &AnalysisContext) -> Result<AnalysisProgress> {
        let parser = Parser::new(ctx.buffer, ctx.binary_object);
        let results = parser.evaluate_section_entropy()?;
        Ok(AnalysisProgress::Entropy(results))
    }
}

/// A plugin that checks imported functions and symbols to identify potential API hooking or function redirection logic.
pub struct ApiHookingPlugin;

impl HeuristicPlugin for ApiHookingPlugin {
    fn name(&self) -> &'static str {
        "api_hooking"
    }

    fn run(&self, ctx: &AnalysisContext) -> Result<AnalysisProgress> {
        let parser = Parser::new(ctx.buffer, ctx.binary_object);
        let results = parser.detect_api_hooking(ctx.section_ranges)?;
        Ok(AnalysisProgress::ApiHooking(results))
    }
}

/// A plugin that analyzes imported library symbols to detect common API patterns indicative of process injection or hollow injection.
pub struct ProcessInjectionPlugin;

impl HeuristicPlugin for ProcessInjectionPlugin {
    fn name(&self) -> &'static str {
        "process_injection"
    }

    fn run(&self, ctx: &AnalysisContext) -> Result<AnalysisProgress> {
        let parser = Parser::new(ctx.buffer, ctx.binary_object);
        let results = parser.check_process_injec()?;
        Ok(AnalysisProgress::ProcessInjection(results))
    }
}

/// A plugin that extracts basic format metadata from binary headers (e.g. entry points, machine CPU, type strings).
pub struct MetadataPlugin;

impl HeuristicPlugin for MetadataPlugin {
    fn name(&self) -> &'static str {
        "metadata"
    }

    fn run(&self, ctx: &AnalysisContext) -> Result<AnalysisProgress> {
        let results = get_binary_metadata(ctx.binary_object)?;
        Ok(AnalysisProgress::BinaryMetadata(results))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{BinaryArch, BinaryOS};
    use crate::utils::test_helpers::test_helpers;
    use goblin::Object;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_metadata_plugin() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("mock_elf");
        test_helpers::generate_elf(&path);

        let buffer = fs::read(&path).unwrap();
        let obj = Object::parse(&buffer).unwrap();
        let section_ranges =
            crate::utils::section_offset::build_section_map(&obj, &buffer).unwrap();

        let ctx = AnalysisContext {
            buffer: &buffer,
            binary_object: &obj,
            section_ranges: &section_ranges,
            os: BinaryOS::Linux,
            arch: BinaryArch::X64,
            text_bytes: &[],
            entry_addr: 0x1000,
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
        let obj = Object::parse(&buffer).unwrap();
        let section_ranges =
            crate::utils::section_offset::build_section_map(&obj, &buffer).unwrap();

        let ctx = AnalysisContext {
            buffer: &buffer,
            binary_object: &obj,
            section_ranges: &section_ranges,
            os: BinaryOS::Linux,
            arch: BinaryArch::X64,
            text_bytes: &[],
            entry_addr: 0x1000,
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
        let obj = Object::parse(&buffer).unwrap();
        let section_ranges =
            crate::utils::section_offset::build_section_map(&obj, &buffer).unwrap();

        let text_bytes = vec![0x90; 30];

        let ctx = AnalysisContext {
            buffer: &buffer,
            binary_object: &obj,
            section_ranges: &section_ranges,
            os: BinaryOS::Linux,
            arch: BinaryArch::X64,
            text_bytes: &text_bytes,
            entry_addr: 0x1000,
        };

        let result = DisassemblyPlugin.run(&ctx).unwrap();
        match result {
            AnalysisProgress::Disassembly((code_cave, _)) => {
                assert!(code_cave.contains_key("nop_addr"));
            }
            _ => panic!("Expected Disassembly progress"),
        }
    }
}
