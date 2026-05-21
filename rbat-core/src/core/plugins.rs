use crate::core::heuristics::disassemble_section;
use crate::core::traits::HeuristicPlugin;
use crate::core::yarahandler::YaraHandler;
use crate::core::{AnalysisContext, AnalysisProgress, Result, parser::Parser};
use crate::utils::get_metadata::get_binary_metadata;

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

pub struct StringCheckPlugin;
impl HeuristicPlugin for StringCheckPlugin {
    fn name(&self) -> &'static str {
        "string_check"
    }

    fn run(&self, ctx: &AnalysisContext) -> Result<AnalysisProgress> {
        let handler = YaraHandler::new("suspicious_strings.yar".to_owned());
        let rules = handler.compile_yara_rule()?;
        let results = handler.scan_mem(&rules, ctx.buffer, ctx.section_ranges)?;
        Ok(AnalysisProgress::Strings(results))
    }
}

pub struct PackerSigCheckPlugin;
impl HeuristicPlugin for PackerSigCheckPlugin {
    fn name(&self) -> &'static str {
        "packer_sig_check"
    }

    fn run(&self, ctx: &AnalysisContext) -> Result<AnalysisProgress> {
        let handler = YaraHandler::new("packer_signatures.yar".to_owned());
        let rules = handler.compile_yara_rule()?;
        let results = handler.scan_mem(&rules, ctx.buffer, ctx.section_ranges)?;
        Ok(AnalysisProgress::PackerSigs(results))
    }
}

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
    use crate::core::{BinaryOS, BinaryArch};
    use crate::utils::test_helpers::test_helpers;
    use tempfile::tempdir;
    use std::fs;
    use goblin::Object;

    #[test]
    fn test_metadata_plugin() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("mock_elf");
        test_helpers::generate_elf(&path);

        let buffer = fs::read(&path).unwrap();
        let obj = Object::parse(&buffer).unwrap();
        let section_ranges = crate::utils::section_offset::build_section_map(&obj, &buffer).unwrap();

        let ctx = AnalysisContext {
            path: &path,
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
        let section_ranges = crate::utils::section_offset::build_section_map(&obj, &buffer).unwrap();

        let ctx = AnalysisContext {
            path: &path,
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
        let section_ranges = crate::utils::section_offset::build_section_map(&obj, &buffer).unwrap();

        let text_bytes = vec![0x90; 30];

        let ctx = AnalysisContext {
            path: &path,
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
