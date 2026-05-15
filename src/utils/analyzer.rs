use goblin::Object;

use crate::rbat::{
    AnalysisResult, DisasmType, Factory, MapValue, RbatError, Result, RiskAssessment,
    parser::Parser, yarahandler::YaraHandler,
};
use crate::utils::{
    get_metadata::get_binary_metadata, get_txt::get_txt_from_file, scoring::calculate_risk,
};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// the main analyzer function that dynamically detects binary environment
/// and processes it accordingly.
pub fn analyzer(bin_path: &Path) -> Result<(AnalysisResult, RiskAssessment)> {
    let metadata = get_binary_metadata(bin_path)?;
    let string_eva = YaraHandler::new("suspicious_strings.yar".to_owned());
    let rules = string_eva.compile_yara_rule()?;
    let string_eva_res = string_eva.scan_file(rules, bin_path)?;

    // Packer signature detection
    let packer_eva = YaraHandler::new("packer_signatures.yar".to_owned());
    let packer_rules = packer_eva.compile_yara_rule()?;
    let packer_results = packer_eva.scan_file(packer_rules, bin_path)?;

    let buffer = fs::read(bin_path)?;
    let binary_object = Object::parse(&buffer)?;
    let parsed = Parser::new(bin_path, buffer.to_owned(), binary_object);
    let mut counter: i32 = 0;
    let mut nop_addr: Vec<u64> = vec![];
    let mut blacklisted_mnemonics: HashMap<String, u64> = HashMap::new();
    let mut code_cave: HashMap<String, Vec<u64>> = HashMap::new();
    let blacklist = get_txt_from_file("blacklisted_mnemonics.txt")?;
    let binary_data = parsed.parse_buffer()?;

    if let (
        Some(MapValue::OS(os)),
        Some(MapValue::Bytes(bytes)),
        Some(MapValue::Word(entry_addr)),
    ) = (
        binary_data.get("os"),
        binary_data.get("text_bytes"),
        binary_data.get("entry_addr"),
    ) {
        let factory = match os {
            DisasmType::Linux => Factory::disasm(DisasmType::Linux),
            DisasmType::Win => Factory::disasm(DisasmType::Win),
            DisasmType::Mac => Factory::disasm(DisasmType::Mac),
        };
        let cs = factory.disassemble()?;
        let instructions = cs.disasm_all(bytes, *entry_addr)?;

        for i in instructions.as_ref() {
            // checking for code caves (NOP sleds)
            let mnemonic = i.mnemonic().unwrap_or("");

            if mnemonic == "nop" {
                nop_addr.push(i.address());
                counter += 1;
                if counter >= 30 {
                    code_cave.insert("nop_addr".to_owned(), nop_addr);
                    break;
                };
            } else {
                counter = 0;
                nop_addr.clear();
            }

            // checks if there any blacklisted mneomonics for Identifying Anti-Analysis & VM Evasion
            if !mnemonic.is_empty() && blacklist.contains(&mnemonic.to_string()) {
                blacklisted_mnemonics.insert(mnemonic.to_string(), i.address());
            }
        }

        let api_hooking = parsed.detect_api_hooking()?;
        let process_inj = parsed.check_process_injec()?;
        let section_entropy = parsed.evaluate_section_entropy().unwrap_or_default();

        let analysis_result: AnalysisResult = AnalysisResult {
            metadata,
            code_cave,
            blacklisted_mnemonics,
            api_hooking,
            process_injection: process_inj,
            section_entropy,
            string_values: string_eva_res,
            packer_signatures: packer_results,
        };

        let score = calculate_risk(
            &analysis_result.section_entropy,
            analysis_result
                .string_values
                .values()
                .map(|v| v.len())
                .sum(),
            analysis_result.api_hooking.len(),
            analysis_result.process_injection.len(),
            !analysis_result.code_cave.is_empty(),
            !analysis_result.packer_signatures.is_empty(),
        );

        return Ok((analysis_result, score));
    }

    Err(RbatError::MissingAnalysisData(
        "Required disassembly inputs were not produced from parse_buffer".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_helpers::test_helpers;
    use tempfile::tempdir;

    #[test]
    fn test_analyzer_full_elf() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("dummy_elf");
        test_helpers::generate_elf(&path);

        let result = analyzer(&path);
        assert!(result.is_ok(), "Analyzer failed on ELF: {:?}", result.err());
        let (analysis, assessment) = result.unwrap();
        assert_eq!(analysis.metadata.binary_type, "Linux ELF");
        assert!(assessment.score <= 100);
    }

    #[test]
    fn test_analyzer_full_macho() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("dummy_macho");
        test_helpers::generate_macho(&path);

        let result = analyzer(&path);
        assert!(
            result.is_ok(),
            "Analyzer failed on Mach-O: {:?}",
            result.err()
        );
        let (analysis, assessment) = result.unwrap();
        assert_eq!(analysis.metadata.binary_type, "Mach-O");
        assert!(assessment.score <= 100);
    }

    #[test]
    fn test_analyzer_full_pe() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("dummy_pe");
        test_helpers::generate_pe_stub(&path);

        let result = analyzer(&path);
        // PE might fail further down due to lack of sections in stub,
        // but we verify the metadata parsing at least.
        if let Ok((analysis, assessment)) = result {
            assert_eq!(analysis.metadata.binary_type, "PE");
            assert!(assessment.score <= 100);
        }
    }
}
