use crate::prelude::*;
use crate::types::DisasmType;
use crate::types::MapValue;
use crate::utils::entropy::calculate_entropy;
use crate::utils::get_metadata::get_binary_metadata;
use crate::utils::get_txt::get_txt_from_file;
use crate::utils::scoring::calculate_risk;
use std::collections::HashMap;
use std::path::PathBuf;

/// the main analyzer function that dynamically detects binary environment
/// and processes it accordingly.
pub fn analyzer(file_path: &PathBuf) -> Result<(AnalysisResult, RiskAssessment)> {
    let metadata = get_binary_metadata(&file_path)?;
    let string_eva = YaraHandler::new("suspicious_strings.yar".to_owned());
    let rules = string_eva.compile_yara_rule()?;
    let string_eva_res = string_eva.scan_file(rules, &file_path)?;

    // Packer signature detection
    let packer_eva = YaraHandler::new("packer_signatures.yar".to_owned());
    let packer_rules = packer_eva.compile_yara_rule()?;
    let packer_results = packer_eva.scan_file(packer_rules, &file_path)?;

    let buffer = Parser::new(file_path);
    let mut counter: i32 = 0;
    let mut nop_addr: Vec<u64> = vec![];
    let mut blacklisted_mnemonics: HashMap<String, u64> = HashMap::new();
    let mut code_cave: HashMap<String, Vec<u64>> = HashMap::new();
    let blacklist = get_txt_from_file("blacklisted_mnemonics.txt")?;
    let binary_data = buffer.parse_buffer()?;

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
            DisasmType::LinuxDisasm => Factory::disasm(DisasmType::LinuxDisasm),
            DisasmType::WinDisasm => Factory::disasm(DisasmType::WinDisasm),
            DisasmType::MacDisasm => Factory::disasm(DisasmType::MacDisasm),
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

        let api_hooking = buffer.detect_api_hooking()?;
        let process_inj = buffer.check_process_injec()?;

        let analysis_result: AnalysisResult = AnalysisResult {
            metadata,
            code_cave,
            blacklisted_mnemonics,
            api_hooking,
            process_injection: process_inj,
            entropy: calculate_entropy(bytes),
            string_values: string_eva_res,
            packer_signatures: packer_results,
        };

        let score = calculate_risk(
            analysis_result.entropy,
            !analysis_result.string_values.is_empty(),
            !analysis_result.api_hooking.is_empty(),
            !analysis_result.code_cave.is_empty(),
            !analysis_result.packer_signatures.is_empty(),
        );

        return Ok((analysis_result, score));
    }

    Err(RbatError::MissingAnalysisData(
        "Required disassembly inputs were not produced from parse_buffer".to_string(),
    ))
}
