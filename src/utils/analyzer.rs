use std::collections::HashMap;

use crate::prelude::*;
use crate::types::DisasmType;
use crate::types::MapValue;
use crate::utils::entropy::calculate_entropy;
use capstone::Instructions;

/// the main analyzer function that dynamically detects binary environment
/// and processes it accordingly.
pub fn analyzer(file_path: &str) -> Result<()> {
    let buffer = Parser::new(file_path.to_owned());
    let string_eva = YaraHandler::new("suspicious_strings.yar".to_owned());
    let rules = string_eva.compile_yara_rule();

    let mut counter: i32 = 0;
    let mut nop_addr: Vec<u64> = vec![];
    let mut blacklisted_mnemonics: HashMap<String, u64> = HashMap::new();
    let mut code_cave: HashMap<String, Vec<u64>> = HashMap::new();

    // TODO: use a txt file to store blacklist data
    let blacklist: [&str; 3] = ["rdtsc", "cpuid", "int3"];

    let binary_data = match buffer.parse_buffer() {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error parsing: {}", e);
            return Ok(());
        }
    };

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
            DisasmType::LinuxDisam => Factory::disasm(DisasmType::LinuxDisam),
            DisasmType::WinDisasm => Factory::disasm(DisasmType::WinDisasm),
            DisasmType::MacDisasm => Factory::disasm(DisasmType::MacDisasm),
        };
        let cs = factory.disassemble().unwrap();
        let instructions = cs.disasm_all(bytes, *entry_addr)?;

        println!("disassembled data: {:#?}", instructions.len());

        for i in instructions.as_ref() {
            // checking for code caves (NOP sleds)
            if i.mnemonic().unwrap_or("") == "nop" {
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
            if blacklist.contains(&i.mnemonic().unwrap()) {
                blacklisted_mnemonics.insert(i.mnemonic().unwrap().to_string(), i.address());
            }
        }

        // returnables
        let api_hooking = buffer.detect_api_hooking()?;
        let process_inj = buffer.check_process_injec()?;
        let string_eva_res = string_eva.scan_file(rules, file_path)?;

        let analysis_result: AnalysisResult = AnalysisResult {
            code_cave: code_cave,
            blacklisted_mnemonics: blacklisted_mnemonics,
            api_hooking: api_hooking,
            process_injection: process_inj,
            entropy: calculate_entropy(bytes),
            string_values: string_eva_res,
        };

        let json_value = serde_json::to_value(&analysis_result)?;

        println!("analysis data: {:#?}", json_value);
    }

    Ok(())
}
