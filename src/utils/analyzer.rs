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

    // returnables
    let mut counter: i32 = 0;
    let mut nop_addr: Vec<u64> = vec![];
    let mut blacklisted_mnemonics: HashMap<&str, u64> = HashMap::new();

    // TODO: use a txt file to store blacklist data
    let blacklist: [&str; 3] = ["rdtsc", "cpuid", "int3"];

    println!("program starts here");

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
                    println!(
                        "surpassed {} threshold \n first mem addr 0x{:x}, last mem addr 0x{:x} ",
                        counter,
                        nop_addr.first().unwrap(),
                        nop_addr.last().unwrap()
                    );
                    break;
                };
            } else {
                counter = 0;
                nop_addr.clear();
            }

            // checks if there any blacklisted mneomonics for Identifying Anti-Analysis & VM Evasion
            if blacklist.contains(&i.mnemonic().unwrap()) {
                blacklisted_mnemonics.insert(i.mnemonic().unwrap(), i.address());
                // print!(
                //     "found blacklisted mnemonic: {} at mem addr: {:x}",
                //     i.mnemonic().unwrap(),
                //     i.address()
                // );
            }

            // println!(
            //     "0x{:x}:\t{}\t{}",
            //     i.address(),
            //     i.mnemonic().unwrap_or(""),
            //     i.op_str().unwrap_or("")
            // );
        }

        buffer.detect_api_hooking();
        // checks for sus functions injection
        let sus_function = buffer.check_process_injec();
        println!("Entropy of random data: {:.2}", calculate_entropy(bytes));
        string_eva.scan_file(rules, file_path);
    }

    Ok(())
}
