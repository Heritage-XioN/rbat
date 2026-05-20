use std::collections::HashMap;
use std::path::Path;

use crate::core::{BinaryArch, BinaryOS, Factory, Result, YaraMatches, yarahandler::YaraHandler};

use crate::utils::get_txt::get_txt_from_file;

pub fn disassemble_section(
    bytes: &[u8],
    entry_addr: &u64,
    os: &BinaryOS,
    arch: &BinaryArch,
) -> Result<(HashMap<String, Vec<u64>>, HashMap<String, u64>)> {
    let mut code_cave: HashMap<String, Vec<u64>> = HashMap::new();
    let mut nop_addr: Vec<u64> = vec![];
    let mut counter: i32 = 0;

    let mut blacklisted_mnemonics: HashMap<String, u64> = HashMap::new();
    let blacklist = get_txt_from_file("blacklisted_mnemonics.txt")?;

    let factory = Factory::disasm(*os, *arch);
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
    Ok((code_cave, blacklisted_mnemonics))
}

pub fn string_check(bin_path: &Path) -> Result<HashMap<String, Vec<YaraMatches>>> {
    let string_check = YaraHandler::new("suspicious_strings.yar".to_owned());
    let rules = string_check.compile_yara_rule()?;
    let string_check_result = string_check.scan_file(rules, bin_path)?;
    Ok(string_check_result)
}

pub fn packer_sig_check(bin_path: &Path) -> Result<HashMap<String, Vec<YaraMatches>>> {
    let packer_check = YaraHandler::new("packer_signatures.yar".to_owned());
    let packer_rules = packer_check.compile_yara_rule()?;
    let packer_results = packer_check.scan_file(packer_rules, bin_path)?;
    Ok(packer_results)
}
