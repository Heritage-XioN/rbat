use std::collections::HashMap;
use std::path::Path;

use crate::core::{BinaryArch, BinaryOS, Factory, Result, YaraMatches, yarahandler::YaraHandler};
use crate::utils::get_txt::get_txt_from_file;
use crate::utils::raw_padding::scan_raw_padding;

type CodeCave = HashMap<String, Vec<u64>>;
type BlacklistedMnemonics = HashMap<String, u64>;

pub fn disassemble_section(
    bytes: &[u8],
    entry_addr: &u64,
    os: &BinaryOS,
    arch: &BinaryArch,
) -> Result<(CodeCave, BlacklistedMnemonics)> {
    let mut code_cave: CodeCave = HashMap::new();
    let mut nop_addr: Vec<u64> = vec![];
    let mut counter: i32 = 0;

    let mut blacklisted_mnemonics: BlacklistedMnemonics = HashMap::new();
    let blacklist = get_txt_from_file("blacklisted_mnemonics.txt")?;

    let factory = Factory::disasm(*os, *arch);
    let cs = factory.disassemble()?;
    let instructions = cs.disasm_all(bytes, *entry_addr)?;

    for i in instructions.as_ref() {
        let mnemonic = i.mnemonic().unwrap_or("");

        // Accumulate NOP sleds
        if mnemonic == "nop" {
            nop_addr.push(i.address());
            counter += 1;
        } else {
            if counter >= 30 {
                let mut existing = code_cave.remove("nop_addr").unwrap_or_default();
                existing.extend(&nop_addr);
                code_cave.insert("nop_addr".to_owned(), existing);
            }
            counter = 0;
            nop_addr.clear();
        }

        // Checks for anti-VM / anti-debugging mnemonics
        if !mnemonic.is_empty() && blacklist.contains(&mnemonic.to_string()) {
            blacklisted_mnemonics.insert(mnemonic.to_string(), i.address());
        }
    }

    // Capture a NOP sled at the end of instructions
    if counter >= 30 {
        let mut existing = code_cave.remove("nop_addr").unwrap_or_default();
        existing.extend(&nop_addr);
        code_cave.insert("nop_addr".to_owned(), existing);
    }

    // Scan raw bytes for consecutive 0x00 runs
    let null_caves = scan_raw_padding(bytes, 0x00, 30, *entry_addr);
    if !null_caves.is_empty() {
        code_cave.insert("null_addr".to_owned(), null_caves);
    }

    // Scan raw bytes for consecutive 0xCC runs
    let int3_caves = scan_raw_padding(bytes, 0xCC, 30, *entry_addr);
    if !int3_caves.is_empty() {
        code_cave.insert("int3_addr".to_owned(), int3_caves);
    }

    Ok((code_cave, blacklisted_mnemonics))
}

pub fn string_check(bin_path: &Path) -> Result<HashMap<String, Vec<YaraMatches>>> {
    let buffer = std::fs::read(bin_path)?;
    let binary_object = goblin::Object::parse(&buffer)?;
    let section_ranges = crate::utils::section_offset::build_section_map(&binary_object, &buffer)?;
    let string_check = YaraHandler::new("suspicious_strings.yar".to_owned());
    let rules = string_check.compile_yara_rule()?;
    let string_check_result = string_check.scan_mem(&rules, &buffer, &section_ranges)?;
    Ok(string_check_result)
}

pub fn packer_sig_check(bin_path: &Path) -> Result<HashMap<String, Vec<YaraMatches>>> {
    let buffer = std::fs::read(bin_path)?;
    let binary_object = goblin::Object::parse(&buffer)?;
    let section_ranges = crate::utils::section_offset::build_section_map(&binary_object, &buffer)?;
    let packer_check = YaraHandler::new("packer_signatures.yar".to_owned());
    let packer_rules = packer_check.compile_yara_rule()?;
    let packer_results = packer_check.scan_mem(&packer_rules, &buffer, &section_ranges)?;
    Ok(packer_results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_raw_padding_nulls() {
        let mut bytes = vec![0x90; 100];
        for idx in 40..70 {
            bytes[idx] = 0x00;
        }

        let results = scan_raw_padding(&bytes, 0x00, 30, 0x1000);
        assert_eq!(results.len(), 30);
        assert_eq!(results[0], 0x1000 + 40);
        assert_eq!(results[29], 0x1000 + 69);
    }

    #[test]
    fn test_scan_raw_padding_int3() {
        let mut bytes = vec![0x90; 100];
        for idx in 20..55 {
            bytes[idx] = 0xCC;
        }

        let results = scan_raw_padding(&bytes, 0xCC, 30, 0x1000);
        assert_eq!(results.len(), 35);
        assert_eq!(results[0], 0x1000 + 20);
        assert_eq!(results[34], 0x1000 + 54);
    }

    #[test]
    fn test_disassemble_section_no_early_breakout() {
        let mut bytes = vec![0x90; 30];
        bytes.push(0x0F);
        bytes.push(0x31);

        let (code_cave, blacklisted) =
            disassemble_section(&bytes, &0x1000, &BinaryOS::Linux, &BinaryArch::X64).unwrap();

        assert!(code_cave.contains_key("nop_addr"));
        assert_eq!(code_cave.get("nop_addr").unwrap().len(), 30);

        assert!(blacklisted.contains_key("rdtsc"));
        assert_eq!(blacklisted.get("rdtsc"), Some(&0x101E));
    }
}
