//! # Binary Evasion and Padding Heuristics
//!
//! This module implements core static disassembly heuristics using the Capstone disassembler
//! to detect anti-analysis techniques, code caves, NOP sleds, and common signature matching rules.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use crate::core::SectionRange;
use crate::core::{BinaryArch, BinaryOS, Factory, Result, YaraMatches, yarahandler::YaraHandler};
use crate::utils::raw_padding::scan_raw_padding;

static SUSPICIOUS_STRINGS_RULES: OnceLock<yara::Rules> = OnceLock::new();
static PACKER_SIGNATURES_RULES: OnceLock<yara::Rules> = OnceLock::new();
static BLACKLISTED_MNEMONICS: OnceLock<HashSet<String>> = OnceLock::new();

type CodeCave = HashMap<String, Vec<u64>>;
type BlacklistedMnemonics = HashMap<String, Vec<u64>>;

/// Disassembles the executable section of a binary and scans for code caves and evasion mnemonics.
///
/// Code caves are identified as:
/// - Sequences of 128 or more consecutive `nop` instructions (returned as `"nop_addr"`).
/// - Runs of 128 or more consecutive `0x00` padding bytes (returned as `"null_addr"`).
/// - Runs of 128 or more consecutive `0xCC` trap/INT3 bytes (returned as `"int3_addr"`).
///
/// Also flags anti-VM or anti-debugging instructions present in the `blacklisted_mnemonics.txt` asset.
///
/// # Errors
/// Returns `RbatError::DisassemblerError` if Capstone initialization or disassembly fails.
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
    let blacklist = if let Some(bl) = BLACKLISTED_MNEMONICS.get() {
        bl
    } else {
        let set: HashSet<String> = ["rdtsc", "int1", "rdpmc", "sidt", "sldt", "sgdt", "smsw"]
            .iter()
            .map(|&s| s.to_string())
            .collect();
        let _ = BLACKLISTED_MNEMONICS.set(set);
        BLACKLISTED_MNEMONICS.get().unwrap()
    };

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
            if counter >= 128 {
                let mut existing = code_cave.remove("nop_addr").unwrap_or_default();
                existing.extend(&nop_addr);
                code_cave.insert("nop_addr".to_owned(), existing);
            }
            counter = 0;
            nop_addr.clear();
        }

        // Checks for anti-VM / anti-debugging mnemonics
        if !mnemonic.is_empty() && blacklist.contains(mnemonic) {
            blacklisted_mnemonics
                .entry(mnemonic.to_string())
                .or_default()
                .push(i.address());
        }
    }

    // Capture a NOP sled at the end of instructions
    if counter >= 128 {
        let mut existing = code_cave.remove("nop_addr").unwrap_or_default();
        existing.extend(&nop_addr);
        code_cave.insert("nop_addr".to_owned(), existing);
    }

    // Scan raw bytes for consecutive 0x00 runs, ignoring trailing alignment padding
    let mut null_scan_len = bytes.len();
    while null_scan_len > 0 && bytes[null_scan_len - 1] == 0x00 {
        null_scan_len -= 1;
    }
    let null_caves = scan_raw_padding(&bytes[..null_scan_len], 0x00, 128, *entry_addr);
    if !null_caves.is_empty() {
        code_cave.insert("null_addr".to_owned(), null_caves);
    }

    // Scan raw bytes for consecutive 0xCC runs
    let int3_caves = scan_raw_padding(bytes, 0xCC, 128, *entry_addr);
    if !int3_caves.is_empty() {
        code_cave.insert("int3_addr".to_owned(), int3_caves);
    }

    Ok((code_cave, blacklisted_mnemonics))
}

/// Helper function to perform YARA string detection.
///
/// # Errors
/// Returns `RbatError::Io` if reading the file fails, or `RbatError::ParseError` if goblin fails to parse the file format.
pub fn string_check(
    buffer: &[u8],
    section_ranges: &[SectionRange],
) -> Result<HashMap<String, Vec<YaraMatches>>> {
    let rules = if let Some(rules) = SUSPICIOUS_STRINGS_RULES.get() {
        rules
    } else {
        let handler = YaraHandler::new("yara/suspicious_strings.yar".to_owned());
        let rules = handler.compile_yara_rule()?;
        let _ = SUSPICIOUS_STRINGS_RULES.set(rules);
        SUSPICIOUS_STRINGS_RULES.get().unwrap()
    };
    let handler = YaraHandler::new("yara/suspicious_strings.yar".to_owned());
    let results = handler.scan_mem(rules, buffer, section_ranges)?;
    Ok(results)
}

/// Helper function to check packer and compiler signatures.
///
/// # Errors
/// Returns `RbatError::Io` if reading the file fails, or `RbatError::ParseError` if goblin fails to parse the file format.
pub fn packer_sig_check(
    buffer: &[u8],
    section_ranges: &[SectionRange],
) -> Result<HashMap<String, Vec<YaraMatches>>> {
    let rules = if let Some(rules) = PACKER_SIGNATURES_RULES.get() {
        rules
    } else {
        let handler = YaraHandler::new("yara/packer_signatures.yar".to_owned());
        let rules = handler.compile_yara_rule()?;
        let _ = PACKER_SIGNATURES_RULES.set(rules);
        PACKER_SIGNATURES_RULES.get().unwrap()
    };
    let handler = YaraHandler::new("yara/packer_signatures.yar".to_owned());
    let results = handler.scan_mem(rules, buffer, section_ranges)?;
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disassemble_section_no_early_breakout() {
        let mut bytes = vec![0x90; 128];
        bytes.push(0x0F);
        bytes.push(0x31);

        let (code_cave, blacklisted) =
            disassemble_section(&bytes, &0x1000, &BinaryOS::Linux, &BinaryArch::X64).unwrap();

        assert!(code_cave.contains_key("nop_addr"));
        assert_eq!(code_cave.get("nop_addr").unwrap().len(), 128);

        assert!(blacklisted.contains_key("rdtsc"));
        assert_eq!(blacklisted.get("rdtsc"), Some(&vec![0x1080]));
    }
}
