//! # Binary Evasion and Padding Heuristics
//!
//! This module implements core static disassembly heuristics using the Capstone disassembler
//! to detect anti-analysis techniques, code caves, NOP sleds, and common signature matching rules.

use ahash::AHashMap;
use std::sync::OnceLock;

use crate::core::{
    disassembler::InstructionInfo,
    types::RbatResult,
    types::SectionRange,
    yarahandler::{YaraHandler, YaraMatches},
};

static SUSPICIOUS_STRINGS_RULES: OnceLock<yara::Rules> = OnceLock::new();
static PACKER_SIGNATURES_RULES: OnceLock<yara::Rules> = OnceLock::new();

/// Disassembles the executable section of a binary and scans for code caves and evasion mnemonics.
///
/// Code caves are identified as:
/// - Sequences of 128 or more consecutive `nop` instructions (returned as `"nop_addr"`).
/// - Runs of 128 or more consecutive `0x00` padding bytes (returned as `"null_addr"`).
/// - Runs of 128 or more consecutive `0xCC` trap/INT3 bytes (returned as `"int3_addr"`).
///
/// # Errors
/// Returns `RbatError::DisassemblerError` if Capstone initialization or disassembly fails.
pub fn disassemble_section<'buf>(
    instructions: &[InstructionInfo],
    bytes: &[u8],
    entry_addr: u64,
) -> RbatResult<AHashMap<&'buf str, Vec<u64>>> {
    let mut code_cave = AHashMap::new();
    let mut nop_addr: Vec<u64> = vec![];
    let mut counter: i32 = 0;

    let mut buf_m = String::new();
    for i in instructions {
        i.format_mnemonic_into(&mut buf_m);
        let mnemonic = buf_m.as_str();

        // Accumulate NOP sleds
        if mnemonic == "nop" {
            nop_addr.push(i.address());
            counter += 1;
        } else {
            if counter >= 128 {
                let mut existing: Vec<u64> = code_cave.remove("nop_addr").unwrap_or_default();
                existing.extend(&nop_addr);
                code_cave.insert("nop_addr", existing);
            }
            counter = 0;
            nop_addr.clear();
        }
    }

    if counter >= 128 {
        let mut existing = code_cave.remove("nop_addr").unwrap_or_default();
        existing.extend(&nop_addr);
        code_cave.insert("nop_addr", existing);
    }

    // Scan raw bytes for consecutive 0x00 runs, ignoring trailing alignment padding
    let mut null_scan_len = bytes.len();
    while null_scan_len > 0 && bytes[null_scan_len - 1] == 0x00 {
        null_scan_len -= 1;
    }
    let null_caves = scan_raw_padding(&bytes[..null_scan_len], 0x00, 128, entry_addr);
    if !null_caves.is_empty() {
        code_cave.insert("null_addr", null_caves);
    }

    // Scan raw bytes for consecutive 0xCC runs
    let int3_caves = scan_raw_padding(bytes, 0xCC, 128, entry_addr);
    if !int3_caves.is_empty() {
        code_cave.insert("int3_addr", int3_caves);
    }

    Ok(code_cave)
}

/// Helper function to perform YARA string detection.
///
/// # Errors
/// Returns `RbatError::Io` if reading the file fails, or `RbatError::ParseError` if object fails to parse the file format.
pub fn string_check<'buf>(
    buffer: &'buf [u8],
    section_ranges: &[SectionRange<'buf>],
) -> RbatResult<AHashMap<&'buf str, Vec<YaraMatches<'buf>>>> {
    let handler = YaraHandler::new("suspicious_strings.yar".to_owned());
    let rules = SUSPICIOUS_STRINGS_RULES.get_or_init(|| {
        handler
            .compile_yara_rule()
            .expect("Failed to compile embedded suspicious_strings.yar")
    });
    let results = handler.scan_mem(rules, buffer, section_ranges)?;
    Ok(results)
}

/// Helper function to check packer and compiler signatures.
///
/// # Errors
/// Returns `RbatError::Io` if reading the file fails, or `RbatError::ParseError` if object fails to parse the file format.
pub fn packer_sig_check<'buf>(
    buffer: &'buf [u8],
    section_ranges: &[SectionRange<'buf>],
) -> RbatResult<AHashMap<&'buf str, Vec<YaraMatches<'buf>>>> {
    let handler = YaraHandler::new("packer_signatures.yar".to_owned());
    let rules = PACKER_SIGNATURES_RULES.get_or_init(|| {
        handler
            .compile_yara_rule()
            .expect("Failed to compile embedded packer_signatures.yar")
    });
    let results = handler.scan_mem(rules, buffer, section_ranges)?;
    Ok(results)
}

/// Scans a byte slice for consecutive runs of `target_byte` of length at least `min_length`.
/// Returns the absolute virtual memory addresses of all bytes within the matching runs.
pub(crate) fn scan_raw_padding(
    bytes: &[u8],
    target_byte: u8,
    min_length: usize,
    text_section_offset: u64,
) -> Vec<u64> {
    let mut addresses = Vec::new();
    let mut start_idx = None;
    let mut count = 0;

    for (idx, &b) in bytes.iter().enumerate() {
        if b == target_byte {
            if start_idx.is_none() {
                start_idx = Some(idx);
            }
            count += 1;
        } else {
            if count >= min_length
                && let Some(start) = start_idx
            {
                for i in 0..count {
                    addresses.push(text_section_offset + (start + i) as u64);
                }
            }
            start_idx = None;
            count = 0;
        }
    }

    if count >= min_length
        && let Some(start) = start_idx
    {
        for i in 0..count {
            addresses.push(text_section_offset + (start + i) as u64);
        }
    }
    addresses
}

#[cfg(all(test, feature = "backend-capstone"))]
mod tests {
    use super::*;

    #[test]
    fn test_scan_raw_padding_nulls() {
        let mut bytes = vec![0x90; 100];
        bytes[40..70].fill(0x00);

        let results = scan_raw_padding(&bytes, 0x00, 30, 0x1000);
        assert_eq!(results.len(), 30);
        assert_eq!(results[0], 0x1000 + 40);
        assert_eq!(results[29], 0x1000 + 69);
    }

    #[test]
    fn test_scan_raw_padding_int3() {
        let mut bytes = vec![0x90; 100];
        bytes[20..55].fill(0xCC);

        let results = scan_raw_padding(&bytes, 0xCC, 30, 0x1000);
        assert_eq!(results.len(), 35);
        assert_eq!(results[0], 0x1000 + 20);
        assert_eq!(results[34], 0x1000 + 54);
    }

    #[test]
    fn test_disassemble_section_no_early_breakout() {
        let mut instructions = Vec::new();
        for addr in 0x1000..0x1080 {
            instructions.push(InstructionInfo {
                address: addr as u64,
                mnemonic: "nop".into(),
                op_str: "".into(),
                api_resolution: None,
                matched: smallvec::SmallVec::new(),
                inst_class: Default::default(),
            });
        }
        instructions.push(InstructionInfo {
            address: 0x1080,
            mnemonic: "rdtsc".into(),
            op_str: "".into(),
            api_resolution: None,
            matched: smallvec::SmallVec::new(),
            inst_class: Default::default(),
        });

        let code_cave = disassemble_section(&instructions, &[], 0x1000).unwrap();

        assert!(code_cave.contains_key("nop_addr"));
        assert_eq!(code_cave.get("nop_addr").unwrap().len(), 128);
    }
}
