//! # Binary Evasion and Padding Heuristics
//!
//! This module implements core static analysis heuristics using pre-disassembled instruction
//! streams to detect anti-analysis techniques, code caves, NOP sleds, and common signature
//! matching rules.

use ahash::AHashMap;
use std::sync::OnceLock;

use crate::core::{
    disassembler::InstructionInfo,
    types::{
        analysis::{CodeCaves, SectionRange},
        result::RbatResult,
    },
    yarahandler::{YaraHandler, YaraMatches},
};

static SUSPICIOUS_STRINGS_RULES: OnceLock<yara::Rules> = OnceLock::new();
static PACKER_SIGNATURES_RULES: OnceLock<yara::Rules> = OnceLock::new();

/// Scans pre-disassembled instructions and raw bytes for code caves and evasion mnemonics.
///
/// Code caves are identified as:
/// - Sequences of 128 or more consecutive `nop` instructions.
/// - Runs of 128 or more consecutive `0x00` padding bytes.
/// - Runs of 128 or more consecutive `0xCC` trap/INT3 bytes.
pub(crate) fn disassemble_section(
    instructions: &[InstructionInfo],
    bytes: &[u8],
    entry_addr: u64,
) -> RbatResult<CodeCaves> {
    let mut code_caves = CodeCaves::default();
    let mut nop_run: Vec<u64> = vec![];

    let mut buf_m = String::new();
    for i in instructions {
        i.format_mnemonic_into(&mut buf_m);
        let mnemonic = buf_m.as_str();

        // Accumulate NOP sleds
        if mnemonic == "nop" {
            nop_run.push(i.address());
        } else {
            if nop_run.len() >= 128 {
                code_caves.nop_sleds.extend(&nop_run);
            }
            nop_run.clear();
        }
    }

    if nop_run.len() >= 128 {
        code_caves.nop_sleds.extend(&nop_run);
    }

    // Scan raw bytes for consecutive 0x00 runs, ignoring trailing alignment padding
    let mut null_scan_len = bytes.len();
    while null_scan_len > 0 && bytes[null_scan_len - 1] == 0x00 {
        null_scan_len -= 1;
    }
    code_caves.null_padding = scan_raw_padding(&bytes[..null_scan_len], 0x00, 128, entry_addr);

    // Scan raw bytes for consecutive 0xCC runs
    code_caves.trap_padding = scan_raw_padding(bytes, 0xCC, 128, entry_addr);

    Ok(code_caves)
}

/// Performs YARA string detection against binary section data.
///
/// # Errors
/// Returns `RbatError::YaraCompileError` if the embedded rule fails to compile,
/// or `RbatError::YaraIO` if the scan engine encounters a runtime error.
pub(crate) fn string_check<'buf>(
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

/// Checks the binary against packer and compiler signature rules.
///
/// # Errors
/// Returns `RbatError::YaraCompileError` if the embedded rule fails to compile,
/// or `RbatError::YaraIO` if the scan engine encounters a runtime error.
pub(crate) fn packer_sig_check<'buf>(
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

#[cfg(test)]
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
        assert_eq!(code_cave.nop_sleds.len(), 128);
    }
}
