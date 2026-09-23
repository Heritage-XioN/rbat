//! FLIRT signature helper functions.
//!
//! Contains utilities for FLIRT (Fast Library Identification and Recognition Technology)
//! symbol resolution, function entry point extraction, and demangling.

use crate::core::{disassembler::InstructionInfo, types::InstructionClass};
use object::{Object, ObjectSymbol};
use rustc_hash::FxHashSet;

/// Discovers potential function entry points from symbols, exports, and call destinations.
pub fn collect_function_entry_points(
    binary_object: &object::File,
    instructions: &[InstructionInfo],
    arch: &crate::core::BinaryArch,
    entry_addr: u64,
) -> FxHashSet<u64> {
    let mut entry_points = FxHashSet::default();
    entry_points.insert(entry_addr);

    // Collect from call instructions
    for insn in instructions {
        if insn.class(arch) == InstructionClass::Call
            && let Some(target) = insn.branch_target()
        {
            entry_points.insert(target);
        }
    }

    for sym in binary_object.symbols() {
        if sym.address() > 0 && sym.kind() == object::SymbolKind::Text {
            entry_points.insert(sym.address());
        }
    }
    for sym in binary_object.dynamic_symbols() {
        if sym.address() > 0 && sym.kind() == object::SymbolKind::Text {
            entry_points.insert(sym.address());
        }
    }
    if let Ok(exports) = binary_object.exports() {
        for export in exports {
            if export.address() > 0 {
                entry_points.insert(export.address());
            }
        }
    }

    entry_points
}

/// Traces execution from a start address to find the semantic end address of a function.
/// It stops scanning when it encounters a return instruction or the start of another function.
pub fn find_function_range(
    start_addr: u64,
    instructions: &[InstructionInfo],
    all_entry_points: &FxHashSet<u64>,
    arch: &crate::core::BinaryArch,
) -> (u64, u64) {
    let start_idx = match instructions.binary_search_by_key(&start_addr, |insn| insn.address()) {
        Ok(idx) => idx,
        Err(_) => {
            return (start_addr, start_addr);
        }
    };

    let mut end_addr = start_addr;
    for insn in instructions.iter().skip(start_idx) {
        if insn.address() != start_addr && all_entry_points.contains(&insn.address()) {
            break;
        }

        end_addr = insn.address();

        if insn.class(arch) == InstructionClass::Return {
            break;
        }
    }

    (start_addr, end_addr)
}

/// Normalizes and demangles symbol names returned by the FLIRT engine.
pub fn normalize_symbol(name: &str) -> String {
    let mut name = name.to_owned();

    // 1. Demangle MSVC C++ symbols (start with '?')
    if name.starts_with('?') {
        if let Ok(demangled) =
            msvc_demangler::demangle(&name, msvc_demangler::DemangleFlags::llvm())
        {
            name = demangled;
        }
    }
    // 2. Demangle GCC/Clang/Itanium C++ symbols (start with '_Z')
    else if name.starts_with("_Z")
        && let Ok(sym) = cpp_demangle::Symbol::new(&name)
    {
        name = sym.to_string();
    }

    // 3. Remove common compiler-specific prefixes
    if let Some(stripped) = name.strip_prefix("__imp___") {
        name = stripped.to_owned();
    } else if let Some(stripped) = name.strip_prefix("__imp_") {
        name = stripped.to_owned();
    }

    // Strip leading underscore commonly added by C compilers for x86 platform symbols
    if name.starts_with('_') && !name.starts_with("__") && name.len() > 1 {
        name = name[1..].to_owned();
    }

    name
}

#[cfg(all(test, feature = "backend-capstone"))]
mod tests {
    use crate::{
        core::{InstructionClass, disassembler::InstructionInfo},
        utils::flirt::normalize_symbol,
    };

    #[test]
    fn test_normalize_symbol_mangled() {
        // MSVC C++ mangled symbol
        let symbol = "?strlen@@YA_KPEBD@Z";
        let normalized = normalize_symbol(symbol);
        assert!(normalized.contains("strlen"));

        // C-style prepended underscore
        assert_eq!(normalize_symbol("_strlen"), "strlen");

        // Windows import wrapper
        assert_eq!(normalize_symbol("__imp_strlen"), "strlen");

        // Double-underscore prefix preserved
        assert_eq!(normalize_symbol("__libc_start_main"), "__libc_start_main");
    }

    #[test]
    fn test_collect_function_entry_points() {
        use crate::core::BinaryArch;
        use object::File;

        let instructions = vec![
            InstructionInfo {
                address: 0x1000,
                mnemonic: "mov".into(),
                op_str: "eax, 1".into(),
                api_resolution: None,
                matched: smallvec::SmallVec::new(),
                inst_class: Default::default(),
            },
            InstructionInfo {
                address: 0x1005,
                mnemonic: "call".into(),
                op_str: "0x2000".into(),
                api_resolution: None,
                matched: smallvec::SmallVec::new(),
                inst_class: InstructionClass::Call,
            },
        ];

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dummy_elf");
        crate::utils::test_helpers::test_helpers::generate_elf(&path);
        let buffer = std::fs::read(&path).unwrap();
        let empty_obj = File::parse(buffer.as_slice()).unwrap();
        let entry_points = super::collect_function_entry_points(
            &empty_obj,
            &instructions,
            &BinaryArch::X64,
            0x1000,
        );

        assert!(entry_points.contains(&0x1000), "Should contain entry_addr");
        assert!(entry_points.contains(&0x2000), "Should contain call target");
    }

    #[test]
    fn test_find_function_range() {
        use crate::core::BinaryArch;
        use rustc_hash::FxHashSet;

        let insns_data = &[
            InstructionInfo {
                address: 0x1000,
                mnemonic: "push".into(),
                op_str: "rbp".into(),
                api_resolution: None,
                matched: smallvec::SmallVec::new(),
                inst_class: Default::default(),
            },
            InstructionInfo {
                address: 0x1005,
                mnemonic: "mov".into(),
                op_str: "eax, 1".into(),
                api_resolution: None,
                matched: smallvec::SmallVec::new(),
                inst_class: Default::default(),
            },
            InstructionInfo {
                address: 0x100A,
                mnemonic: "ret".into(),
                op_str: "".into(),
                api_resolution: None,
                matched: smallvec::SmallVec::new(),
                inst_class: InstructionClass::Return,
            },
            InstructionInfo {
                address: 0x100B, // new function starts here
                mnemonic: "xor".into(),
                op_str: "eax, eax".into(),
                api_resolution: None,
                matched: smallvec::SmallVec::new(),
                inst_class: Default::default(),
            },
        ];

        let mut entries = FxHashSet::default();
        entries.insert(0x1000);
        entries.insert(0x100B);

        // 1. Should stop at ret
        let (start, end) =
            super::find_function_range(0x1000, insns_data, &entries, &BinaryArch::X64);
        assert_eq!(start, 0x1000);
        assert_eq!(end, 0x100A);

        // 2. Should stop at next function entry point if no ret found
        let insns_no_ret_data = [
            InstructionInfo {
                address: 0x1000,
                mnemonic: "push".into(),
                op_str: "rbp".into(),
                api_resolution: None,
                matched: smallvec::SmallVec::new(),
                inst_class: Default::default(),
            },
            InstructionInfo {
                address: 0x1005,
                mnemonic: "int3".into(),
                op_str: "".into(),
                api_resolution: None,
                matched: smallvec::SmallVec::new(),
                inst_class: Default::default(),
            },
            InstructionInfo {
                address: 0x100B, // new function starts here
                mnemonic: "xor".into(),
                op_str: "eax, eax".into(),
                api_resolution: None,
                matched: smallvec::SmallVec::new(),
                inst_class: Default::default(),
            },
        ];

        let (start2, end2) =
            super::find_function_range(0x1000, &insns_no_ret_data, &entries, &BinaryArch::X64);
        assert_eq!(start2, 0x1000);
        assert_eq!(end2, 0x1005);
    }
}
