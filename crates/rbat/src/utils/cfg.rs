//! # Control Flow Graph Utilities
//!
//! Provides low-level helper functions for classifying disassembled instructions
//! and parsing branch target addresses from operand strings. These primitives are
//! consumed by [`crate::core::cfg::ControlFlowGraph`] during basic-block partitioning
//! and edge reconstruction.
//!
//! ## Architecture Support
//!
//! Instruction classification covers two ISA families:
//!
//! | Family        | Architectures        | Conditional Branches     | Calls       |
//! |---------------|----------------------|--------------------------|-------------|
//! | x86           | `X86`, `X64`         | `je`, `jne`, `jg`, etc.  | `call`      |
//! | ARM           | `Arm`, `Arm64`       | `b.eq`, `cbz`, `tbnz`    | `bl`, `blx` |
//!
//! ## Operand Parsing
//!
//! [`parse_target_address`] strips common assembler prefixes (`#`, `$`, `*`) and
//! attempts to interpret the remainder as a hex (`0x…`) or decimal literal. Indirect
//! or register-based operands (e.g. `rax`, `[rbx+8]`) return `None`.

use crate::core::{BinaryArch, types::InstructionClass};

/// Classifies a disassembled instruction mnemonic into its control-flow role.
///
/// The classification determines how [`crate::core::cfg::ControlFlowGraph`] partitions
/// the instruction stream into basic blocks and what edge types to emit.
///
/// # Arguments
///
/// * `mnemonic` — The lowercase mnemonic string (e.g. `"jmp"`, `"ret"`, `"bl"`).
/// * `arch` — The target CPU architecture, which selects the ISA-specific matching rules.
///
/// # Returns
///
/// An [`InstructionClass`] variant:
///
/// * [`Normal`](InstructionClass::Normal) — No control-flow effect; execution continues sequentially.
/// * [`ConditionalJump`](InstructionClass::ConditionalJump) — A branch taken only when a condition is met
///   (e.g. `je`, `b.eq`). Produces both a *true* and *false/fallthrough* edge.
/// * [`UnconditionalJump`](InstructionClass::UnconditionalJump) — An unconditional transfer of control
///   (e.g. `jmp`, `b`). Produces a single *unconditional* edge with no fallthrough.
/// * [`Call`](InstructionClass::Call) — A subroutine invocation (e.g. `call`, `bl`). Produces a *call*
///   edge plus a *fallthrough* edge for the return site.
/// * [`Return`](InstructionClass::Return) — A subroutine exit (e.g. `ret`, `bx lr`). Terminates the
///   current basic block with no outgoing edges.
///
/// # Examples
///
/// ```
/// use rbat::utils::cfg::classify_instruction;
/// use rbat::core::{BinaryArch, types::InstructionClass};
///
/// assert_eq!(classify_instruction("jmp", &BinaryArch::X64), InstructionClass::UnconditionalJump);
/// assert_eq!(classify_instruction("je", &BinaryArch::X64), InstructionClass::ConditionalJump);
/// assert_eq!(classify_instruction("mov", &BinaryArch::X64), InstructionClass::Normal);
/// ```
pub fn classify_instruction(mnemonic: &str, arch: &BinaryArch) -> InstructionClass {
    match arch {
        BinaryArch::X86 | BinaryArch::X64 => match mnemonic {
            "jmp" => InstructionClass::UnconditionalJump,
            "ret" | "retf" | "retn" | "iret" | "iretd" | "sysret" => InstructionClass::Return,
            "call" => InstructionClass::Call,
            m if m.starts_with('j') => InstructionClass::ConditionalJump,
            _ => InstructionClass::Normal,
        },
        BinaryArch::Arm | BinaryArch::Arm64 => match mnemonic {
            "b" => InstructionClass::UnconditionalJump,
            "br" | "bx" | "ret" => InstructionClass::Return,
            "bl" | "blx" => InstructionClass::Call,
            m if m.starts_with("b.")
                || m.starts_with("cbz")
                || m.starts_with("cbnz")
                || m.starts_with("tbz")
                || m.starts_with("tbnz") =>
            {
                InstructionClass::ConditionalJump
            }
            _ => InstructionClass::Normal,
        },
    }
}

/// Parses a branch target virtual address from an instruction operand string.
///
/// Capstone-formatted operand strings may carry assembler-specific prefix characters
/// (`#`, `$`, `*`, `@`) depending on the syntax mode (Intel vs AT&T) or the target
/// architecture (ARM uses `#` for immediates). This function strips those prefixes
/// and attempts to interpret the remaining token as either a hexadecimal (`0x…`) or
/// decimal address literal.
///
/// Indirect or register-based operands (e.g. `"rax"`, `"[rbp+0x10]"`, `"qword ptr [rsp]"`)
/// are not valid branch targets for CFG purposes and return `None`.
///
/// # Arguments
///
/// * `op_str` — The raw operand string produced by the disassembler.
///
/// # Returns
///
/// * `Some(address)` — If the operand resolves to a valid numeric address.
/// * `None` — If the operand is empty, register-based, or otherwise unparseable.
///
/// # Examples
///
/// ```
/// use rbat::utils::cfg::parse_target_address;
///
/// assert_eq!(parse_target_address("0x1080"), Some(0x1080));
/// assert_eq!(parse_target_address("#0x401000"), Some(0x401000));
/// assert_eq!(parse_target_address("rax"), None);
/// assert_eq!(parse_target_address(""), None);
/// ```
pub fn parse_target_address(op_str: &str) -> Option<u64> {
    let trimmed = op_str.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Filter out common prefix characters like #, $, *, @
    let cleaned: String = trimmed
        .chars()
        .filter(|&c| c.is_alphanumeric() || c == 'x' || c == 'X' || c == '-' || c == '+')
        .collect();

    if cleaned.starts_with("0x") || cleaned.starts_with("0X") {
        u64::from_str_radix(&cleaned[2..], 16).ok()
    } else {
        cleaned.parse::<u64>().ok()
    }
}

#[cfg(test)]
mod tests {
    use crate::core::{BinaryArch, types::InstructionClass};

    use super::*;

    #[test]
    fn test_instruction_classification_x64() {
        let arch = BinaryArch::X64;
        assert_eq!(
            classify_instruction("jmp", &arch),
            InstructionClass::UnconditionalJump
        );
        assert_eq!(
            classify_instruction("je", &arch),
            InstructionClass::ConditionalJump
        );
        assert_eq!(classify_instruction("call", &arch), InstructionClass::Call);
        assert_eq!(classify_instruction("ret", &arch), InstructionClass::Return);
        assert_eq!(classify_instruction("mov", &arch), InstructionClass::Normal);
    }

    #[test]
    fn test_instruction_classification_x64_extended() {
        let arch = BinaryArch::X64;
        // All return variants
        assert_eq!(
            classify_instruction("retf", &arch),
            InstructionClass::Return
        );
        assert_eq!(
            classify_instruction("retn", &arch),
            InstructionClass::Return
        );
        assert_eq!(
            classify_instruction("iret", &arch),
            InstructionClass::Return
        );
        assert_eq!(
            classify_instruction("iretd", &arch),
            InstructionClass::Return
        );
        assert_eq!(
            classify_instruction("sysret", &arch),
            InstructionClass::Return
        );
        // Conditional jump variants
        assert_eq!(
            classify_instruction("jne", &arch),
            InstructionClass::ConditionalJump
        );
        assert_eq!(
            classify_instruction("jg", &arch),
            InstructionClass::ConditionalJump
        );
        assert_eq!(
            classify_instruction("jle", &arch),
            InstructionClass::ConditionalJump
        );
        // Normal instructions
        assert_eq!(
            classify_instruction("push", &arch),
            InstructionClass::Normal
        );
        assert_eq!(classify_instruction("nop", &arch), InstructionClass::Normal);
    }

    #[test]
    fn test_instruction_classification_arm64() {
        let arch = BinaryArch::Arm64;
        assert_eq!(
            classify_instruction("b", &arch),
            InstructionClass::UnconditionalJump
        );
        assert_eq!(
            classify_instruction("b.eq", &arch),
            InstructionClass::ConditionalJump
        );
        assert_eq!(
            classify_instruction("b.ne", &arch),
            InstructionClass::ConditionalJump
        );
        assert_eq!(
            classify_instruction("cbz", &arch),
            InstructionClass::ConditionalJump
        );
        assert_eq!(
            classify_instruction("cbnz", &arch),
            InstructionClass::ConditionalJump
        );
        assert_eq!(
            classify_instruction("tbz", &arch),
            InstructionClass::ConditionalJump
        );
        assert_eq!(
            classify_instruction("tbnz", &arch),
            InstructionClass::ConditionalJump
        );
        assert_eq!(classify_instruction("bl", &arch), InstructionClass::Call);
        assert_eq!(classify_instruction("blx", &arch), InstructionClass::Call);
        assert_eq!(classify_instruction("ret", &arch), InstructionClass::Return);
        assert_eq!(classify_instruction("br", &arch), InstructionClass::Return);
        assert_eq!(classify_instruction("bx", &arch), InstructionClass::Return);
        assert_eq!(classify_instruction("mov", &arch), InstructionClass::Normal);
    }

    #[test]
    fn test_parse_target_address() {
        assert_eq!(parse_target_address("0x1080"), Some(0x1080));
        assert_eq!(parse_target_address("#0x401000"), Some(0x401000));
        assert_eq!(parse_target_address("*0x40"), Some(0x40));
        assert_eq!(parse_target_address("100"), Some(100));
        assert_eq!(parse_target_address("rax"), None);
    }

    #[test]
    fn test_parse_target_address_edge_cases() {
        // Empty and whitespace
        assert_eq!(parse_target_address(""), None);
        assert_eq!(parse_target_address("   "), None);

        // Uppercase hex prefix
        assert_eq!(parse_target_address("0X1000"), Some(0x1000));

        // AT&T style with $ prefix
        assert_eq!(parse_target_address("$0x4000"), Some(0x4000));

        // Register operands must return None
        assert_eq!(parse_target_address("rax"), None);
        assert_eq!(parse_target_address("rbx"), None);
        assert_eq!(parse_target_address("eax"), None);
    }
}
