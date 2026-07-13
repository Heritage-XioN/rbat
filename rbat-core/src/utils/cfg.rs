use crate::core::{BinaryArch, types::InstructionClass};

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
    fn test_parse_target_address() {
        assert_eq!(parse_target_address("0x1080"), Some(0x1080));
        assert_eq!(parse_target_address("#0x401000"), Some(0x401000));
        assert_eq!(parse_target_address("*0x40"), Some(0x40));
        assert_eq!(parse_target_address("100"), Some(100));
        assert_eq!(parse_target_address("rax"), None);
    }
}
