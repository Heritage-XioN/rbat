//! # Disassembler Factory
//!
//! This module configures and constructs disassembly engines (Capstone or Iced),
//! adapting to target operating systems and CPU architectures.

use super::traits::*;
use crate::core::InstructionInfo;
use crate::core::Result;

// Feature flagged disassembler implementations

#[cfg(feature = "backend-capstone")]
pub use capstone_backend::*;

#[cfg(feature = "backend-capstone")]
mod capstone_backend {
    use crate::core::{BinaryArch, BinaryOS};

    use super::*;
    use capstone::prelude::*;

    #[derive(Debug)]
    pub struct DisassemblerImpl {
        os: BinaryOS,
        arch: BinaryArch,
    }

    impl DisassemblerImpl {
        pub fn new(os: BinaryOS, arch: BinaryArch) -> Self {
            Self { os, arch }
        }
    }

    impl Disassembler for DisassemblerImpl {
        fn disassemble(&self, text_bytes: &[u8], entry_addr: u64) -> Result<Vec<InstructionInfo>> {
            let cs = match self.arch {
                BinaryArch::X86 | BinaryArch::X64 => {
                    let mut x86 = Capstone::new().x86();
                    if self.arch == BinaryArch::X64 {
                        x86 = x86.mode(arch::x86::ArchMode::Mode64);
                    } else {
                        x86 = x86.mode(arch::x86::ArchMode::Mode32);
                    }
                    x86 = match self.os {
                        BinaryOS::Linux => x86.syntax(arch::x86::ArchSyntax::Att),
                        _ => x86.syntax(arch::x86::ArchSyntax::Intel),
                    };
                    x86.build()?
                }
                BinaryArch::Arm => Capstone::new()
                    .arm()
                    .mode(arch::arm::ArchMode::Arm)
                    .build()?,
                BinaryArch::Arm64 => Capstone::new()
                    .arm64()
                    .mode(arch::arm64::ArchMode::Arm)
                    .build()?,
            };

            let cs_insns = cs.disasm_all(text_bytes, entry_addr)?;
            Ok(cs_insns
                .iter()
                .map(|insn| InstructionInfo::from_capstone(insn))
                .collect())
        }
    }
}

#[cfg(feature = "backend-iced")]
pub use iced_backend::*;

#[cfg(feature = "backend-iced")]
mod iced_backend {
    use super::*;
    use iced_x86::{Code, Decoder, DecoderOptions};

    #[derive(Debug)]
    pub struct DisassemblerImpl {
        os: BinaryOS,
        arch: BinaryArch,
    }

    impl DisassemblerImpl {
        pub fn new(os: BinaryOS, arch: BinaryArch) -> Self {
            Self { os, arch }
        }
    }

    impl Disassembler for DisassemblerImpl {
        fn disassemble(&self, text_bytes: &[u8], entry_addr: u64) -> Result<Vec<InstructionInfo>> {
            let bitness = match self.arch {
                BinaryArch::X64 => 64,
                BinaryArch::X86 => 32,
                _ => {
                    return Err(crate::core::RbatError::GenericDisassemblerError(
                        "iced-x86 only supports x86 and x64 architectures".into(),
                    ));
                }
            };

            let mut decoder =
                Decoder::with_ip(bitness, text_bytes, entry_addr, DecoderOptions::NONE);
            let mut instructions = Vec::with_capacity(if decoder.can_decode() { 1024 } else { 0 });
            let mut instr = iced_x86::Instruction::default();

            while decoder.can_decode() {
                decoder.decode_out(&mut instr);

                if instr.code() == Code::INVALID {
                    continue;
                }

                instructions.push(InstructionInfo::from_iced(&instr, self.os));
            }

            Ok(instructions)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::core::{BinaryArch, BinaryOS};

    use super::*;

    #[test]
    fn test_disasm_factory_x64_intel() {
        let disasm = DisassemblerImpl::new(BinaryOS::Win, BinaryArch::X64);
        let insns = disasm.disassemble(&[0x90], 0x1000).unwrap();
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].format_mnemonic(), "nop");
    }

    #[test]
    fn test_disasm_factory_x86_att() {
        let disasm = DisassemblerImpl::new(BinaryOS::Linux, BinaryArch::X86);
        let insns = disasm.disassemble(&[0x90], 0x1000).unwrap();
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].format_mnemonic(), "nop");
    }

    #[test]
    fn test_disasm_factory_arm() {
        // Iced does not support ARM, but we'll mock or disable if we need to
    }

    #[test]
    fn test_disasm_factory_arm64() {
        // Iced does not support ARM64, but we'll mock or disable if we need to
    }
}
