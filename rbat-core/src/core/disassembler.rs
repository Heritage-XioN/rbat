//! # Disassembler Factory
//!
//! This module configures and constructs disassembly engines (Capstone or Iced),
//! adapting to target operating systems and CPU architectures.

use super::traits::*;
use crate::core::InstructionInfo;
use crate::core::Result;

#[cfg(feature = "backend-capstone")]
pub use capstone_backend::*;

#[cfg(feature = "backend-capstone")]
mod capstone_backend {
    use crate::core::{BinaryArch, BinaryOS, IatMap};

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
        fn disassemble(
            &self,
            text_bytes: &[u8],
            entry_addr: u64,
            iat_map: &IatMap,
        ) -> Result<Vec<InstructionInfo>> {
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
                    x86.detail(true).build()?
                }
                BinaryArch::Arm => Capstone::new()
                    .arm()
                    .mode(arch::arm::ArchMode::Arm)
                    .detail(true)
                    .build()?,
                BinaryArch::Arm64 => Capstone::new()
                    .arm64()
                    .mode(arch::arm64::ArchMode::Arm)
                    .detail(true)
                    .build()?,
            };

            let cs_insns = cs.disasm_all(text_bytes, entry_addr)?;
            Ok(cs_insns
                .iter()
                .map(|insn| {
                    let mut api_resolution = None;
                    if let Ok(detail) = cs.insn_detail(insn) {
                        let arch_detail = detail.arch_detail();
                        if let Some(x86) = arch_detail.x86() {
                            for op in x86.operands() {
                                match op.op_type {
                                    capstone::arch::x86::X86OperandType::Imm(imm) => {
                                        if let Some(api) = iat_map.get(&(imm as u64)) {
                                            api_resolution = Some(api.clone());
                                            break;
                                        }
                                    }
                                    capstone::arch::x86::X86OperandType::Mem(mem) => {
                                        if let Some(api) = iat_map.get(&(mem.disp() as u64)) {
                                            api_resolution = Some(api.clone());
                                            break;
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    InstructionInfo::from_capstone(insn, api_resolution)
                })
                .collect())
        }
    }
}

#[cfg(all(feature = "backend-iced", not(feature = "backend-capstone")))]
pub use iced_backend::*;

#[cfg(all(feature = "backend-iced", not(feature = "backend-capstone")))]
mod iced_backend {
    use crate::core::{BinaryArch, BinaryOS, IatMap};

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
        fn disassemble(
            &self,
            text_bytes: &[u8],
            entry_addr: u64,
            iat_map: &IatMap,
        ) -> Result<Vec<InstructionInfo>> {
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

                let mut api_resolution = None;
                let target = instr.near_branch64();
                if target != 0
                    && let Some(api) = iat_map.get(&target)
                {
                    api_resolution = Some(api.clone());
                }
                if api_resolution.is_none() {
                    let disp = instr.memory_displacement64();
                    if disp != 0
                        && let Some(api) = iat_map.get(&disp)
                    {
                        api_resolution = Some(api.clone());
                    }
                }

                instructions.push(InstructionInfo::from_iced(&instr, self.os, api_resolution));
            }

            Ok(instructions)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::core::{BinaryArch, BinaryOS};

    use super::*;

    #[cfg(all(test, feature = "backend-capstone", not(feature = "backend-iced")))]
    #[test]
    fn test_disasm_factory_x64_intel() {
        let disasm = DisassemblerImpl::new(BinaryOS::Win, BinaryArch::X64);
        let iat_map = crate::core::types::IatMap::default();
        let insns = disasm.disassemble(&[0x90], 0x1000, &iat_map).unwrap();
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].format_mnemonic(), "nop");
    }

    #[cfg(all(test, feature = "backend-capstone", not(feature = "backend-iced")))]
    #[test]
    fn test_disasm_factory_x86_att() {
        let disasm = DisassemblerImpl::new(BinaryOS::Linux, BinaryArch::X86);
        let iat_map = crate::core::types::IatMap::default();
        let insns = disasm.disassemble(&[0x90], 0x1000, &iat_map).unwrap();
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].format_mnemonic(), "nop");
    }

    #[cfg(all(test, feature = "backend-capstone", not(feature = "backend-iced")))]
    #[test]
    fn test_disasm_factory_arm() {
        let disasm = DisassemblerImpl::new(BinaryOS::Linux, BinaryArch::Arm);
        // NOP in ARM (little endian): 0x00, 0xF0, 0x20, 0xE3
        let bytes = &[0x00, 0xF0, 0x20, 0xE3];

        #[cfg(feature = "backend-capstone")]
        {
            let iat_map = crate::core::types::IatMap::default();
            let insns = disasm.disassemble(bytes, 0x1000, &iat_map).unwrap();
            assert_eq!(insns.len(), 1);
            assert_eq!(insns[0].format_mnemonic(), "nop");
        }
    }

    #[cfg(all(test, feature = "backend-capstone", not(feature = "backend-iced")))]
    #[test]
    fn test_disasm_factory_arm64() {
        let disasm = DisassemblerImpl::new(BinaryOS::Linux, BinaryArch::Arm64);
        // NOP in ARM64: 0x1F, 0x20, 0x03, 0xD5
        let bytes = &[0x1F, 0x20, 0x03, 0xD5];

        #[cfg(feature = "backend-capstone")]
        {
            let iat_map = crate::core::types::IatMap::default();
            let insns = disasm.disassemble(bytes, 0x1000, &iat_map).unwrap();
            assert_eq!(insns.len(), 1);
            assert_eq!(insns[0].format_mnemonic(), "nop");
        }
    }

    #[cfg(all(test, feature = "backend-iced", not(feature = "backend-capstone")))]
    #[test]
    fn test_iced_disasm_factory_x64_intel() {
        let disasm = DisassemblerImpl::new(BinaryOS::Win, BinaryArch::X64);
        // NOP, RET
        let bytes = &[0x90, 0xC3];
        let iat_map = crate::core::types::IatMap::default();
        let insns = disasm.disassemble(bytes, 0x1000, &iat_map).unwrap();
        assert_eq!(insns.len(), 2);

        assert_eq!(insns[0].address(), 0x1000);
        assert_eq!(insns[0].format_mnemonic(), "nop");

        assert_eq!(insns[1].address(), 0x1001);
        assert_eq!(insns[1].format_mnemonic(), "ret");
    }

    #[cfg(all(test, feature = "backend-iced", not(feature = "backend-capstone")))]
    #[test]
    fn test_iced_disasm_factory_x86_att() {
        let disasm = DisassemblerImpl::new(BinaryOS::Linux, BinaryArch::X86);
        // MOV EAX, 1
        let bytes = &[0xB8, 0x01, 0x00, 0x00, 0x00];
        let iat_map = crate::core::types::IatMap::default();
        let insns = disasm.disassemble(bytes, 0x1000, &iat_map).unwrap();
        assert_eq!(insns.len(), 1);

        assert_eq!(insns[0].address(), 0x1000);
        assert_eq!(insns[0].format_mnemonic(), "mov");
        // GAS format: $1, %eax
        let op_str = insns[0].format_operands();
        assert!(
            op_str.contains("%eax") || op_str.contains("$1") || op_str.contains("eax"),
            "op_str: {}",
            op_str
        );
    }

    #[cfg(all(test, feature = "backend-iced", not(feature = "backend-capstone")))]
    #[test]
    fn test_iced_disasm_invalid_bytes() {
        let disasm = DisassemblerImpl::new(BinaryOS::Win, BinaryArch::X64);
        // 0xFF 0xFF is an invalid x86 instruction
        let bytes = &[0xFF, 0xFF];
        let iat_map = crate::core::types::IatMap::default();
        let insns = disasm.disassemble(bytes, 0x1000, &iat_map).unwrap();
        // Iced decodes it as an INVALID instruction and we skip it in our loop,
        // but let's check what it outputs, probably 0 instructions.
        assert_eq!(insns.len(), 0);
    }
}
