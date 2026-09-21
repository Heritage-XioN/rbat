//! capstone based disassembler implementation

use crate::core::InstructionClass;
use crate::core::traits::Disassembler;
use crate::core::types::RbatResult;
use crate::core::{BinaryArch, IatMap};
use aho_corasick::PatternID;
use capstone::prelude::*;
use compact_str::CompactString;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::sync::Arc;

/// Represents a single disassembled instruction with pre-computed optimization metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstructionInfo {
    /// The memory address of the instruction.
    pub address: u64,
    /// The cached mnemonic string.
    pub mnemonic: CompactString,
    /// The cached operand string.
    pub op_str: CompactString,
    pub api_resolution: Option<Arc<str>>,
    /// The set of PatternIDs this instruction matched.
    #[serde(skip)]
    pub matched: SmallVec<[PatternID; 8]>,
    /// Precise control-flow class resolved from Capstone instruction detail.
    pub inst_class: InstructionClass,
}

impl InstructionInfo {
    /// Instantiates an `InstructionInfo` from a Capstone instruction.
    pub fn from_capstone(
        insn: &capstone::Insn,
        api_resolution: Option<Arc<str>>,
        inst_class: InstructionClass,
    ) -> Self {
        Self {
            address: insn.address(),
            mnemonic: CompactString::new(insn.mnemonic().unwrap_or("")),
            op_str: CompactString::new(insn.op_str().unwrap_or("")),
            api_resolution,
            matched: SmallVec::new(),
            inst_class,
        }
    }

    /// Returns the address of the instruction.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Returns a new lowercase formatted mnemonic string.
    pub fn format_mnemonic(&self) -> String {
        self.mnemonic.to_string()
    }

    /// Returns a new lowercase formatted operand string.
    pub fn format_operands(&self) -> String {
        self.op_str.to_string()
    }

    /// Zero-allocation formatted mnemonic writer.
    pub fn format_mnemonic_into(&self, buf: &mut String) {
        buf.clear();
        buf.push_str(&self.mnemonic);
    }

    /// Zero-allocation formatted operand writer.
    pub fn format_operands_into(&self, buf: &mut String) {
        buf.clear();
        buf.push_str(&self.op_str);
    }

    /// Returns the branch target address if this is a branch/call to a direct address.
    /// Falls back to string parsing for capstone backend.
    pub fn branch_target(&self) -> Option<u64> {
        crate::utils::cfg::parse_target_address(&self.op_str)
    }

    /// Classifies this instruction's control-flow role.
    /// Uses the precise class resolved from Capstone detail when available,
    /// otherwise falls back to the string-based mnemonic heuristic.
    pub fn class(&self, _arch: &crate::core::BinaryArch) -> InstructionClass {
        self.inst_class
    }
}

#[derive(Debug)]
pub struct DisassemblerImpl {
    arch: BinaryArch,
}

impl DisassemblerImpl {
    pub fn new(arch: BinaryArch) -> Self {
        Self { arch }
    }
}

impl Disassembler for DisassemblerImpl {
    fn disassemble(
        &self,
        text_bytes: &[u8],
        entry_addr: u64,
        iat_map: &IatMap,
    ) -> RbatResult<Vec<InstructionInfo>> {
        let mut cs = match self.arch {
            BinaryArch::X86 | BinaryArch::X64 => {
                let mut x86 = Capstone::new().x86();
                if self.arch == BinaryArch::X64 {
                    x86 = x86.mode(arch::x86::ArchMode::Mode64);
                } else {
                    x86 = x86.mode(arch::x86::ArchMode::Mode32);
                }
                // Intel syntax on every OS so mnemonic/operand text matches capa's ruleset
                x86 = x86.syntax(arch::x86::ArchSyntax::Intel);
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

        // Continue past undecodable bytes (alignment padding, embedded data,
        // jump tables) instead of truncating coverage at the first invalid one.
        cs.set_skipdata(true)?;

        let cs_insns = cs.disasm_all(text_bytes, entry_addr)?;

        let inst_vec: Vec<InstructionInfo> = cs_insns
            .iter()
            .map(|insn| {
                let detail = cs.insn_detail(insn).ok();
                let mut api_resolution = None;
                if let Some(detail) = &detail {
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
                let inst_class = match &detail {
                    Some(d) => instruction_class_from_detail(insn, d),
                    None => crate::utils::cfg::classify_instruction(
                        insn.mnemonic().unwrap_or(""),
                        &self.arch,
                    ),
                };
                InstructionInfo::from_capstone(insn, api_resolution, inst_class)
            })
            .collect();

        Ok(inst_vec)
    }
}

/// A helper that resolves a precise `InstructionClass` from Capstone instruction detail
/// (control-flow groups), disambiguating unconditional vs conditional jumps.
/// Falls back to the mnemonic for x86 `loop*` instructions, which Capstone
/// does not always tag with a generic branch group.
fn instruction_class_from_detail(
    insn: &capstone::Insn,
    detail: &capstone::InsnDetail,
) -> InstructionClass {
    use capstone::InsnGroupType;
    let grouped = |g: u8| detail.groups().iter().any(|x| x.0 == g);
    if grouped(InsnGroupType::CS_GRP_CALL as u8) {
        InstructionClass::Call
    } else if grouped(InsnGroupType::CS_GRP_RET as u8) || grouped(InsnGroupType::CS_GRP_IRET as u8)
    {
        InstructionClass::Return
    } else if grouped(InsnGroupType::CS_GRP_JUMP as u8) {
        // Capstone tags both conditional and unconditional jumps with the
        // generic `Jump` group. Recognize x86 (`jmp`) and ARM/ARM64 (`b`, `bx`, `br`) unconditional jumps.
        match insn.mnemonic() {
            Some("jmp") | Some("b") | Some("bx") | Some("br") => {
                InstructionClass::UnconditionalJump
            }
            _ => InstructionClass::ConditionalJump,
        }
    } else {
        match insn.mnemonic() {
            Some(m) if m == "loop" || m == "loope" || m == "loopne" => {
                InstructionClass::ConditionalJump
            }
            _ => InstructionClass::Normal,
        }
    }
}

#[cfg(all(test, feature = "backend-capstone", not(feature = "backend-iced")))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::BinaryArch;
    use crate::core::traits::Disassembler;

    #[test]
    fn test_disasm_factory_x64_intel() {
        let disasm = DisassemblerImpl::new(BinaryArch::X64);
        let iat_map = crate::core::types::IatMap::default();
        let insns = disasm.disassemble(&[0x90], 0x1000, &iat_map).unwrap();
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].format_mnemonic(), "nop");
    }

    #[test]
    fn test_disasm_factory_x86_att() {
        let disasm = DisassemblerImpl::new(BinaryArch::X86);
        let iat_map = crate::core::types::IatMap::default();
        let insns = disasm.disassemble(&[0x90], 0x1000, &iat_map).unwrap();
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].format_mnemonic(), "nop");
    }

    #[test]
    fn test_disasm_factory_arm() {
        let disasm = DisassemblerImpl::new(BinaryArch::Arm);
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

    #[test]
    fn test_disasm_factory_arm64() {
        let disasm = DisassemblerImpl::new(BinaryArch::Arm64);
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

    #[test]
    fn test_capstone_precise_control_flow_class() {
        use crate::core::traits::Disassembler;
        use crate::core::types::IatMap;
        use crate::core::{BinaryArch, InstructionClass};
        let disasm = DisassemblerImpl::new(BinaryArch::X64);
        let iat_map = IatMap::default();
        // call rel32 ; ret ; jmp short ; je short ; rdtsc ; aesenc xmm0,xmm0
        let bytes = [
            0xe8, 0x00, 0x00, 0x00, 0x00, 0xc3, 0xeb, 0x00, 0x74, 0x00, 0x0f, 0x31, 0x66, 0x0f,
            0x38, 0xdc, 0xc0,
        ];
        let insns = disasm.disassemble(&bytes, 0x1000, &iat_map).unwrap();
        let class: Vec<InstructionClass> =
            insns.iter().map(|i| i.class(&BinaryArch::X64)).collect();

        assert_eq!(insns.len(), 6);
        assert_eq!(class[0], InstructionClass::Call);
        assert_eq!(class[1], InstructionClass::Return);
        assert_eq!(class[2], InstructionClass::UnconditionalJump);
        assert_eq!(class[3], InstructionClass::ConditionalJump);
        // Crypto/anti-debug primitives are NOT branches.
        assert_eq!(class[4], InstructionClass::Normal);
        assert_eq!(class[5], InstructionClass::Normal);
    }

    #[test]
    fn test_capstone_arm_unconditional_branch_class() {
        use crate::core::traits::Disassembler;
        use crate::core::types::IatMap;
        use crate::core::{BinaryArch, InstructionClass};
        let disasm = DisassemblerImpl::new(BinaryArch::Arm);
        let iat_map = IatMap::default();
        // b #0 (ARM32 little endian: 0x00, 0x00, 0x00, 0xEA)
        let bytes = [0x00, 0x00, 0x00, 0xEA];
        let insns = disasm.disassemble(&bytes, 0x1000, &iat_map).unwrap();

        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].format_mnemonic(), "b");
        assert_eq!(
            insns[0].class(&BinaryArch::Arm),
            InstructionClass::UnconditionalJump
        );
    }

    #[test]
    fn test_capstone_resumes_after_invalid_bytes() {
        use crate::core::types::IatMap;
        let disasm = DisassemblerImpl::new(BinaryArch::X64);
        let iat_map = IatMap::default();
        // nop ; 0x06 (invalid in long mode) ; rdtsc ; aesenc xmm0, xmm0
        let bytes = [0x90, 0x06, 0x0f, 0x31, 0x66, 0x0f, 0x38, 0xdc, 0xc0];
        let insns = disasm.disassemble(&bytes, 0x1000, &iat_map).unwrap();

        // Without skipdata capstone truncates at the first invalid byte (only `nop`);
        // with skipdata it decodes everything, so instructions past 0x06 survive.
        assert!(
            insns.len() >= 4,
            "capstone stopped at the invalid byte; decoded {} instructions",
            insns.len()
        );
        let mnems: Vec<String> = insns.iter().map(|i| i.format_mnemonic()).collect();
        assert!(
            mnems.iter().any(|m| m == "rdtsc"),
            "missing rdtsc: {mnems:?}"
        );
        assert!(
            mnems.iter().any(|m| m == "aesenc"),
            "missing aesenc: {mnems:?}"
        );
    }
}
