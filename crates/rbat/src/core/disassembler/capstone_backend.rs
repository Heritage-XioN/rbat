//! # Capstone Disassembly Backend
//!
//! Multi-architecture linear-sweep disassembler leveraging the C-based Capstone engine.
//!
//! ## Overview
//!
//! The [`DisassemblerImpl`] engine supports multi-architecture disassembly across:
//! - `x86` (32-bit Intel syntax)
//! - `x64` (64-bit Intel syntax)
//! - `ARM` (32-bit little-endian)
//! - `ARM64` (AArch64 little-endian)
//!
//! Disassembly uses Intel syntax across all targets to guarantee exact mnemonic and operand
//! text compatibility with capa rule signatures.
//!
//! ## Resilient Disassembly & Skipdata
//!
//! In compiled binaries, code sections frequently interleave non-code elements (alignment padding,
//! embedded jump tables, literal pools, inline data). Standard linear disassembly would halt upon
//! encountering undecodable byte sequences. `DisassemblerImpl` enables Capstone's `skipdata`
//! mode (`cs.set_skipdata(true)`), skipping invalid bytes and resuming disassembly at the next
//! aligned sequence to maintain complete section coverage.
//!
//! ## Allocation & Memory Characteristics
//!
//! - **Decode-Time Inlining**: Mnemonics and operands are unpacked into stack-allocated
//!   [`CompactString`] buffers within [`InstructionInfo`]. Instructions with <= 24 bytes of
//!   text representation require 0 heap allocations.
//! - **IAT Thunk Resolution**: Instructions targeting Import Address Table (IAT) entries
//!   share existing [`Arc<str>`] symbol allocations from [`IatMap`].
//! - **Instruction Classification**: Each instruction is classified into an [`InstructionClass`]
//!   (Call, Return, ConditionalJump, UnconditionalJump, Normal) using Capstone's instruction
//!   group detail tables.
//!
//! ## Examples
//!
//! ```rust
//! use rbat::core::disassembler::DisassemblerImpl;
//! use rbat::core::parser::{BinaryArch, IatMap};
//!
//! let disasm = DisassemblerImpl::new(BinaryArch::X64);
//! let iat_map = IatMap::default();
//! let bytes = [0x90, 0xc3]; // nop; ret
//! let instructions = disasm.disassemble(&bytes, 0x1000, &iat_map).unwrap();
//!
//! assert_eq!(instructions.len(), 2);
//! assert_eq!(instructions[0].format_mnemonic(), "nop");
//! assert_eq!(instructions[1].format_mnemonic(), "ret");
//! ```

use super::InstructionInfo;
use crate::core::types::result::RbatResult;
use crate::core::{
    cfg::{ControlFlowGraph, InstructionClass},
    parser::{BinaryArch, IatMap},
};
use capstone::prelude::*;
use compact_str::CompactString;
use smallvec::SmallVec;
use std::sync::Arc;

/// Multi-architecture disassembly engine powered by Capstone.
///
/// Disassembles machine code for x86, x64, ARM, and ARM64 architectures into unified
/// [`InstructionInfo`] sequences. Configures Capstone with instruction detail inspection
/// and skipdata resilience.
///
/// # Examples
///
/// ```rust
/// use rbat::core::disassembler::DisassemblerImpl;
/// use rbat::core::parser::BinaryArch;
///
/// let disasm = DisassemblerImpl::new(BinaryArch::X64);
/// ```
#[derive(Debug)]
pub struct DisassemblerImpl {
    arch: BinaryArch,
}

impl DisassemblerImpl {
    /// Creates a new Capstone-backed [`DisassemblerImpl`] configured for the specified [`BinaryArch`].
    ///
    /// # Parameters
    ///
    /// - `arch`: Target binary architecture ([`BinaryArch::X86`], [`BinaryArch::X64`],
    ///   [`BinaryArch::Arm`], or [`BinaryArch::Arm64`]).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rbat::core::disassembler::DisassemblerImpl;
    /// use rbat::core::parser::BinaryArch;
    ///
    /// let disasm = DisassemblerImpl::new(BinaryArch::X64);
    /// ```
    pub fn new(arch: BinaryArch) -> Self {
        Self { arch }
    }

    /// Disassembles all machine code instructions from the provided byte slice.
    ///
    /// Configures the Capstone engine for `self.arch` with Intel syntax and detail tracking enabled.
    /// Inlines mnemonic and operand strings, inspects operands against `iat_map` to resolve
    /// imported API calls, and assigns control-flow classifications.
    ///
    /// # Parameters
    ///
    /// - `text_bytes`: Raw executable machine code bytes (typically from `.text` or executable section).
    /// - `entry_addr`: Virtual memory base address corresponding to the start of `text_bytes`.
    /// - `iat_map`: Import Address Table mapping virtual addresses / displacements to API symbol names.
    ///
    /// # Returns
    ///
    /// A vector of [`InstructionInfo`] structs representing the disassembled instructions in linear order.
    ///
    /// # Errors
    ///
    /// Returns an [`RbatError`](crate::core::types::result::RbatError) if:
    /// - Capstone initialization fails for the requested architecture.
    /// - Setting disassembly mode, syntax, or skipdata options fails.
    /// - Linear disassembly fails fatally in the Capstone C engine.
    ///
    /// # Allocation Behavior
    ///
    /// - Capstone's C engine allocates an internal instruction buffer during `disasm_all`.
    /// - The resulting vector pre-allocates space for all decoded instructions.
    /// - Text strings are stored inline via [`CompactString`] without dynamic heap allocations for strings <= 24 bytes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rbat::core::disassembler::DisassemblerImpl;
    /// use rbat::core::parser::{BinaryArch, IatMap};
    ///
    /// let disasm = DisassemblerImpl::new(BinaryArch::X86);
    /// let iat = IatMap::default();
    /// let code = [0xb8, 0x01, 0x00, 0x00, 0x00]; // mov eax, 1
    /// let insns = disasm.disassemble(&code, 0x400000, &iat).unwrap();
    ///
    /// assert_eq!(insns.len(), 1);
    /// assert_eq!(insns[0].format_mnemonic(), "mov");
    /// ```
    pub fn disassemble(
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
                    Some(d) => Self::instruction_class_from_detail(insn, d),
                    None => {
                        ControlFlowGraph::classify_instr(insn.mnemonic().unwrap_or(""), &self.arch)
                    }
                };
                InstructionInfo::from_capstone(insn, api_resolution, inst_class)
            })
            .collect();

        Ok(inst_vec)
    }

    /// Resolves a precise [`InstructionClass`] from Capstone instruction detail groups.
    ///
    /// Inspects architecture group flags to identify calls, returns, and jumps, disambiguating
    /// unconditional branches (`jmp`, `b`, `bx`, `br`) from conditional jumps. Falls back to
    /// mnemonic matching for x86 `loop*` instructions which Capstone does not consistently tag
    /// with branch group flags.
    ///
    /// # Parameters
    ///
    /// - `insn`: The native Capstone instruction.
    /// - `detail`: The decoded Capstone instruction detail containing operand and group metadata.
    ///
    /// # Returns
    ///
    /// An [`InstructionClass`] denoting the control-flow role of the instruction.
    fn instruction_class_from_detail(
        insn: &capstone::Insn,
        detail: &capstone::InsnDetail,
    ) -> InstructionClass {
        use capstone::InsnGroupType;
        let grouped = |g: u8| detail.groups().iter().any(|x| x.0 == g);
        if grouped(InsnGroupType::CS_GRP_CALL as u8) {
            InstructionClass::Call
        } else if grouped(InsnGroupType::CS_GRP_RET as u8)
            || grouped(InsnGroupType::CS_GRP_IRET as u8)
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
}

impl InstructionInfo {
    /// Instantiates an [`InstructionInfo`] from a Capstone instruction and resolved metadata.
    ///
    /// # Parameters
    ///
    /// - `insn`: Reference to the native [`capstone::Insn`].
    /// - `api_resolution`: Optional [`Arc<str>`] representing an imported API resolved from IAT.
    /// - `inst_class`: Control flow classification resolved from Capstone detail groups.
    pub(crate) fn from_capstone(
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{
        cfg::InstructionClass,
        parser::{BinaryArch, IatMap},
    };

    #[test]
    fn test_disasm_factory_x64_intel() {
        let disasm = DisassemblerImpl::new(BinaryArch::X64);
        let iat_map = IatMap::default();
        let insns = disasm.disassemble(&[0x90], 0x1000, &iat_map).unwrap();
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].format_mnemonic(), "nop");
    }

    #[test]
    fn test_disasm_factory_x86_intel() {
        let disasm = DisassemblerImpl::new(BinaryArch::X86);
        let iat_map = IatMap::default();
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
            let iat_map = IatMap::default();
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
            let iat_map = IatMap::default();
            let insns = disasm.disassemble(bytes, 0x1000, &iat_map).unwrap();
            assert_eq!(insns.len(), 1);
            assert_eq!(insns[0].format_mnemonic(), "nop");
        }
    }

    #[test]
    fn test_capstone_precise_control_flow_class() {
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
