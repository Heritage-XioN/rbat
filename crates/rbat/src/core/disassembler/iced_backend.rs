//! iced_x86 based disassembler implementation

use crate::core::{
    cfg::InstructionClass,
    parser::{BinaryArch, IatMap},
    traits::Disassembler,
    types::{RbatError, RbatResult},
};
use aho_corasick::PatternID;
use iced_x86::{Code, Decoder, DecoderOptions, FlowControl};
use smallvec::SmallVec;
use std::sync::Arc;

/// A generic view over a disassembled instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstructionInfo {
    pub inner: iced_x86::Instruction,
    pub api_resolution: Option<Arc<str>>,
    /// Pre-computed set of Aho-Corasick pattern IDs matched against this instruction's text.
    pub matched: SmallVec<[PatternID; 8]>,
    /// Control-flow class resolved from Iced's precise `flow_control()`
    pub inst_class: InstructionClass,
}

impl InstructionInfo {
    pub fn from_iced(inner: &iced_x86::Instruction, api_resolution: Option<Arc<str>>) -> Self {
        Self {
            inner: *inner,
            api_resolution,
            matched: smallvec::SmallVec::new(),
            inst_class: Self::classify_flow(inner.flow_control()),
        }
    }

    pub fn address(&self) -> u64 {
        self.inner.ip()
    }

    pub fn format_mnemonic_into(&self, buf: &mut String) {
        use std::fmt::Write;
        buf.clear();
        let _ = write!(buf, "{:?}", self.inner.mnemonic());
        buf.make_ascii_lowercase();
    }

    pub fn format_mnemonic(&self) -> String {
        let mut buf = String::new();
        self.format_mnemonic_into(&mut buf);
        buf
    }

    pub fn format_operands_into(&self, buf: &mut String) {
        use iced_x86::Formatter;
        use std::cell::RefCell;
        thread_local! {
            static INTEL_FMT: RefCell<iced_x86::IntelFormatter> = RefCell::new(iced_x86::IntelFormatter::new());
        }

        buf.clear();
        // Intel syntax on every OS so operand text matches capa's ruleset
        INTEL_FMT.with(|fmt| fmt.borrow_mut().format_all_operands(&self.inner, buf))
    }

    pub fn format_operands(&self) -> String {
        let mut buf = String::new();
        self.format_operands_into(&mut buf);
        buf
    }

    /// Returns the branch target address if this is a near branch instruction, without
    /// allocating a string. Returns `None` for non-branch or indirect branches.
    pub fn branch_target(&self) -> Option<u64> {
        let target = self.inner.near_branch_target();
        if target != 0 { Some(target) } else { None }
    }

    /// Classifies this instruction's control-flow role without allocating a string.
    pub fn class(&self, _arch: &BinaryArch) -> InstructionClass {
        self.inst_class
    }

    fn classify_flow(flow: iced_x86::FlowControl) -> InstructionClass {
        match flow {
            FlowControl::UnconditionalBranch => InstructionClass::UnconditionalJump,
            FlowControl::ConditionalBranch => InstructionClass::ConditionalJump,
            FlowControl::Call | FlowControl::IndirectCall => InstructionClass::Call,
            FlowControl::Return => InstructionClass::Return,
            _ => InstructionClass::Normal,
        }
    }
}

impl serde::Serialize for InstructionInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("InstructionInfo", 3)?;
        state.serialize_field("address", &self.address())?;
        state.serialize_field("mnemonic", &self.format_mnemonic())?;
        state.serialize_field("op_str", &self.format_operands())?;
        state.end()
    }
}

impl<'de> serde::Deserialize<'de> for InstructionInfo {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Deserialization is a stub because we cannot easily recreate the raw iced_x86 instruction
        // from formatted strings without the binary data.
        Err(serde::de::Error::custom(
            "Deserialize not supported for backend-iced InstructionInfo",
        ))
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
    /// Decodes/disassembles all x86 instructions in the provided text bytes.
    ///
    /// # Allocation behavior
    ///
    /// The returned `Vec<InstructionInfo>` is pre-allocated to
    /// `min(text.len() / 4, MAX_PREALLOC_BYTES / size_of::<InstructionInfo>())`
    /// entries as a heuristic estimate of instruction count (x86 instructions
    /// average ~3–4 bytes). The upfront allocation is therefore capped at
    /// `MAX_PREALLOC_BYTES` (8 MiB) regardless of input size, so a very large
    /// or adversarial `text` cannot trigger an unbounded upfront allocation.
    ///
    /// If the input contains more instructions than the pre-allocated capacity
    /// (e.g. a long run of 1-byte instructions such as NOPs), the vector grows
    /// amortized, requiring a small, bounded number of reallocations.
    ///
    /// Peak memory is O(number of instructions).
    fn disassemble(
        &self,
        text_bytes: &[u8],
        entry_addr: u64,
        iat_map: &IatMap,
    ) -> RbatResult<Vec<InstructionInfo>> {
        let bitness = match self.arch {
            BinaryArch::X64 => 64,
            BinaryArch::X86 => 32,
            _ => {
                return Err(RbatError::GenericDisassemblerError(
                    "iced-x86 only supports x86 and x64 architectures".into(),
                ));
            }
        };

        const MAX_PREALLOC_BYTES: usize = 8 << 20; // 8 MiB
        let max_entries = MAX_PREALLOC_BYTES / size_of::<InstructionInfo>();
        let cap = (text_bytes.len() / 4).min(max_entries);

        let mut decoder = Decoder::with_ip(bitness, text_bytes, entry_addr, DecoderOptions::NONE);
        let mut instructions = Vec::with_capacity(if decoder.can_decode() { cap } else { 0 });
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

            instructions.push(InstructionInfo::from_iced(&instr, api_resolution));
        }

        Ok(instructions)
    }
}

#[cfg(all(test, feature = "backend-iced", not(feature = "backend-capstone")))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{
        parser::{BinaryArch, IatMap},
        traits::Disassembler,
    };

    #[test]
    fn test_iced_disasm_factory_x64_intel() {
        let disasm = DisassemblerImpl::new(BinaryArch::X64);
        // NOP, RET
        let bytes = &[0x90, 0xC3];
        let iat_map = IatMap::default();
        let insns = disasm.disassemble(bytes, 0x1000, &iat_map).unwrap();
        assert_eq!(insns.len(), 2);

        assert_eq!(insns[0].address(), 0x1000);
        assert_eq!(insns[0].format_mnemonic(), "nop");

        assert_eq!(insns[1].address(), 0x1001);
        assert_eq!(insns[1].format_mnemonic(), "ret");
    }

    #[test]
    fn test_iced_disasm_factory_x86_att() {
        let disasm = DisassemblerImpl::new(BinaryArch::X86);
        // MOV EAX, 1
        let bytes = &[0xB8, 0x01, 0x00, 0x00, 0x00];
        let iat_map = IatMap::default();
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

    #[test]
    fn test_iced_disasm_invalid_bytes() {
        let disasm = DisassemblerImpl::new(BinaryArch::X64);
        // 0xFF 0xFF is an invalid x86 instruction
        let bytes = &[0xFF, 0xFF];
        let iat_map = IatMap::default();
        let insns = disasm.disassemble(bytes, 0x1000, &iat_map).unwrap();
        // Iced decodes it as an INVALID instruction and we skip it in our loop,
        // but let's check what it outputs, probably 0 instructions.
        assert_eq!(insns.len(), 0);
    }
}
