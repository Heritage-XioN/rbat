//! # Iced-x86 Disassembly Backend
//!
//! High-throughput pure-Rust x86 and x64 disassembler leveraging the `iced-x86` crate.
//!
//! ## Overview
//!
//! The [`DisassemblerImpl`] engine provides fast, memory-safe instruction decoding for:
//! - `x86` (32-bit protected mode)
//! - `x64` (64-bit long mode)
//!
//! All instructions are decoded directly into unified [`InstructionInfo`] structs, formatting
//! operands using Intel syntax with lowercase hexadecimal values (`0x...`) to ensure strict
//! parity with capa rule evaluation and Capstone output.
//!
//! ## Memory & Allocation Bounds
//!
//! - **Bounded Pre-allocation**: The instruction vector is pre-allocated up to a maximum
//!   safety cap of `MAX_PREALLOC_BYTES` (8 MiB, ~131,000 instructions) based on the heuristic
//!   `min(text_bytes.len() / 4, cap)`. Malformed or adversarial binaries with huge `.text`
//!   virtual sizes cannot trigger unbounded upfront allocation.
//! - **Decode-Time Inlining**: Operands and mnemonics are formatted directly into reusable
//!   scratch buffers and stored inside inline [`CompactString`] fields. This eliminates dynamic
//!   re-formatting across downstream analysis threads (such as parallel CFG reconstruction).
//! - **Zero Foreign Allocations**: Unlike C-based disassemblers, `iced-x86` performs zero heap
//!   allocations inside the decoder core.
//!
//! ## Resilient Decoding
//!
//! The decoder steps linearly through `text_bytes`. Invalid instructions (`Code::INVALID`)
//! are skipped, allowing disassembly to recover after data alignment padding, embedded tables,
//! or non-code bytes.
//!
//! ## Examples
//!
//! ```rust
//! use rbat::core::{
//!   disassembler::DisassemblerImpl,
//!   parser::{BinaryArch, IatMap},
//! };
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
use crate::core::{
    cfg::InstructionClass,
    parser::{BinaryArch, IatMap},
    types::result::{RbatError, RbatResult},
};
use compact_str::CompactString;
use iced_x86::{Code, Decoder, DecoderOptions, FlowControl, Formatter};
use smallvec::SmallVec;
use std::{fmt::Write, sync::Arc};

/// High-performance x86/x64 disassembly engine powered by [`iced-x86`].
///
/// Decodes 32-bit and 64-bit x86 machine code into unified [`InstructionInfo`] sequences
/// with pre-computed control flow classification and IAT import resolution.
///
/// # Examples
///
/// ```rust
/// use rbat::core::disassembler::DisassemblerImpl;
/// use rbat::core::parser::BinaryArch;
///
/// let disasm = DisassemblerImpl::new(BinaryArch::X64);
/// ```
///
/// [`iced-x86`]: iced_x86
#[derive(Debug)]
pub struct DisassemblerImpl {
    arch: BinaryArch,
}

impl DisassemblerImpl {
    /// Creates a new iced-x86 [`DisassemblerImpl`] configured for the specified [`BinaryArch`].
    ///
    /// # Parameters
    ///
    /// - `arch`: Target architecture (must be [`BinaryArch::X86`] or [`BinaryArch::X64`]).
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

    /// Creates an [`IntelFormatter`] configured with Capstone-compatible settings:
    /// lowercase hex prefix (`0x`), no suffix, and lowercase formatting.
    #[must_use]
    fn create_formatter() -> iced_x86::IntelFormatter {
        let mut formatter = iced_x86::IntelFormatter::new();
        formatter.options_mut().set_hex_prefix("0x");
        formatter.options_mut().set_hex_suffix("");
        formatter.options_mut().set_uppercase_hex(false);
        formatter
    }

    /// Resolves direct branch targets or memory displacements against `iat_map` for imported API detection.
    #[inline]
    fn resolve_api(instr: &iced_x86::Instruction, iat_map: &IatMap) -> Option<Arc<str>> {
        let target = instr.near_branch64();
        if target != 0
            && let Some(api) = iat_map.get(&target)
        {
            return Some(api.clone());
        }
        let disp = instr.memory_displacement64();
        if disp != 0
            && let Some(api) = iat_map.get(&disp)
        {
            return Some(api.clone());
        }
        None
    }

    /// Decodes and disassembles all x86/x64 instructions in the provided byte slice.
    ///
    /// Uses an `iced_x86::Decoder` configured for 32-bit or 64-bit execution mode.
    /// Resolves direct branch targets and memory displacements against `iat_map` for imported API detection,
    /// formats operands into normalized Intel syntax, and classifies control flow.
    ///
    /// # Parameters
    ///
    /// - `text_bytes`: Raw executable machine code bytes.
    /// - `entry_addr`: Virtual memory base address corresponding to the start of `text_bytes`.
    /// - `iat_map`: Import Address Table mapping virtual addresses to API symbol names.
    ///
    /// # Returns
    ///
    /// A vector of [`InstructionInfo`] structs representing the decoded instructions.
    ///
    /// # Errors
    ///
    /// Returns an [`RbatError::DisassembleInstructionError`] if `self.arch` is not [`BinaryArch::X86`]
    /// or [`BinaryArch::X64`] (e.g. ARM or ARM64, which are only supported by the Capstone backend).
    ///
    /// # Allocation Behavior
    ///
    /// The returned `Vec<InstructionInfo>` is pre-allocated up to `MAX_PREALLOC_BYTES` (8 MiB)
    /// based on the heuristic `min(text_bytes.len() / 4, cap)` to mitigate initial allocation churn.
    /// If dynamic reallocations occur during disassembly of large binaries, [`Vec::shrink_to_fit`]
    /// is invoked prior to returning to immediately release any exponential doubling overcapacity,
    /// guaranteeing that returned vectors hold zero unused memory slots.
    /// Text strings are formatted using caller-reused scratch buffers and inlined into
    /// [`CompactString`] fields without heap allocations for strings <= 24 bytes.
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
        let bitness = match self.arch {
            BinaryArch::X64 => 64,
            BinaryArch::X86 => 32,
            _ => {
                return Err(RbatError::DisassembleInstructionError(
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

        let mut formatter = Self::create_formatter();
        let mut mnem_buf = String::with_capacity(16);
        let mut op_buf = String::with_capacity(64);

        while decoder.can_decode() {
            decoder.decode_out(&mut instr);

            if instr.code() == Code::INVALID {
                continue;
            }

            let api_resolution = Self::resolve_api(&instr, iat_map);
            instructions.push(InstructionInfo::from_iced(
                &instr,
                &mut formatter,
                &mut mnem_buf,
                &mut op_buf,
                api_resolution,
            ));
        }

        instructions.shrink_to_fit();

        Ok(instructions)
    }

    /// Maps an `iced_x86::FlowControl` descriptor to an [`InstructionClass`].
    ///
    /// Disambiguates unconditional branches, conditional branches, calls, and returns
    /// from normal sequential execution flow.
    ///
    /// # Parameters
    ///
    /// - `flow`: The flow control classification provided by `iced-x86`.
    ///
    /// # Returns
    ///
    /// The corresponding [`InstructionClass`].
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

impl InstructionInfo {
    /// High-throughput constructor reusing caller-allocated scratch buffers and formatter.
    ///
    /// Avoids dynamic memory allocations in tight disassembly loops while ensuring consistent
    /// control-flow classification and string inlining.
    ///
    /// # Parameters
    ///
    /// - `instr`: Reference to the native [`iced_x86::Instruction`].
    /// - `formatter`: Mutable reference to the configured [`iced_x86::IntelFormatter`].
    /// - `mnem_buf`: Scratch buffer for mnemonic formatting. Cleared before use.
    /// - `op_buf`: Scratch buffer for operand formatting. Cleared before use.
    /// - `api_resolution`: Optional [`Arc<str>`] representing an imported API resolved from IAT.
    fn from_iced(
        instr: &iced_x86::Instruction,
        formatter: &mut iced_x86::IntelFormatter,
        mnem_buf: &mut String,
        op_buf: &mut String,
        api_resolution: Option<Arc<str>>,
    ) -> Self {
        mnem_buf.clear();
        let _ = write!(mnem_buf, "{:?}", instr.mnemonic());
        mnem_buf.make_ascii_lowercase();

        op_buf.clear();
        formatter.format_all_operands(instr, op_buf);

        let inst_class = DisassemblerImpl::classify_flow(instr.flow_control());

        InstructionInfo {
            address: instr.ip(),
            mnemonic: CompactString::new(mnem_buf.as_str()),
            op_str: CompactString::new(op_buf.as_str()),
            api_resolution,
            matched: SmallVec::new(),
            inst_class,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::parser::{BinaryArch, IatMap};

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
    fn test_iced_disasm_factory_x86_intel() {
        let disasm = DisassemblerImpl::new(BinaryArch::X86);
        // MOV EAX, 1
        let bytes = &[0xB8, 0x01, 0x00, 0x00, 0x00];
        let iat_map = IatMap::default();
        let insns = disasm.disassemble(bytes, 0x1000, &iat_map).unwrap();
        assert_eq!(insns.len(), 1);

        assert_eq!(insns[0].address(), 0x1000);
        assert_eq!(insns[0].format_mnemonic(), "mov");
        // Intel format
        let op_str = insns[0].format_operands();
        assert!(
            op_str.contains("eax") || op_str.contains("1"),
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
        assert_eq!(insns.len(), 0);
    }

    #[test]
    fn test_from_iced_constructors() {
        let mut decoder = Decoder::with_ip(64, &[0xC3], 0x401000, DecoderOptions::NONE);
        let instr = decoder.decode();
        // High-throughput constructor with reusable buffers
        let mut formatter = DisassemblerImpl::create_formatter();
        let mut mnem_buf = String::with_capacity(16);
        let mut op_buf = String::with_capacity(64);
        let api_sym: Arc<str> = Arc::from("dummy_api");
        let info_buf = InstructionInfo::from_iced(
            &instr,
            &mut formatter,
            &mut mnem_buf,
            &mut op_buf,
            Some(api_sym.clone()),
        );
        assert_eq!(info_buf.address(), 0x401000);
        assert_eq!(info_buf.format_mnemonic(), "ret");
        assert_eq!(info_buf.api_resolution, Some(api_sym));
        assert_eq!(info_buf.inst_class, InstructionClass::Return);
    }
}
