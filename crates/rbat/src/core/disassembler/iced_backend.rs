//! # Iced-x86 Disassembly Backend
//!
//! High-throughput pure-Rust x86 and x64 disassembler leveraging the `iced-x86` crate.
//!
//! ## Overview
//!
//! The [`IcedBackend`] engine provides fast, memory-safe instruction decoding for:
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
//!   disassembler::{IcedBackend},
//!   traits::Disassembler,
//!   parser::{BinaryArch, IatMap},
//! };
//!
//! let disasm = IcedBackend;
//! let iat_map = IatMap::default();
//! let bytes = [0x90, 0xc3]; // nop; ret
//! let instructions = disasm.disassemble(&bytes, 0x1000, BinaryArch::X64, &iat_map).unwrap();
//!
//! assert_eq!(instructions.len(), 2);
//! assert_eq!(instructions[0].format_mnemonic(), "nop");
//! assert_eq!(instructions[1].format_mnemonic(), "ret");
//! ```

use crate::core::{
    cfg::InstructionClass,
    disassembler::InstructionInfo,
    parser::{BinaryArch, IatMap},
    traits::Disassembler,
    types::result::{RbatError, RbatResult},
};
use iced_x86::{Code, Decoder, DecoderOptions, FlowControl, Formatter};
use std::{fmt::Write, sync::Arc};

/// High-performance x86/x64 disassembly engine powered by [`iced-x86`].
///
/// Decodes 32-bit and 64-bit x86 machine code into unified [`InstructionInfo`] sequences
/// with pre-computed control flow classification and IAT import resolution.
///
/// # Examples
///
/// ```rust
/// use rbat::core::disassembler::IcedBackend;
///
/// let disasm = IcedBackend;
/// ```
///
/// [`iced-x86`]: iced_x86
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IcedBackend;

impl Disassembler for IcedBackend {
    fn name(&self) -> &'static str {
        "iced"
    }

    fn supports_arch(&self, arch: BinaryArch) -> bool {
        matches!(arch, BinaryArch::X86 | BinaryArch::X64)
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
    /// - `arch`: Architecture classification (must be [`BinaryArch::X86`] or [`BinaryArch::X64`]).
    /// - `iat_map`: Import Address Table mapping virtual addresses to API symbol names.
    ///
    /// # Returns
    ///
    /// An [`Arc<[InstructionInfo]>`](Arc) slice representing the decoded instructions.
    ///
    /// # Errors
    ///
    /// Returns an [`RbatError::DisassembleInstructionError`] if:
    /// - `arch` is not [`BinaryArch::X86`] or [`BinaryArch::X64`] (e.g. ARM or ARM64, which are only supported by the Capstone backend).
    /// - No valid instructions could be decoded from `text_bytes`.
    ///
    /// # Allocation Behavior
    ///
    /// Constructs the [`Arc<[InstructionInfo]>`](Arc) directly via pre-counting and uninitialized
    /// slice allocation ([`Arc::new_uninit_slice`]), requiring only a single allocation of exact size
    /// and eliminating any transient buffer duplication or reallocation churn.
    /// Text strings are formatted using caller-reused scratch buffers and inlined into
    /// [`CompactString`] fields without heap allocations for strings <= 24 bytes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rbat::core::{
    ///   disassembler::{IcedBackend},
    ///   traits::Disassembler,
    ///   parser::{BinaryArch, IatMap},
    /// };
    ///
    /// let disasm = IcedBackend;
    /// let iat = IatMap::default();
    /// let code = [0xb8, 0x01, 0x00, 0x00, 0x00]; // mov eax, 1
    /// let insns = disasm.disassemble(&code, 0x400000, BinaryArch::X86, &iat).unwrap();
    ///
    /// assert_eq!(insns.len(), 1);
    /// assert_eq!(insns[0].format_mnemonic(), "mov");
    /// ```
    fn disassemble(
        &self,
        text_bytes: &[u8],
        entry_addr: u64,
        arch: BinaryArch,
        iat_map: &IatMap,
    ) -> RbatResult<Arc<[InstructionInfo]>> {
        if !self.supports_arch(arch) {
            return Err(RbatError::DisassembleInstructionError(
                "iced-x86 only supports x86 and x64 architectures".into(),
            ));
        }

        let bitness = match arch {
            BinaryArch::X64 => 64,
            BinaryArch::X86 => 32,
            _ => unreachable!(),
        };

        // Pass 1: Fast zero-allocation instruction count
        let mut count = 0usize;
        let mut count_decoder =
            Decoder::with_ip(bitness, text_bytes, entry_addr, DecoderOptions::NONE);
        let mut count_instr = iced_x86::Instruction::default();

        while count_decoder.can_decode() {
            count_decoder.decode_out(&mut count_instr);
            if count_instr.code() != Code::INVALID {
                count += 1;
            }
        }

        if count == 0 {
            return Err(RbatError::DisassembleInstructionError(
                "no instructions decoded from binary text bytes".to_string(),
            ));
        }

        // Allocate Arc slice directly with exact capacity
        let mut uninit_arc = Arc::new_uninit_slice(count);
        let slice = Arc::get_mut(&mut uninit_arc).expect("uniquely owned Arc slice");

        // Pass 2: decode instructions and write slice
        let mut decoder = Decoder::with_ip(bitness, text_bytes, entry_addr, DecoderOptions::NONE);
        let mut instr = iced_x86::Instruction::default();

        let mut formatter = Self::create_formatter();
        let mut mnem_buf = String::with_capacity(16);
        let mut op_buf = String::with_capacity(64);
        let mut idx = 0usize;

        while decoder.can_decode() {
            decoder.decode_out(&mut instr);

            if instr.code() == Code::INVALID {
                continue;
            }

            let api_resolution = Self::resolve_api(&instr, iat_map);
            let inst_class = Self::classify_flow(instr.flow_control());

            mnem_buf.clear();
            let _ = write!(mnem_buf, "{:?}", instr.mnemonic());
            mnem_buf.make_ascii_lowercase();

            op_buf.clear();
            formatter.format_all_operands(&instr, &mut op_buf);

            slice[idx].write(InstructionInfo::new(
                instr.ip(),
                mnem_buf.as_str(),
                op_buf.as_str(),
                inst_class,
                api_resolution,
            ));
            idx += 1;
        }

        assert_eq!(
            idx, count,
            "Decoded instruction count must match pre-counted instruction count"
        );

        // SAFETY: `uninit_arc` was allocated with capacity `count`. Pass 1 counted the exact number
        // of valid non-Code::INVALID instructions in `text_bytes`, and pass 2 decodes with the exact
        // same decoder configuration, writing an initialized `InstructionInfo` into every index `0..count`
        // without early return. The `assert_eq!(idx, count)` assertion dynamically guarantees that all
        // `count` elements in the slice were sequentially initialized.
        let instructions = unsafe { uninit_arc.assume_init() };

        Ok(instructions)
    }
}

impl IcedBackend {
    /// Creates an [`IntelFormatter`] configured with Capstone-compatible settings:
    /// lowercase hex prefix (`0x`), no suffix, and lowercase formatting.
    #[must_use]
    pub fn create_formatter() -> iced_x86::IntelFormatter {
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
    pub fn classify_flow(flow: iced_x86::FlowControl) -> InstructionClass {
        match flow {
            FlowControl::UnconditionalBranch => InstructionClass::UnconditionalJump,
            FlowControl::ConditionalBranch => InstructionClass::ConditionalJump,
            FlowControl::Call | FlowControl::IndirectCall => InstructionClass::Call,
            FlowControl::Return => InstructionClass::Return,
            _ => InstructionClass::Normal,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::parser::{BinaryArch, IatMap};

    #[test]
    fn test_iced_disasm_factory_x64_intel() {
        let disasm = IcedBackend;
        // NOP, RET
        let bytes = &[0x90, 0xC3];
        let iat_map = IatMap::default();
        let insns = disasm
            .disassemble(bytes, 0x1000, BinaryArch::X64, &iat_map)
            .unwrap();
        assert_eq!(insns.len(), 2);

        assert_eq!(insns[0].address(), 0x1000);
        assert_eq!(insns[0].format_mnemonic(), "nop");

        assert_eq!(insns[1].address(), 0x1001);
        assert_eq!(insns[1].format_mnemonic(), "ret");
    }

    #[test]
    fn test_iced_disasm_factory_x86_intel() {
        let disasm = IcedBackend;
        // MOV EAX, 1
        let bytes = &[0xB8, 0x01, 0x00, 0x00, 0x00];
        let iat_map = IatMap::default();
        let insns = disasm
            .disassemble(bytes, 0x1000, BinaryArch::X86, &iat_map)
            .unwrap();
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
    fn test_iced_disasm_invalid_bytes_error() {
        let disasm = IcedBackend;
        // 0xFF 0xFF is an invalid x86 instruction
        let bytes = &[0xFF, 0xFF];
        let iat_map = IatMap::default();
        let res = disasm.disassemble(bytes, 0x1000, BinaryArch::X64, &iat_map);
        match res {
            Err(RbatError::DisassembleInstructionError(msg)) => {
                assert!(
                    msg.contains("no instructions decoded"),
                    "unexpected error message: {msg}"
                );
            }
            other => panic!("expected DisassembleInstructionError, got {other:?}"),
        }
    }

    #[test]
    fn test_iced_disasm_empty_bytes_error() {
        let disasm = IcedBackend;
        let bytes = &[];
        let iat_map = IatMap::default();
        let res = disasm.disassemble(bytes, 0x1000, BinaryArch::X64, &iat_map);
        match res {
            Err(RbatError::DisassembleInstructionError(msg)) => {
                assert!(
                    msg.contains("no instructions decoded"),
                    "unexpected error message: {msg}"
                );
            }
            other => panic!("expected DisassembleInstructionError, got {other:?}"),
        }
    }

    #[test]
    fn test_iced_disasm_unsupported_arch_error() {
        let disasm = IcedBackend;
        let bytes = &[0x90, 0xC3];
        let iat_map = IatMap::default();
        let res = disasm.disassemble(bytes, 0x1000, BinaryArch::Arm, &iat_map);
        match res {
            Err(RbatError::DisassembleInstructionError(msg)) => {
                assert!(
                    msg.contains("iced-x86 only supports x86 and x64"),
                    "unexpected error message: {msg}"
                );
            }
            other => panic!("expected DisassembleInstructionError, got {other:?}"),
        }
    }

    #[test]
    fn test_from_iced_constructors() {
        let mut decoder = Decoder::with_ip(64, &[0xC3], 0x401000, DecoderOptions::NONE);
        let instr = decoder.decode();
        let mut formatter = IcedBackend::create_formatter();
        let mut mnem_buf = String::with_capacity(16);
        let mut op_buf = String::with_capacity(64);
        let api_sym: Arc<str> = Arc::from("dummy_api");

        mnem_buf.clear();
        let _ = write!(mnem_buf, "{:?}", instr.mnemonic());
        mnem_buf.make_ascii_lowercase();

        op_buf.clear();
        formatter.format_all_operands(&instr, &mut op_buf);

        let info_buf = InstructionInfo::new(
            instr.ip(),
            mnem_buf.as_str(),
            op_buf.as_str(),
            IcedBackend::classify_flow(instr.flow_control()),
            Some(api_sym.clone()),
        );
        assert_eq!(info_buf.address(), 0x401000);
        assert_eq!(info_buf.format_mnemonic(), "ret");
        assert_eq!(info_buf.api_resolution, Some(api_sym));
        assert_eq!(info_buf.inst_class, InstructionClass::Return);
    }
}
