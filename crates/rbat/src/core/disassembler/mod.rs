//! # Disassembly Engine and Backend Abstractions
//!
//! Translates raw architecture-specific machine code bytes into structured sequences
//! of [`InstructionInfo`] for control-flow reconstruction, heuristic feature extraction,
//! FLIRT signature identification, and literal rule matching.
//!
//! ## Backend Architecture
//!
//! `rbat` provides two pluggable, mutually exclusive disassembly backends selectable
//! at compile time:
//!
//! - **Capstone** (`backend-capstone`, default): `x86`, `x64`, `ARM`, `ARM64`, C-library bindings via `capstone`, Broad multi-architecture binary analysis.
//! - **Iced-x86** (`backend-iced`): `x86`, `x64` Pure-Rust decoder via `iced-x86`, High-throughput x86/x64 analysis with bounded memory.
//!
//! ## Core Types
//!
//! - [`InstructionInfo`]: Unified, backend-agnostic representation of a disassembled machine instruction.
//! - [`DisassemblerImpl`]: Concrete disassembler engine configured for the active CPU architecture.
//!
//! ## Memory & Performance Characteristics
//!
//! - **Inlined String Storage**: Both instruction mnemonics and operands are cached in
//!   [`CompactString`] buffers. Up to 24 UTF-8 bytes are stored directly on the stack without
//!   heap allocation, eliminating dynamic allocation for >99% of x86 and ARM instructions.
//! - **SmallVec Pattern Tracking**: Matched Aho-Corasick pattern IDs are stored in an inline
//!   [`SmallVec<[PatternID; 8]>`], ensuring zero heap allocations for basic instructions.
//! - **Shared Symbol Storage**: Resolved import symbols are stored as [`Arc<str>`], sharing single
//!   heap allocations across all instructions calling the same IAT thunk.
//!
//! ## Examples
//!
//! ```rust
//! use compact_str::CompactString;
//! use smallvec::SmallVec;
//! use rbat::core::{
//!   cfg::InstructionClass,
//!   disassembler::InstructionInfo,
//! };
//!
//! let insn = InstructionInfo {
//!     address: 0x401000,
//!     mnemonic: CompactString::new("mov"),
//!     op_str: CompactString::new("eax, 0x1"),
//!     api_resolution: None,
//!     matched: SmallVec::new(),
//!     inst_class: InstructionClass::Normal,
//! };
//!
//! assert_eq!(insn.address(), 0x401000);
//! assert_eq!(insn.format_mnemonic(), "mov");
//! assert_eq!(insn.format_operands(), "eax, 0x1");
//! ```

use crate::core::{
    cfg::{ControlFlowGraph, InstructionClass},
    parser::BinaryArch,
};
use aho_corasick::PatternID;
use compact_str::CompactString;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::sync::Arc;

#[cfg(all(feature = "backend-capstone", feature = "backend-iced"))]
compile_error!(
    "Conflicting disassembly backends: `backend-capstone` and `backend-iced` are both enabled. \
     Pick exactly ONE — for the iced backend use \
     `cargo build --release --no-default-features --features backend-iced`."
);

#[cfg(not(any(feature = "backend-capstone", feature = "backend-iced")))]
compile_error!(
    "No disassembly backend selected: enable exactly one of \
     `backend-capstone` (default) or `backend-iced`."
);

#[cfg(feature = "backend-capstone")]
mod capstone_backend;
#[cfg(feature = "backend-capstone")]
pub use capstone_backend::DisassemblerImpl;

#[cfg(feature = "backend-iced")]
mod iced_backend;
#[cfg(feature = "backend-iced")]
pub use iced_backend::DisassemblerImpl;

/// A disassembled machine instruction with cached text representation and analysis metadata.
///
/// Serves as the primary unit of code representation across all `rbat` analysis stages,
/// including CFG basic block partitioning, FLIRT pattern matching, and rule evaluation.
///
/// # Examples
///
/// ```rust
/// use compact_str::CompactString;
/// use smallvec::SmallVec;
/// use rbat::core::{
///   cfg::InstructionClass,
///   disassembler::InstructionInfo,
/// };
///
/// let insn = InstructionInfo {
///     address: 0x401000,
///     mnemonic: CompactString::new("jmp"),
///     op_str: CompactString::new("0x401050"),
///     api_resolution: None,
///     matched: SmallVec::new(),
///     inst_class: InstructionClass::UnconditionalJump,
/// };
///
/// assert_eq!(insn.branch_target(), Some(0x401050));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstructionInfo {
    /// The virtual memory address of the instruction.
    pub address: u64,
    /// The normalized lowercase mnemonic string (e.g. `"mov"`, `"call"`, `"jmp"`).
    pub mnemonic: CompactString,
    /// The formatted operand string in Intel syntax (e.g. `"eax, ebx"`, `"0x1000"`).
    pub op_str: CompactString,
    /// Resolved import API name (e.g. `"VirtualAlloc"`) if this instruction references an IAT entry or thunk.
    pub api_resolution: Option<Arc<str>>,
    /// Pre-computed set of Aho-Corasick pattern IDs matched against this instruction's text.
    #[serde(skip)]
    pub matched: SmallVec<[PatternID; 8]>,
    /// Precise control-flow classification resolved during disassembly.
    pub inst_class: InstructionClass,
}

impl InstructionInfo {
    /// Returns the virtual memory address of this instruction.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use compact_str::CompactString;
    /// use smallvec::SmallVec;
    /// use rbat::core::{
    ///   cfg::InstructionClass,
    ///   disassembler::InstructionInfo,
    /// };
    ///
    /// let insn = InstructionInfo {
    ///     address: 0x00401000,
    ///     mnemonic: CompactString::new("nop"),
    ///     op_str: CompactString::new(""),
    ///     api_resolution: None,
    ///     matched: SmallVec::new(),
    ///     inst_class: InstructionClass::Normal,
    /// };
    /// assert_eq!(insn.address(), 0x00401000);
    /// ```
    #[inline]
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Returns a new lowercase formatted mnemonic string.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use compact_str::CompactString;
    /// use smallvec::SmallVec;
    /// use rbat::core::{
    ///   cfg::InstructionClass,
    ///   disassembler::InstructionInfo,
    /// };
    ///
    /// let insn = InstructionInfo {
    ///     address: 0x1000,
    ///     mnemonic: CompactString::new("xor"),
    ///     op_str: CompactString::new("eax, eax"),
    ///     api_resolution: None,
    ///     matched: SmallVec::new(),
    ///     inst_class: InstructionClass::Normal,
    /// };
    /// assert_eq!(insn.format_mnemonic(), "xor");
    /// ```
    #[inline]
    pub fn format_mnemonic(&self) -> String {
        self.mnemonic.to_string()
    }

    /// Returns a new formatted operand string.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use compact_str::CompactString;
    /// use smallvec::SmallVec;
    /// use rbat::core::{
    ///   cfg::InstructionClass,
    ///   disassembler::InstructionInfo,
    /// };
    ///
    /// let insn = InstructionInfo {
    ///     address: 0x1000,
    ///     mnemonic: CompactString::new("mov"),
    ///     op_str: CompactString::new("rcx, rdx"),
    ///     api_resolution: None,
    ///     matched: SmallVec::new(),
    ///     inst_class: InstructionClass::Normal,
    /// };
    /// assert_eq!(insn.format_operands(), "rcx, rdx");
    /// ```
    #[inline]
    pub fn format_operands(&self) -> String {
        self.op_str.to_string()
    }

    /// Writes the instruction mnemonic into a pre-allocated scratch buffer without heap allocations.
    ///
    /// # Parameters
    ///
    /// - `buf`: Mutable reference to the target [`String`] buffer. Cleared before appending.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use compact_str::CompactString;
    /// use smallvec::SmallVec;
    /// use rbat::core::{
    ///   cfg::InstructionClass,
    ///   disassembler::InstructionInfo,
    /// };
    ///
    /// let insn = InstructionInfo {
    ///     address: 0x1000,
    ///     mnemonic: CompactString::new("ret"),
    ///     op_str: CompactString::new(""),
    ///     api_resolution: None,
    ///     matched: SmallVec::new(),
    ///     inst_class: InstructionClass::Return,
    /// };
    ///
    /// let mut buf = String::new();
    /// insn.format_mnemonic_into(&mut buf);
    /// assert_eq!(buf, "ret");
    /// ```
    #[inline]
    pub fn format_mnemonic_into(&self, buf: &mut String) {
        buf.clear();
        buf.push_str(&self.mnemonic);
    }

    /// Writes the formatted operands into a pre-allocated scratch buffer without heap allocations.
    ///
    /// # Parameters
    ///
    /// - `buf`: Mutable reference to the target [`String`] buffer. Cleared before appending.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use compact_str::CompactString;
    /// use smallvec::SmallVec;
    /// use rbat::core::{
    ///   cfg::InstructionClass,
    ///   disassembler::InstructionInfo,
    /// };
    ///
    /// let insn = InstructionInfo {
    ///     address: 0x1000,
    ///     mnemonic: CompactString::new("sub"),
    ///     op_str: CompactString::new("rsp, 0x28"),
    ///     api_resolution: None,
    ///     matched: SmallVec::new(),
    ///     inst_class: InstructionClass::Normal,
    /// };
    ///
    /// let mut buf = String::new();
    /// insn.format_operands_into(&mut buf);
    /// assert_eq!(buf, "rsp, 0x28");
    /// ```
    #[inline]
    pub fn format_operands_into(&self, buf: &mut String) {
        buf.clear();
        buf.push_str(&self.op_str);
    }

    /// Extracts the direct branch target virtual address from operand text, if applicable.
    ///
    /// Returns `Some(addr)` for direct jumps and calls with explicit hex (`0x...`) or decimal
    /// targets, or `None` for register-indirect branches, non-branch instructions, or complex expressions.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use compact_str::CompactString;
    /// use smallvec::SmallVec;
    /// use rbat::core::{
    ///   cfg::InstructionClass,
    ///   disassembler::InstructionInfo,
    /// };
    ///
    /// let insn = InstructionInfo {
    ///     address: 0x1000,
    ///     mnemonic: CompactString::new("call"),
    ///     op_str: CompactString::new("0x402000"),
    ///     api_resolution: None,
    ///     matched: SmallVec::new(),
    ///     inst_class: InstructionClass::Call,
    /// };
    /// assert_eq!(insn.branch_target(), Some(0x402000));
    /// ```
    #[inline]
    pub fn branch_target(&self) -> Option<u64> {
        ControlFlowGraph::parse_target_addr(&self.op_str)
    }

    /// Returns this instruction's control-flow classification.
    ///
    /// The classification is pre-resolved during disassembly from backend instruction detail
    /// or flow-control descriptors, disambiguating calls, returns, conditional jumps, and unconditional jumps.
    ///
    /// # Parameters
    ///
    /// - `_arch`: Reference to [`BinaryArch`]. Kept for API compatibility; classification is pre-computed.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use compact_str::CompactString;
    /// use smallvec::SmallVec;
    /// use rbat::core::{
    ///   cfg::InstructionClass,
    ///   disassembler::InstructionInfo,
    ///   parser::BinaryArch,
    /// };
    ///
    /// let insn = InstructionInfo {
    ///     address: 0x1000,
    ///     mnemonic: CompactString::new("ret"),
    ///     op_str: CompactString::new(""),
    ///     api_resolution: None,
    ///     matched: SmallVec::new(),
    ///     inst_class: InstructionClass::Return,
    /// };
    /// assert_eq!(insn.class(&BinaryArch::X64), InstructionClass::Return);
    /// ```
    #[inline]
    pub fn class(&self, _arch: &BinaryArch) -> InstructionClass {
        self.inst_class
    }
}
