//! # Disassembly Engine and Backend Abstractions
//!
//! Translates raw architecture-specific machine code bytes into structured sequences
//! of [`InstructionInfo`] for control-flow reconstruction, heuristic feature extraction,
//! FLIRT signature identification, and literal rule matching.
//!
//! ## Backend Architecture
//!
//! `rbat` provides pluggable disassembly backends with runtime selection via [`DisassemblerBackend`]:
//!
//! - **Capstone** (`backend-capstone`, default): `x86`, `x64`, `ARM`, `ARM64`, C-library bindings via `capstone`, Broad multi-architecture binary analysis.
//! - **Iced-x86** (`backend-iced`): `x86`, `x64` Pure-Rust decoder via `iced-x86`, High-throughput x86/x64 analysis with bounded memory.
//! - **Custom**: User-provided disassembler engines implementing the [`Disassembler`] trait.
//!
//! ## Core Types
//!
//! - [`InstructionInfo`]: Unified, backend-agnostic representation of a disassembled machine instruction.
//! - [`Disassembler`]: Common trait implemented by disassembler engines.
//! - [`DisassemblerBackend`]: Runtime backend selector using enum dispatch for zero-cost abstraction.
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
//! use rbat::core::{
//!   cfg::InstructionClass,
//!   disassembler::InstructionInfo,
//! };
//!
//! let insn = InstructionInfo::new(
//!     0x401000,
//!     "mov",
//!     "eax, 0x1",
//!     InstructionClass::Normal,
//!     None,
//! );
//!
//! assert_eq!(insn.address(), 0x401000);
//! assert_eq!(insn.format_mnemonic(), "mov");
//! assert_eq!(insn.format_operands(), "eax, 0x1");
//! ```

use crate::core::{
    cfg::{ControlFlowGraph, InstructionClass},
    parser::{BinaryArch, IatMap},
    traits::Disassembler,
    types::result::RbatResult,
};
use aho_corasick::PatternID;
use compact_str::CompactString;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::sync::Arc;

#[cfg(not(any(feature = "backend-capstone", feature = "backend-iced")))]
compile_error!(
    "No disassembly backend selected: enable at least one of \
     `backend-capstone` or `backend-iced`."
);

#[cfg(feature = "backend-capstone")]
pub mod capstone_backend;
#[cfg(feature = "backend-capstone")]
pub use capstone_backend::CapstoneBackend;

#[cfg(feature = "backend-iced")]
pub mod iced_backend;
#[cfg(feature = "backend-iced")]
pub use iced_backend::IcedBackend;

/// Runtime disassembler backend selector using enum dispatch.
#[derive(Clone, Default, Debug)]
pub enum DisassemblerBackend {
    /// Multi-architecture Capstone C-library disassembler backend.
    #[cfg(feature = "backend-capstone")]
    #[default]
    Capstone,
    /// High-throughput pure-Rust iced-x86 disassembler backend.
    #[cfg(feature = "backend-iced")]
    Iced,
    /// Custom user-provided disassembler implementation.
    Custom(Arc<dyn Disassembler>),
}

impl Disassembler for DisassemblerBackend {
    fn disassemble(
        &self,
        text_bytes: &[u8],
        entry_addr: u64,
        arch: BinaryArch,
        iat_map: &IatMap,
    ) -> RbatResult<Arc<[InstructionInfo]>> {
        match self {
            #[cfg(feature = "backend-capstone")]
            DisassemblerBackend::Capstone => {
                CapstoneBackend.disassemble(text_bytes, entry_addr, arch, iat_map)
            }
            #[cfg(feature = "backend-iced")]
            DisassemblerBackend::Iced => {
                IcedBackend.disassemble(text_bytes, entry_addr, arch, iat_map)
            }
            DisassemblerBackend::Custom(custom) => {
                custom.disassemble(text_bytes, entry_addr, arch, iat_map)
            }
        }
    }

    fn supports_arch(&self, arch: BinaryArch) -> bool {
        match self {
            #[cfg(feature = "backend-capstone")]
            DisassemblerBackend::Capstone => CapstoneBackend.supports_arch(arch),
            #[cfg(feature = "backend-iced")]
            DisassemblerBackend::Iced => IcedBackend.supports_arch(arch),
            DisassemblerBackend::Custom(custom) => custom.supports_arch(arch),
        }
    }

    fn name(&self) -> &'static str {
        match self {
            #[cfg(feature = "backend-capstone")]
            DisassemblerBackend::Capstone => "capstone",
            #[cfg(feature = "backend-iced")]
            DisassemblerBackend::Iced => "iced",
            DisassemblerBackend::Custom(custom) => custom.name(),
        }
    }
}

impl DisassemblerBackend {
    /// Wraps a custom disassembler implementation into a [`DisassemblerBackend::Custom`].
    pub fn custom<D: Disassembler + 'static>(disassembler: D) -> Self {
        Self::Custom(Arc::new(disassembler))
    }
}

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
    /// Creates a new disassembled instruction with specified operands, control flow class,
    /// and optional resolved IAT API symbol.
    ///
    /// Initializes `matched` with an empty inline [`SmallVec`] for downstream Aho-Corasick tracking.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rbat::core::{
    ///   cfg::InstructionClass,
    ///   disassembler::InstructionInfo,
    /// };
    ///
    /// let insn = InstructionInfo::new(
    ///     0x401000,
    ///     "mov",
    ///     "eax, 1",
    ///     InstructionClass::Normal,
    ///     None,
    /// );
    /// assert_eq!(insn.address(), 0x401000);
    /// assert_eq!(insn.format_mnemonic(), "mov");
    /// assert_eq!(insn.format_operands(), "eax, 1");
    /// ```
    #[inline]
    pub fn new(
        address: u64,
        mnemonic: impl Into<CompactString>,
        op_str: impl Into<CompactString>,
        inst_class: InstructionClass,
        api_resolution: Option<Arc<str>>,
    ) -> Self {
        Self {
            address,
            mnemonic: mnemonic.into(),
            op_str: op_str.into(),
            api_resolution,
            matched: SmallVec::new(),
            inst_class,
        }
    }

    /// Creates a new disassembled instruction, automatically classifying its control flow
    /// class from its mnemonic and the target architecture.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rbat::core::{
    ///   cfg::InstructionClass,
    ///   disassembler::InstructionInfo,
    ///   parser::BinaryArch,
    /// };
    ///
    /// let insn = InstructionInfo::with_classified_flow(
    ///     0x401000,
    ///     "ret",
    ///     "",
    ///     &BinaryArch::X64,
    ///     None,
    /// );
    /// assert_eq!(insn.inst_class, InstructionClass::Return);
    /// ```
    #[inline]
    pub fn with_classified_flow(
        address: u64,
        mnemonic: impl Into<CompactString>,
        op_str: impl Into<CompactString>,
        arch: &BinaryArch,
        api_resolution: Option<Arc<str>>,
    ) -> Self {
        let mnemonic = mnemonic.into();
        let inst_class = InstructionClass::classify(&mnemonic, arch);
        Self::new(address, mnemonic, op_str, inst_class, api_resolution)
    }

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
