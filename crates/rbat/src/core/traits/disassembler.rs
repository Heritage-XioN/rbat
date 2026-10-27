//! # Disassembler Trait Abstractions
//!
//! Provides the [`Disassembler`] trait for integrating built-in and custom disassembler engines.
//!
//! ## Core Traits
//!
//! - [`Disassembler`]: Common interface for decoding raw machine code into structured [`InstructionInfo`] slices.
//!
//! ## Overview
//!
//! The [`Disassembler`] trait abstracts architecture-specific linear instruction decoders.
//! Built-in implementations include [`CapstoneBackend`] (multi-architecture C bindings) and [`IcedBackend`] (pure-Rust x86/x64).
//! Implementing this trait allows developers to supply custom or third-party disassembly engines to the
//! [`Analyzer`] pipeline via [`DisassemblerBackend::custom`].
//!
//! ## Examples
//!
//! Querying architecture support on a disassembler:
//!
//! ```rust
//! use rbat::core::{
//!   traits::Disassembler,
//!   disassembler::IcedBackend,
//!   parser::BinaryArch,
//! };
//!
//! let disasm = IcedBackend;
//! assert!(disasm.supports_arch(BinaryArch::X64));
//! assert!(!disasm.supports_arch(BinaryArch::Arm));
//! assert_eq!(disasm.name(), "iced");
//! ```
//!
//! [`CapstoneBackend`]: crate::core::disassembler::CapstoneBackend
//! [`IcedBackend`]: crate::core::disassembler::IcedBackend
//! [`Analyzer`]: crate::core::analyzer::Analyzer
//! [`DisassemblerBackend::custom`]: crate::core::disassembler::DisassemblerBackend::custom

use std::{fmt::Debug, sync::Arc};

use crate::core::{
    disassembler::InstructionInfo,
    parser::{BinaryArch, IatMap},
    types::result::RbatResult,
};

/// Interface for architecture-specific or custom disassembler engines.
///
/// Implemented by instruction decoding engines to translate raw executable machine code bytes into
/// structured sequences of [`InstructionInfo`]. Engines must be thread-safe ([`Send`] + [`Sync`])
/// to support concurrent analysis across multiple threads.
///
/// Both built-in engines ([`CapstoneBackend`] and [`IcedBackend`] and user-defined engines implement this trait.
/// Pointer types [`Arc<dyn Disassembler>`] and [`Box<dyn Disassembler>`] also implement `Disassembler`
/// transparently.
///
/// # Examples
///
/// ```rust
/// use rbat::core::traits::Disassembler;
/// use rbat::core::disassembler::CapstoneBackend;
/// use rbat::core::parser::{BinaryArch, IatMap};
///
/// let disasm = CapstoneBackend;
/// let iat_map = IatMap::default();
/// let bytes = [0x90, 0xc3]; // nop; ret
/// let instructions = disasm.disassemble(&bytes, 0x1000, BinaryArch::X64, &iat_map).unwrap();
/// assert_eq!(instructions.len(), 2);
/// ```
///
/// [`CapstoneBackend`]: crate::core::disassembler::CapstoneBackend
/// [`IcedBackend`]: crate::core::disassembler::IcedBackend
pub trait Disassembler: Send + Sync + Debug {
    /// Disassembles machine code from `text_bytes` starting at `entry_addr` for the given architecture.
    ///
    /// Decodes linear instruction streams, normalizes mnemonic and operand text into Intel syntax,
    /// queries `iat_map` for imported API resolution, and assigns control-flow classifications.
    ///
    /// # Parameters
    ///
    /// - `text_bytes`: Raw executable machine code bytes (typically from `.text` or executable section).
    /// - `entry_addr`: Virtual memory base address corresponding to the start of `text_bytes`.
    /// - `arch`: Target binary CPU architecture ([`BinaryArch`]).
    /// - `iat_map`: Import Address Table mapping virtual addresses or displacements to API symbol names.
    ///
    /// # Returns
    ///
    /// An [`Arc<[InstructionInfo]>`](Arc) slice containing decoded instructions in linear execution order.
    ///
    /// # Errors
    ///
    /// Returns an [`RbatError`] if:
    /// - The requested `arch` is unsupported by this disassembler.
    /// - Linear instruction decoding fails fatally.
    /// - No valid instructions could be decoded from `text_bytes` ([`RbatError::DisassembleInstructionError`]).
    /// 
    /// [`RbatError`]: crate::core::types::result::RbatError
    /// [`RbatError::DisassembleInstructionError`]: crate::core::types::result::RbatError::DisassembleInstructionError
    fn disassemble(
        &self,
        text_bytes: &[u8],
        entry_addr: u64,
        arch: BinaryArch,
        iat_map: &IatMap,
    ) -> RbatResult<Arc<[InstructionInfo]>>;

    /// Returns whether this disassembler supports the given binary architecture.
    ///
    /// # Parameters
    ///
    /// - `arch`: Architecture classification to test.
    ///
    /// # Returns
    ///
    /// `true` if this disassembler can decode machine code for `arch`, `false` otherwise.
    fn supports_arch(&self, _arch: BinaryArch) -> bool {
        true
    }

    /// Returns a human-readable identifier for this disassembler backend.
    ///
    /// # Returns
    ///
    /// Static string slice naming the disassembler engine (e.g. `"capstone"`, `"iced"`).
    fn name(&self) -> &'static str;
}

impl<D: Disassembler + ?Sized> Disassembler for Arc<D> {
    fn disassemble(
        &self,
        text_bytes: &[u8],
        entry_addr: u64,
        arch: BinaryArch,
        iat_map: &IatMap,
    ) -> RbatResult<Arc<[InstructionInfo]>> {
        (**self).disassemble(text_bytes, entry_addr, arch, iat_map)
    }

    fn supports_arch(&self, arch: BinaryArch) -> bool {
        (**self).supports_arch(arch)
    }

    fn name(&self) -> &'static str {
        (**self).name()
    }
}

impl<D: Disassembler + ?Sized> Disassembler for Box<D> {
    fn disassemble(
        &self,
        text_bytes: &[u8],
        entry_addr: u64,
        arch: BinaryArch,
        iat_map: &IatMap,
    ) -> RbatResult<Arc<[InstructionInfo]>> {
        (**self).disassemble(text_bytes, entry_addr, arch, iat_map)
    }

    fn supports_arch(&self, arch: BinaryArch) -> bool {
        (**self).supports_arch(arch)
    }

    fn name(&self) -> &'static str {
        (**self).name()
    }
}
