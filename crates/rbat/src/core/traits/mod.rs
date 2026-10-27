//! # Common Abstractions and Traits
//!
//! Defines the core extensibility interfaces used across the binary analysis engine, including
//! pluggable disassembler backends.
//!
//! ## Core Traits
//!
//! - [`Disassembler`]: Abstraction for linear instruction decoders and architecture-specific disassemblers.
//!
//! ## Overview
//!
//! Modular architecture in `rbat` decouples specific third-party engines from core analysis workflows:
//! - Disassembly engines implement the [`Disassembler`] trait, enabling both built-in decoders
//!   (Capstone, `iced-x86`) and custom user-provided engines to be dispatched seamlessly via [`DisassemblerBackend`].
//! - Static analysis heuristics implement the internal `HeuristicPlugin` trait, allowing independent tasks
//!   (hashing, entropy estimation, CFG extraction) to run concurrently over a shared analysis context.
//!
//! ## Examples
//!
//! ```rust
//! use rbat::core::traits::Disassembler;
//! use rbat::core::disassembler::CapstoneBackend;
//!
//! let disasm: &dyn Disassembler = &CapstoneBackend;
//! assert_eq!(disasm.name(), "capstone");
//! ```
//!
//! [`DisassemblerBackend`]: crate::core::disassembler::DisassemblerBackend

pub mod disassembler;
pub mod plugins;

pub use disassembler::Disassembler;
pub(crate) use plugins::HeuristicPlugin;
