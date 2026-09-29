//! Binary target and embedded-asset descriptors.

use rust_embed::RustEmbed;
use rustc_hash::FxHashMap;
use std::sync::Arc;

/// Maps IAT virtual addresses to their resolved API names.
pub type IatMap = FxHashMap<u64, Arc<str>>;

/// Supported target operating systems for assembly syntax style selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOS {
    /// Windows operating system.
    Win,
    /// Linux operating system.
    Linux,
    /// macOS operating system.
    Mac,
}

/// Supported CPU architectures for disassembly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryArch {
    /// 32-bit x86 architecture.
    X86,
    /// 64-bit x86-64 architecture.
    X64,
    /// 32-bit ARM architecture.
    Arm,
    /// 64-bit ARM (AArch64) architecture.
    Arm64,
}

/// Context extracted from parsing the binary's basic executable headers.
#[derive(Debug, Clone)]
pub struct ParsedBinaryContext {
    pub os: BinaryOS,
    pub arch: BinaryArch,
    pub entry_addr: u64,
    pub text_bytes: Vec<u8>,
    pub iat_map: IatMap,
}

/// Built-in binary assets embedded directly into the library compilation.
#[derive(RustEmbed)]
#[folder = "./assets/"]
#[exclude = "flirtdb/*"]
#[exclude = "signatures_embedded/*"]
#[exclude = "capa-rules/*"]
pub struct Asset;
