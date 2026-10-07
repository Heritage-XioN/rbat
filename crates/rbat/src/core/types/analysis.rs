//! # Analysis Data Models and Aggregation Structures
//!
//! Captures binary metadata, cryptographic and fuzzy hashes, section boundaries,
//! code cave regions, and intermediate progress events emitted during concurrent
//! heuristic execution.
//!
//! ## Core Types
//!
//! - [`AnalysisProgress`]: Granular streaming progress updates emitted in real time as individual
//!   heuristic plugins complete their execution.
//! - [`AnalysisResult`]: Comprehensive aggregation of all static analysis findings across a single
//!   target binary buffer.
//! - [`BinaryMetadata`]: Normalized executable format, architecture, and entry point metadata.
//! - [`BinaryHashes`]: Cryptographic digests (MD5, SHA-1, SHA-256) and fuzzy hashes (SSDEEP, TLSH)
//!   matching triage platform standards.
//! - [`SectionRange`]: Fast virtual file-offset interval mapper for binary sections.
//! - [`CodeCaves`]: Strongly-typed container for suspicious consecutive instruction and padding blocks.
//!
//! ## Pipeline Data Flow
//!
//! ```text
//! Raw Binary &[u8]
//!       │
//!       ├───► Parser ─────────────► BinaryMetadata / SectionRange
//!       │
//!       ├───► Concurrent Plugins ──► AnalysisProgress Stream
//!       │        ├── Hashes
//!       │        ├── Entropy
//!       │        ├── Strings & Packer YARA
//!       │        ├── Code Caves
//!       │        └── Imports / Exports
//!       │
//!       └───► Collector ──────────► AnalysisResult
//! ```
//!
//! ## Lifetime Semantics
//!
//! The lifetime `'buf` ties extracted strings and section name slices directly to the underlying
//! raw binary buffer, avoiding unnecessary heap allocations during analysis.
//!
//! ## Examples
//!
//! Inspecting an aggregated [`AnalysisResult`]:
//!
//! ```rust
//! use rbat::core::types::analysis::AnalysisResult;
//!
//! let result = AnalysisResult::default();
//! assert_eq!(result.total_analysis_time_ms, 0);
//! assert!(result.imports.is_empty());
//! assert!(result.code_cave.is_empty());
//! ```

use crate::core::{
    cfg::ControlFlowGraph,
    disassembler::InstructionInfo,
    flirt::FlirtMatcher,
    needle::NeedleIndex,
    parser::{BinaryArch, BinaryOS},
    types::result::{RbatError, RbatResult},
    yarahandler::YaraMatches,
};
use ahash::AHashMap;
use rustc_hash::{FxHashMap, FxHashSet};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Represents progress updates emitted during static analysis.
///
/// Each variant corresponds to the completion of an individual heuristic analysis
/// plugin or parsing stage. In streaming mode, these events are delivered immediately
/// to progress callbacks.
///
/// # Examples
///
/// ```rust
/// use rbat::core::types::analysis::{AnalysisProgress, BinaryHashes};
///
/// let hashes = BinaryHashes::default();
/// let event = AnalysisProgress::Hashes(hashes);
///
/// match event {
///     AnalysisProgress::Hashes(h) => assert!(h.sha256.is_empty()),
///     _ => unreachable!(),
/// }
/// ```
pub enum AnalysisProgress<'buf> {
    /// Digest and fuzzy hashes computed over the raw binary buffer.
    Hashes(BinaryHashes),
    /// Disassembly results: code caves detected across executable sections.
    Disassembly(CodeCaves),
    /// Extracted suspicious strings matched by embedded YARA rules.
    Strings(AHashMap<&'buf str, Vec<YaraMatches<'buf>>>),
    /// Packer, compiler, and protector signatures matched by YARA rules.
    PackerSigs(AHashMap<&'buf str, Vec<YaraMatches<'buf>>>),
    /// Shannon entropy score calculated per binary section.
    Entropy(AHashMap<&'buf str, f64>),
    /// Dynamically imported API symbols and library imports.
    Imports(Vec<usize>),
    /// Exported symbol and function entry offsets.
    Exports(Vec<usize>),
    /// Format-independent metadata extracted from binary headers.
    BinaryMetadata(BinaryMetadata),
    /// Reconstructed Control Flow Graph across functions.
    CFG(ControlFlowGraph),
    /// Standard library functions identified via FLIRT signatures.
    LibraryFunctions(FxHashMap<u64, String>),
}

/// Cryptographic digests and triage fuzzy hashes identifying the analyzed binary.
///
/// Matches the hash identifier schema exposed by malware triage platforms
/// (VirusTotal, MalwareBazaar, Hybrid Analysis).
///
/// # Examples
///
/// ```rust
/// use rbat::core::types::analysis::BinaryHashes;
///
/// let hashes = BinaryHashes {
///     md5: "d41d8cd98f00b204e9800998ecf8427e".to_string(),
///     sha1: "da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string(),
///     sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
///     ssdeep: String::new(),
///     tlsh: String::new(),
/// };
///
/// assert_eq!(hashes.md5.len(), 32);
/// assert_eq!(hashes.sha256.len(), 64);
/// ```
#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq, Eq)]
pub struct BinaryHashes {
    /// MD5 digest (lowercase hexadecimal, 32 characters).
    pub md5: String,
    /// SHA-1 digest (lowercase hexadecimal, 40 characters).
    pub sha1: String,
    /// SHA-256 digest (lowercase hexadecimal, 64 characters); primary lookup key.
    pub sha256: String,
    /// SSDEEP context-triggered piecewise hash; empty when input is too small (< 4096 bytes).
    pub ssdeep: String,
    /// TLSH locality-sensitive hash (uppercase, `T1`-prefixed); empty when input is below minimum (~50 bytes).
    pub tlsh: String,
}

/// The accumulated results of all static analysis heuristics run on a binary.
///
/// Contains all metadata, hashes, entropy maps, string matches, imports, exports,
/// CFG structures, and detected library functions collected during an analysis run.
///
/// # Examples
///
/// ```rust
/// use rbat::core::types::analysis::AnalysisResult;
///
/// let result = AnalysisResult::default();
/// assert_eq!(result.total_analysis_time_ms, 0);
/// assert!(result.cfg.is_none());
/// ```
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct AnalysisResult<'buf> {
    /// Extracted header and format metadata.
    pub metadata: BinaryMetadata,
    /// Cryptographic and fuzzy hashes computed over the raw buffer.
    pub hashes: BinaryHashes,
    /// Code cave findings (NOP sleds, null padding, trap padding).
    pub code_cave: CodeCaves,
    /// Dynamically imported APIs and symbols.
    pub imports: Vec<usize>,
    /// Exported symbols and functions.
    pub exports: Vec<usize>,
    /// Entropy score per binary section.
    #[serde(borrow)]
    pub section_entropy: AHashMap<&'buf str, f64>,
    /// String extraction YARA matches.
    #[serde(borrow)]
    pub string_values: AHashMap<&'buf str, Vec<YaraMatches<'buf>>>,
    /// Packer or crypter signature matches.
    #[serde(borrow)]
    pub packer_signatures: AHashMap<&'buf str, Vec<YaraMatches<'buf>>>,
    /// Reconstructed Control Flow Graph.
    pub cfg: Option<ControlFlowGraph>,
    /// Matched library functions mapped by start virtual address.
    pub library_functions: FxHashMap<u64, String>,
    /// Total time taken for the full analysis pipeline in milliseconds.
    pub total_analysis_time_ms: u128,
}

/// Format-independent metadata extracted from binary headers.
///
/// Normalizes architecture identification, container format names, and entry point
/// addresses across ELF, PE, and Mach-O binaries.
///
/// # Examples
///
/// ```rust
/// use rbat::core::types::analysis::BinaryMetadata;
///
/// let meta = BinaryMetadata {
///     binary_type: "Linux ELF".to_string(),
///     entry_point: 0x401000,
///     architecture: 62,
/// };
///
/// assert_eq!(meta.architecture_name(), "x86_64");
/// ```
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct BinaryMetadata {
    /// Human-readable file type (e.g. `"Linux ELF"`, `"Windows PE"`, `"Mach-O"`).
    pub binary_type: String,
    /// Entry point address in virtual memory.
    pub entry_point: u64,
    /// Target architecture machine code.
    pub architecture: u16,
}

impl BinaryMetadata {
    /// Returns a clean, human-readable architecture name.
    ///
    /// Maps numeric machine codes from ELF (`e_machine`), PE (`Machine`), and Mach-O (`cputype`)
    /// headers to canonical architecture labels:
    /// - `"x86_64"`, `"x86"`
    /// - `"ARM64"`, `"ARM"`
    /// - `"RISC-V"`, `"MIPS"`, `"PowerPC"`
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rbat::core::types::analysis::BinaryMetadata;
    ///
    /// let meta = BinaryMetadata {
    ///     binary_type: "Windows PE".to_string(),
    ///     entry_point: 0x140001000,
    ///     architecture: 0x8664,
    /// };
    /// assert_eq!(meta.architecture_name(), "x86_64");
    /// ```
    pub fn architecture_name(&self) -> String {
        match (self.binary_type.as_str(), self.architecture) {
            // x86_64 / x64
            (_, 62) | (_, 0x8664) => "x86_64".to_string(),
            // x86 / i386
            (_, 3) | (_, 0x014c) => "x86".to_string(),
            // AArch64 / ARM64
            (_, 183) | (_, 0xaa64) => "ARM64".to_string(),
            // ARM 32-bit
            (_, 40) | (_, 0x01c0) => "ARM".to_string(),
            // RISC-V
            (_, 243) => "RISC-V".to_string(),
            // MIPS
            (_, 8) => "MIPS".to_string(),
            // PowerPC
            (_, 20) | (_, 21) => "PowerPC".to_string(),
            // Mach-O Machine Codes (cputype & 0xFFFF: 7 is 32-bit x86, 12 is 32-bit ARM)
            ("Mach-O", 7) | ("Mach-O (Fat)", 7) => "x86".to_string(),
            ("Mach-O", 12) | ("Mach-O (Fat)", 12) => "ARM".to_string(),
            // Unknown Machine Code Fallback
            _ => format!("Unknown (0x{:04X})", self.architecture),
        }
    }

    /// Extracts high-level metadata (architecture type, entry address, name) from a parsed object.
    ///
    /// # Arguments
    ///
    /// - `binary_object`: A parsed [`object::File`] handle.
    ///
    /// # Errors
    ///
    /// Returns [`RbatError::ValidateBinaryFormatError`] if the binary format is unrecognized.
    pub fn from_object(binary_object: &object::File) -> RbatResult<Self> {
        use object::{Architecture, BinaryFormat, Object};
        let binary_type = match binary_object.format() {
            BinaryFormat::Elf => "Linux ELF",
            BinaryFormat::Pe | BinaryFormat::Coff => "Windows PE",
            BinaryFormat::MachO => "Mach-O",
            _ => {
                return Err(RbatError::ValidateBinaryFormatError(
                    "Unsupported format".to_string(),
                ));
            }
        }
        .to_string();

        let architecture = match binary_object.architecture() {
            Architecture::X86_64 | Architecture::X86_64_X32 => 0x3e,
            Architecture::I386 => 0x03,
            Architecture::Arm => 0x28,
            Architecture::Aarch64 | Architecture::Aarch64_Ilp32 => 0xb7,
            Architecture::Riscv32 | Architecture::Riscv64 => 243,
            Architecture::Mips | Architecture::Mips64 => 8,
            Architecture::PowerPc => 20,
            Architecture::PowerPc64 => 21,
            _ => 0,
        };

        Ok(BinaryMetadata {
            binary_type,
            entry_point: binary_object.entry(),
            architecture,
        })
    }
}

/// Shared context providing read-only access to binary structures across parallel heuristic plugins.
///
/// This structure holds borrows of parsed binary components, allowing heuristic analysis
/// plugins to process them concurrently without data duplication or locking.
///
/// # Example
/// ```ignore
/// use object::File;
/// use rbat::core::{AnalysisContext, BinaryArch, BinaryOS};
///
/// let buffer = vec![0x90; 100];
/// let section_ranges = vec![];
///
/// // Mock context without triggering object::File::parse
/// let ctx = AnalysisContext {
///     buffer: &buffer,
///     binary_object: unsafe { std::mem::zeroed() },
///     section_ranges: &section_ranges,
///     entry_points: rustc_hash::FxHashSet::default(),
///     custom_flirt: &None,
///     os: BinaryOS::Linux,
///     arch: BinaryArch::X64,
///     text_bytes: &buffer,
///     entry_addr: 0x1000,
///     instructions: std::sync::Arc::from([]),
///     needle: std::sync::Arc::new(rbat::core::types::NeedleIndex::build_from_rules(&[])),
/// };
/// ```
pub(crate) struct AnalysisContext<'buf, 'ctx> {
    /// Raw bytes of the target binary file.
    pub(crate) buffer: &'buf [u8],
    /// Parsed representation of the executable headers and sections.
    pub(crate) binary_object: &'ctx object::File<'buf, &'buf [u8]>,
    /// Cached mappings of section offsets to names.
    pub(crate) section_ranges: &'ctx [SectionRange<'buf>],
    /// Collection of potential entry points in the binary.
    pub(crate) entry_points: FxHashSet<u64>,
    /// Optional custom FLIRT signatures; borrows the analysis-scoped lifetime.
    pub(crate) custom_flirt: &'ctx FlirtMatcher,
    /// Target operating system preference.
    #[allow(dead_code)]
    pub(crate) os: BinaryOS,
    /// Target CPU architecture.
    pub(crate) arch: BinaryArch,
    /// Raw instruction bytes extracted from the executable section.
    pub(crate) text_bytes: &'ctx [u8],
    /// Raw binary entry point.
    pub(crate) entry_addr: u64,
    /// Parsed instruction list for the code section.
    pub(crate) instructions: Arc<[InstructionInfo]>,
    /// The global NeedleIndex automaton for pattern matching.
    pub(crate) needle: Arc<NeedleIndex>,
}

/// Cached mapping representing a binary section's file offset boundaries.
///
/// Pre-computed during initial binary parsing to enable fast interval lookups
/// when mapping raw file byte offsets (e.g. from YARA match offsets or code caves)
/// back to section names (`.text`, `.data`, `.rdata`).
///
/// # Examples
///
/// ```rust
/// use rbat::core::types::analysis::SectionRange;
///
/// let ranges = vec![
///     SectionRange { start: 0x1000, end: 0x2000, name: ".text" },
///     SectionRange { start: 0x2000, end: 0x3000, name: ".data" },
/// ];
///
/// assert_eq!(SectionRange::find_section(&ranges, 0x1500), Some(".text"));
/// assert_eq!(SectionRange::find_section(&ranges, 0x3500), None);
/// assert_eq!(SectionRange::get_section_for_offset(&ranges, 0x3500), "<unknown>");
/// ```
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SectionRange<'buf> {
    /// Start byte offset in the binary file.
    pub start: usize,
    /// End byte offset in the binary file.
    pub end: usize,
    /// Name of the binary section (e.g. `".text"`, `"__TEXT"`).
    #[serde(borrow)]
    pub name: &'buf str,
}

impl<'buf> SectionRange<'buf> {
    /// Builds a cached mapping of file offset boundaries for all sections in a parsed binary object.
    ///
    /// # Arguments
    ///
    /// - `binary_object`: A parsed [`object::File`] handle.
    ///
    /// # Returns
    ///
    /// A vector of [`SectionRange`] instances sorted by binary layout.
    pub fn build_map(binary_object: &object::File<'buf, &'buf [u8]>) -> RbatResult<Vec<Self>> {
        use object::{Object, ObjectSection};
        let mut ranges = Vec::new();
        for section in binary_object.sections() {
            if let Some((start, size)) = section.file_range() {
                let start = start as usize;
                let end = start.saturating_add(size as usize);
                let name = section.name().unwrap_or("<unnamed>");
                ranges.push(SectionRange { start, end, name });
            }
        }
        Ok(ranges)
    }

    /// Finds the section name containing the given file offset.
    ///
    /// # Arguments
    ///
    /// - `ranges`: Slice of known binary [`SectionRange`] records.
    /// - `offset`: Raw file byte offset to query.
    ///
    /// # Returns
    ///
    /// `Some(name)` if the offset falls within `[start, end)`, or `None` otherwise.
    pub fn find_section(ranges: &[SectionRange<'buf>], offset: usize) -> Option<&'buf str> {
        for range in ranges {
            if offset >= range.start && offset < range.end {
                return Some(range.name);
            }
        }
        None
    }

    /// Finds the section name containing the given file offset, returning `"<unknown>"` if not found.
    ///
    /// # Arguments
    ///
    /// - `ranges`: Slice of known binary [`SectionRange`] records.
    /// - `offset`: Raw file byte offset to query.
    pub fn get_section_for_offset(ranges: &[SectionRange<'buf>], offset: usize) -> &'buf str {
        Self::find_section(ranges, offset).unwrap_or("<unknown>")
    }
}

/// Strongly typed findings for suspicious code caves and padding sequences.
///
/// Tracks consecutive blocks of unused or padded executable space:
/// - **NOP sleds**: Runs of $\ge 128$ consecutive `NOP` instructions (`0x90`).
/// - **NULL padding**: Runs of $\ge 128$ consecutive zero bytes (`0x00`).
/// - **Trap padding**: Runs of $\ge 128$ consecutive debugger interrupt bytes (`0xCC` / `INT3`).
///
/// # Examples
///
/// ```rust
/// use rbat::core::types::analysis::CodeCaves;
///
/// let mut caves = CodeCaves::default();
/// assert!(caves.is_empty());
/// assert_eq!(caves.total_caves(), 0);
///
/// caves.nop_sleds.push(0x401000);
/// assert!(!caves.is_empty());
/// assert_eq!(caves.total_caves(), 1);
/// assert_eq!(caves.len(), 1);
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodeCaves {
    /// Consecutive NOP instruction addresses (>= 128 instructions).
    pub nop_sleds: Vec<u64>,
    /// Consecutive NULL padding addresses (>= 128 bytes).
    pub null_padding: Vec<u64>,
    /// Consecutive INT3/trap padding addresses (>= 128 bytes).
    pub trap_padding: Vec<u64>,
}

impl CodeCaves {
    /// Returns `true` if no code caves of any type were found.
    pub fn is_empty(&self) -> bool {
        self.nop_sleds.is_empty() && self.null_padding.is_empty() && self.trap_padding.is_empty()
    }

    /// Returns the total count of cave addresses across all categories.
    pub fn total_caves(&self) -> usize {
        self.nop_sleds.len() + self.null_padding.len() + self.trap_padding.len()
    }

    /// Alias for [`CodeCaves::total_caves`].
    pub fn len(&self) -> usize {
        self.total_caves()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_metadata_architecture_names() {
        let meta_x64 = BinaryMetadata {
            binary_type: "Linux ELF".to_string(),
            entry_point: 0x1000,
            architecture: 62,
        };
        assert_eq!(meta_x64.architecture_name(), "x86_64");

        let meta_macho_x86 = BinaryMetadata {
            binary_type: "Mach-O".to_string(),
            entry_point: 0x1000,
            architecture: 7,
        };
        assert_eq!(meta_macho_x86.architecture_name(), "x86");

        let meta_macho_arm = BinaryMetadata {
            binary_type: "Mach-O".to_string(),
            entry_point: 0x1000,
            architecture: 12,
        };
        assert_eq!(meta_macho_arm.architecture_name(), "ARM");

        let meta_arm64 = BinaryMetadata {
            binary_type: "Linux ELF".to_string(),
            entry_point: 0x1000,
            architecture: 183,
        };
        assert_eq!(meta_arm64.architecture_name(), "ARM64");
    }
}
