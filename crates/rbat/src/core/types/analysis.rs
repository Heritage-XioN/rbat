//! Analysis result, context, and reporting structures.

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

/// Represents the progress updates emitted during static analysis.
pub enum AnalysisProgress<'buf> {
    /// Digest and fuzzy hashes of the raw binary buffer.
    Hashes(BinaryHashes),
    /// Disassembly results: code caves detected across executable sections.
    Disassembly(CodeCaves),
    /// Extracted strings matched by YARA rules.
    Strings(AHashMap<&'buf str, Vec<YaraMatches<'buf>>>),
    /// Packer and compiler signatures matched by YARA rules.
    PackerSigs(AHashMap<&'buf str, Vec<YaraMatches<'buf>>>),
    /// Computed entropy score per binary section.
    Entropy(AHashMap<&'buf str, f64>),
    /// Dynamically imported symbols and APIs.
    Imports(Vec<usize>),
    /// Exported symbols and functions.
    Exports(Vec<usize>),
    /// Extracted binary format metadata.
    BinaryMetadata(BinaryMetadata),
    /// Reconstructed Control Flow Graph.
    CFG(ControlFlowGraph),
    /// Matched library functions mapped by start virtual address.
    LibraryFunctions(FxHashMap<u64, String>),
}

/// Cryptographic digest and fuzzy hashes identifying the analyzed binary,
/// matching the identifier set exposed by triage platforms (VirusTotal, MalwareBazaar).
#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq, Eq)]
pub struct BinaryHashes {
    /// MD5 digest (lowercase hex).
    pub md5: String,
    /// SHA-1 digest (lowercase hex).
    pub sha1: String,
    /// SHA-256 digest (lowercase hex); the primary lookup key on triage platforms.
    pub sha256: String,
    /// SSDEEP context-triggered piecewise hash; empty when input is too small.
    pub ssdeep: String,
    /// TLSH locality-sensitive hash (uppercase, `T1`-prefixed); empty when
    /// input is below the algorithm's minimum length (~50 bytes).
    pub tlsh: String,
}

/// The accumulated results of all static analysis heuristics run on a binary.
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
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct BinaryMetadata {
    /// Human-readable file type (e.g. `"Linux ELF"`, `"Windows PE"`).
    pub binary_type: String,
    /// Entry point address in virtual memory.
    pub entry_point: u64,
    /// Target architecture machine code.
    pub architecture: u16,
}

impl BinaryMetadata {
    /// Returns a clean, human-readable architecture name (e.g. `"x86_64"`, `"x86"`, `"ARM64"`, `"ARM"`, `"RISC-V"`).
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
    pub fn from_object(binary_object: &object::File) -> RbatResult<Self> {
        use object::{Architecture, BinaryFormat, Object};
        let binary_type = match binary_object.format() {
            BinaryFormat::Elf => "Linux ELF",
            BinaryFormat::Pe | BinaryFormat::Coff => "Windows PE",
            BinaryFormat::MachO => "Mach-O",
            _ => {
                return Err(RbatError::UnsupportedBinaryFormat(
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
    pub fn find_section(ranges: &[SectionRange<'buf>], offset: usize) -> Option<&'buf str> {
        for range in ranges {
            if offset >= range.start && offset < range.end {
                return Some(range.name);
            }
        }
        None
    }

    /// Finds the section name containing the given file offset, returning `"<unknown>"` if not found.
    pub fn get_section_for_offset(ranges: &[SectionRange<'buf>], offset: usize) -> &'buf str {
        Self::find_section(ranges, offset).unwrap_or("<unknown>")
    }
}

/// Strongly typed code cave findings replacing `AHashMap<&str, Vec<u64>>`
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
