//! Analysis result, context, and reporting structures.

use crate::core::disassembler::InstructionInfo;
use crate::core::{BinaryArch, BinaryOS, ControlFlowGraph, FlirtMatcher, NeedleIndex};
use ahash::AHashMap;
use rustc_hash::{FxHashMap, FxHashSet};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::sync::Arc;

/// Represents the progress updates emitted during static analysis.
pub enum AnalysisProgress<'buf> {
    /// Digest and fuzzy hashes of the raw binary buffer.
    Hashes(BinaryHashes),
    /// Disassembly results: code caves mapped by pattern type (`"nop_addr"`, `"null_addr"`, `"int3_addr"`)
    Disassembly(AHashMap<&'buf str, Vec<u64>>),
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

/// Details of a single YARA rule signature match within a binary section.
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct YaraMatches<'buf> {
    /// File offset where the match starts.
    pub offset: usize,
    /// Name of the binary section where the match was located.
    #[serde(borrow)]
    pub section: &'buf str,
    /// Length of the matching byte sequence.
    pub length: usize,
    /// Human-readable representation of the matched data.
    #[serde(borrow)]
    pub data: Cow<'buf, str>,
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
    /// List of consecutive padding/cave virtual memory addresses.
    #[serde(borrow)]
    pub code_cave: AHashMap<&'buf str, Vec<u64>>,
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
            // Mach-O Machine Codes (cputype & 0xFFFF)
            ("Mach-O", 7) | ("Mach-O (Fat)", 7) => "x86_64".to_string(),
            ("Mach-O", 12) | ("Mach-O (Fat)", 12) => "ARM64".to_string(),
            // Unknown Machine Code Fallback
            _ => format!("Unknown (0x{:04X})", self.architecture),
        }
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
///     os: BinaryOS::Linux,
///     arch: BinaryArch::X64,
///     text_bytes: &buffer,
///     entry_addr: 0x1000,
///     instructions: &[],
/// };
/// ```
pub struct AnalysisContext<'buf, 'ctx> {
    /// Raw bytes of the target binary file.
    pub buffer: &'buf [u8],
    /// Parsed representation of the executable headers and sections.
    pub binary_object: &'ctx object::File<'buf, &'buf [u8]>,
    /// Cached mappings of section offsets to names.
    pub section_ranges: &'ctx [SectionRange<'buf>],
    /// collection of potential entry points in a binary
    pub entry_points: FxHashSet<u64>,
    /// Optional custom FLIRT signatures; borrows the analysis-scoped lifetime
    pub custom_flirt: &'ctx Option<FlirtMatcher>,
    /// Target operating system preference.
    pub os: BinaryOS,
    /// Target CPU architecture.
    pub arch: BinaryArch,
    /// Raw instruction bytes extracted from the executable section.
    pub text_bytes: &'ctx [u8],
    /// Raw binary entry point.
    pub entry_addr: u64,
    /// Parsed instruction list for the code section.
    pub instructions: &'ctx [InstructionInfo],
    /// The global NeedleIndex automaton for pattern matching.
    pub needle: Arc<NeedleIndex>,
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
