//! # Analysis Data Types
//!
//! This module defines the core data structures, enums, and utility structures
//! used throughout the binary analysis pipeline, reporting, and scoring engines.

use super::{BinaryArch, BinaryOS};
use goblin::Object;
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Represents the progress updates emitted during static analysis.
pub enum AnalysisProgress {
    /// Disassembly results: code caves mapped by pattern type (`"nop_addr"`, `"null_addr"`, `"int3_addr"`)
    /// and blacklisted anti-analysis mnemonics.
    Disassembly((HashMap<String, Vec<u64>>, HashMap<String, Vec<u64>>)),
    /// Extracted strings matched by YARA rules.
    Strings(HashMap<String, Vec<YaraMatches>>),
    /// Packer and compiler signatures matched by YARA rules.
    PackerSigs(HashMap<String, Vec<YaraMatches>>),
    /// Computed entropy score per binary section.
    Entropy(HashMap<String, f64>),
    /// Identified API hooks or imported function calls.
    ApiHooking(HashMap<String, u64>),
    /// Process injection API occurrences.
    ProcessInjection(HashSet<String>),
    /// Extracted binary format metadata.
    BinaryMetadata(BinaryMetadata),
}

/// Built-in binary assets embedded directly into the library compilation.
#[derive(RustEmbed)]
#[folder = "./assets/"]
pub struct Asset;

/// Details of a single YARA rule signature match within a binary section.
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct YaraMatches {
    /// File offset where the match starts.
    pub offset: usize,
    /// Name of the binary section where the match was located.
    pub section: String,
    /// Length of the matching byte sequence.
    pub length: usize,
    /// Human-readable representation of the matched data.
    pub data: String,
}

/// The accumulated results of all static analysis heuristics run on a binary.
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct AnalysisResult {
    /// Extracted header and format metadata.
    pub metadata: BinaryMetadata,
    /// List of consecutive padding/cave virtual memory addresses.
    pub code_cave: HashMap<String, Vec<u64>>,
    /// Count and location of blacklisted anti-analysis instructions.
    pub blacklisted_mnemonics: HashMap<String, Vec<u64>>,
    /// System and API calls associated with library/function hooking.
    pub api_hooking: HashMap<String, u64>,
    /// Indicators of process injection capabilities.
    pub process_injection: HashSet<String>,
    /// Entropy score per binary section.
    pub section_entropy: HashMap<String, f64>,
    /// String extraction YARA matches.
    pub string_values: HashMap<String, Vec<YaraMatches>>,
    /// Packer or crypter signature matches.
    pub packer_signatures: HashMap<String, Vec<YaraMatches>>,
}

/// Auxiliary key-value mapping wrapper for binary properties.
#[derive(Debug)]
pub enum MapValue {
    /// Extracted raw bytes.
    Bytes(Vec<u8>),
    /// Numerical word value.
    Word(u64),
    /// Operating system type.
    OS(BinaryOS),
    /// Binary CPU architecture.
    Arch(BinaryArch),
}

/// Confidence rating of a security finding.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub enum Confidence {
    /// Low likelihood of false positives or minor security indicator.
    #[default]
    Low,
    /// Moderate security indicator.
    Medium,
    /// Strong indicator of malicious behavior or packing.
    High,
    /// Direct indicator of active evasion or process hijacking techniques.
    Critical,
}

/// A specific threat indicator or security anomaly discovered during analysis.
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Finding {
    /// The shorthand description or type of the threat.
    pub indicator: String,
    /// A detailed explanation of what was found and why it is flagged.
    pub description: String,
    /// Severity rating of the finding.
    pub confidence: Confidence,
    /// Numeric impact score (used to calculate final assessment score).
    pub weight: u32,
}

/// The aggregated security assessment containing the threat score and findings.
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct RiskAssessment {
    /// The final numeric score ranging from `0` (Safe) to `100` (Highly Malicious).
    pub score: u32,
    /// Qualitative severity evaluation: `"Safe"`, `"Suspicious"`, or `"Malicious"`.
    pub severity: String,
    /// Detailed list of security findings.
    pub findings: Vec<Finding>,
    /// Actionable mitigation and remediation steps.
    pub recommendations: Vec<String>,
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

/// Shared context providing read-only access to binary structures across parallel heuristic plugins.
///
/// This structure holds borrows of parsed binary components, allowing heuristic analysis
/// plugins to process them concurrently without data duplication or locking.
///
/// # Example
/// ```rust
/// use std::path::Path;
/// use goblin::Object;
/// use rbat::core::{AnalysisContext, BinaryArch, BinaryOS};
///
/// let path = Path::new("test_bin");
/// let buffer = vec![0x90; 100];
/// let obj = Object::parse(&buffer).unwrap();
/// let section_ranges = vec![];
///
/// let ctx = AnalysisContext {
///     path: &path,
///     buffer: &buffer,
///     binary_object: &obj,
///     section_ranges: &section_ranges,
///     os: BinaryOS::Linux,
///     arch: BinaryArch::X64,
///     text_bytes: &buffer,
///     entry_addr: 0x1000,
/// };
/// ```
pub struct AnalysisContext<'a> {
    /// Raw byte buffer of the binary.
    pub buffer: &'a [u8],
    /// Parsed representation of the executable headers and sections.
    pub binary_object: &'a Object<'a>,
    /// Cached mappings of section offsets to names.
    pub section_ranges: &'a [SectionRange],
    /// Target operating system preference.
    pub os: BinaryOS,
    /// Target CPU architecture.
    pub arch: BinaryArch,
    /// Raw instruction bytes extracted from the executable section.
    pub text_bytes: &'a [u8],
    /// Raw binary entry point.
    pub entry_addr: u64,
}

/// Cached mapping representing a binary section's file offset boundaries.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SectionRange {
    /// Start byte offset in the binary file.
    pub start: usize,
    /// End byte offset in the binary file.
    pub end: usize,
    /// Name of the binary section (e.g. `".text"`, `"__TEXT"`).
    pub name: String,
}
