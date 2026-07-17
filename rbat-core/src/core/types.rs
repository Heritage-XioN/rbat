//! # Analysis Data Types
//!
//! This module defines the core data structures, enums, and utility structures
//! used throughout the binary analysis pipeline, reporting, and scoring engines.

use super::{BinaryArch, BinaryOS};
use crate::core::cfg::ControlFlowGraph;
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
    /// Reconstructed Control Flow Graph.
    CFG(ControlFlowGraph),
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
    /// Reconstructed Control Flow Graph.
    pub cfg: Option<ControlFlowGraph>,
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
/// use goblin::Object;
/// use rbat::core::{AnalysisContext, BinaryArch, BinaryOS};
///
/// let buffer = vec![0x90; 100];
/// let obj = Object::parse(&buffer).unwrap();
/// let section_ranges = vec![];
///
/// let ctx = AnalysisContext {
///     buffer: &buffer,
///     binary_object: &obj,
///     section_ranges: &section_ranges,
///     os: BinaryOS::Linux,
///     arch: BinaryArch::X64,
///     text_bytes: &buffer,
///     entry_addr: 0x1000,
///     instructions: &[],
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
    /// Pre-disassembled instructions made available to all plugins.
    pub instructions: &'a [InstructionInfo],
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

/// A single instruction with simplified, owned properties for serializability.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstructionInfo {
    /// The virtual memory address of the instruction.
    pub address: u64,
    /// The instruction mnemonic (e.g. `"mov"`, `"jmp"`).
    pub mnemonic: String,
    /// The instruction operands string (e.g. `"rax, rcx"`).
    pub op_str: String,
}

/// Represents a basic block: a straight-line sequence of execution with a single entry and exit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BasicBlock {
    /// The start virtual memory address of the block.
    pub start_address: u64,
    /// The end virtual memory address of the block.
    pub end_address: u64,
    /// The set of instructions belonging to this block.
    pub instructions: Vec<InstructionInfo>,
}

/// Types of control flow edges connecting basic blocks.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EdgeType {
    /// Sequential execution continuation.
    FallThrough,
    /// Taken branch of a conditional jump.
    ConditionalTrue,
    /// Not-taken branch of a conditional jump.
    ConditionalFalse,
    /// Unconditional jump target.
    Unconditional,
    /// Subroutine call target.
    Call,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstructionClass {
    Normal,
    ConditionalJump,
    UnconditionalJump,
    Call,
    Return,
}

/// Metadata describing a security rule and its mapped threat techniques.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleMeta {
    /// The unique rule identifier name.
    pub name: String,
    /// Detailed behavior explanation.
    pub description: String,
    /// Mapped MITRE ATT&CK technique ID (e.g. `"T1055"`).
    pub mitre_attack: String,
    /// Quantitative threat severity rating (e.g. `"Low"`, `"Medium"`, `"High"`, `"Critical"`).
    pub severity: String,
    /// MITRE ATT&CK tactic category (e.g. `"defense_evasion"`, `"privilege_escalation"`).
    pub category: String,
    /// The individual weight contribution of this rule when matched (0-100).
    pub weight: u32,
}

/// A leaf feature assertion matching code, string, or structural anomalies.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FeatureCondition {
    /// Matches if an imported API function contains this pattern.
    Api(String),
    /// Matches if an extracted string contains this pattern.
    String(String),
    /// Matches if a blacklisted assembly mnemonic is found.
    Mnemonic(String),
    /// Matches if a specific binary section's entropy is equal to or greater than `min`.
    Entropy {
        /// The target binary section name (e.g. `".text"`).
        section: String,
        /// The minimum Shannon entropy boundary (0.0 to 8.0).
        min: f64,
    },
    /// Matches if any code caves were detected.
    CodeCave,
    /// Matches if any packer signatures were detected.
    PackerSig,
}
