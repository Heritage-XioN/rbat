//! # Analysis Data Types
//!
//! This module defines the core data structures, enums, and utility structures
//! used throughout the binary analysis pipeline, reporting, and scoring engines.

use super::{BinaryArch, BinaryOS};
use crate::{
    core::{FeatureSet, cfg::ControlFlowGraph},
    utils::rules::{StringOrVec, parse_count_threshold, parse_number_constant},
};
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

/// Metadata describing a security rule aligned with the Mandiant `capa` specification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct RuleMeta {
    /// The unique rule identifier name.
    pub name: String,
    /// Rule namespace path (e.g. `"communication/c2/shell"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Authors list or author attribution string.
    #[serde(default, alias = "author", skip_serializing_if = "Option::is_none")]
    pub authors: Option<StringOrVec>,
    /// Rule evaluation scopes (e.g. `{ "static": "function" }`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<HashMap<String, String>>,
    /// Mapped MITRE ATT&CK technique list or ID (e.g. `["Execution::Windows Command Shell [T1059.003]"]` or `"T1055"`).
    #[serde(
        default,
        alias = "att&ck",
        alias = "attack",
        alias = "mitre_attack",
        skip_serializing_if = "Option::is_none"
    )]
    pub mitre_attack: Option<StringOrVec>,
    /// Malware Behavior Catalog (MBC) technique mappings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mbc: Option<StringOrVec>,
    /// Example binary hash offsets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub examples: Option<Vec<String>>,
    /// Detailed behavior explanation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Threat severity rating (`"Low"`, `"Medium"`, `"High"`, `"Critical"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// Threat tactic category.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Weight contribution (0-100).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<u32>,
    /// Reference URLs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub references: Option<Vec<String>>,
    /// Tag labels.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    /// Whether this is a library rule (referenced by other rules but not standalone).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lib: Option<bool>,
    /// MAEC malware category mapping.
    #[serde(
        default,
        rename = "maec/malware-category",
        skip_serializing_if = "Option::is_none"
    )]
    pub maec_malware_category: Option<String>,
    /// MAEC malware family mapping.
    #[serde(
        default,
        rename = "maec/malware-family",
        skip_serializing_if = "Option::is_none"
    )]
    pub maec_malware_family: Option<String>,
}

/// Supported tag-based feature conditions represented as raw strings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleTag {
    CodeCave,
    PackerSig,
    Loop,
}

/// The inner structure of the rules struct containing rule metadata and feature triggers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleInner {
    /// The rule metadata.
    pub meta: RuleMeta,
    /// The condition tree/features to evaluate.
    pub features: Vec<RuleCondition>,
}

/// Boolean logic combinations of rule conditions aligned with the Mandiant `capa` specification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum RuleCondition {
    // Logic Operators
    And {
        and: Vec<RuleCondition>,
    },
    Or {
        or: Vec<RuleCondition>,
    },
    Not {
        not: Box<RuleCondition>,
    },
    // capa Supported Feature Assertions
    Api {
        api: String,
    },
    String {
        string: String,
    },
    Mnemonic {
        mnemonic: String,
    },
    Match {
        #[serde(rename = "match")]
        match_name: String,
    },
    Entropy {
        section: String,
        min: f64,
    },
    // codebase heuristics feature
    Tag(RuleTag),
    // CFG properties & localized scopes
    BasicBlocksCount {
        #[serde(rename = "basic_blocks_count")]
        count: usize,
    },
    CyclomaticComplexity {
        #[serde(rename = "cyclomatic_complexity")]
        min: usize,
    },
    BasicBlockScope {
        #[serde(rename = "basic block")]
        conditions: Vec<RuleCondition>,
    },
    CallScope {
        #[serde(rename = "call")]
        conditions: Vec<RuleCondition>,
    },
    // other capa feature checks
    Export {
        export: String,
    },
    Import {
        import: String,
    },
    Section {
        section: String,
    },
    Os {
        os: String,
    },
    Arch {
        arch: String,
    },
    Characteristic {
        characteristic: String,
    },
    // catch all variant for unhandled/unsupported rules
    Other(std::collections::HashMap<String, serde_json::Value>),
}

impl RuleCondition {
    /// Recursively sanitizes the condition tree to remove informational description-only nodes.
    pub fn sanitize(self) -> Option<Self> {
        match self {
            Self::And { and } => {
                let sanitized: Vec<RuleCondition> =
                    and.into_iter().filter_map(|c| c.sanitize()).collect();
                if sanitized.is_empty() {
                    None
                } else {
                    Some(Self::And { and: sanitized })
                }
            }
            Self::Or { or } => {
                let sanitized: Vec<RuleCondition> =
                    or.into_iter().filter_map(|c| c.sanitize()).collect();
                if sanitized.is_empty() {
                    None
                } else {
                    Some(Self::Or { or: sanitized })
                }
            }
            Self::Not { not } => not.sanitize().map(|c| Self::Not { not: Box::new(c) }),
            Self::BasicBlockScope { conditions } => {
                let sanitized: Vec<RuleCondition> = conditions
                    .into_iter()
                    .filter_map(|c| c.sanitize())
                    .collect();
                Some(Self::BasicBlockScope {
                    conditions: sanitized,
                })
            }
            Self::CallScope { conditions } => {
                let sanitized: Vec<RuleCondition> = conditions
                    .into_iter()
                    .filter_map(|c| c.sanitize())
                    .collect();
                Some(Self::CallScope {
                    conditions: sanitized,
                })
            }
            Self::Other(map) => {
                if map.len() == 1 && map.contains_key("description") {
                    None
                } else {
                    Some(Self::Other(map))
                }
            }
            other => Some(other),
        }
    }

    /// Recursively evaluates the condition against the feature set.
    pub fn matches(&self, features: &FeatureSet) -> bool {
        match self {
            // Logic Operators
            Self::And { and } => and.iter().all(|c| c.matches(features)),
            Self::Or { or } => or.iter().any(|c| c.matches(features)),
            Self::Not { not } => !not.matches(features),
            // capa Supported Feature Assertions
            Self::Api { api } => features
                .apis
                .iter()
                .any(|a| a.to_lowercase().contains(&api.to_lowercase())),
            Self::String { string } => features
                .strings
                .iter()
                .any(|s| s.to_lowercase().contains(&string.to_lowercase())),
            Self::Mnemonic { mnemonic } => features.mnemonics.contains(mnemonic),
            Self::Match { match_name } => features
                .apis
                .iter()
                .chain(features.strings.iter())
                .any(|s| s.to_lowercase().contains(&match_name.to_lowercase())),
            Self::Entropy { section, min } => features
                .section_entropies
                .get(section)
                .map(|&e| e >= *min)
                .unwrap_or(false),
            // codebase heuristics checks
            Self::Tag(RuleTag::CodeCave) => features.has_code_cave,
            Self::Tag(RuleTag::PackerSig) => features.has_packer_sig,
            Self::Tag(RuleTag::Loop) => features.has_loop,
            // cfg and basic block checks
            Self::BasicBlocksCount { count } => features.basic_blocks_count >= *count,
            Self::CyclomaticComplexity { min } => features.max_cyclomatic_complexity >= *min,
            Self::BasicBlockScope { conditions } => features.blocks.iter().any(|block| {
                let local_features =
                    FeatureSet::from_basic_block(block, &features.os, &features.arch);
                conditions.iter().all(|cond| cond.matches(&local_features))
            }),
            Self::CallScope { conditions } => features.blocks.iter().any(|block| {
                block.instructions.iter().any(|insn| {
                    let local_features =
                        FeatureSet::from_instruction(insn, &features.os, &features.arch);
                    conditions.iter().all(|cond| cond.matches(&local_features))
                })
            }),
            // Minimally match OS and Arch if present
            Self::Os { os } => features.os.contains(&os.to_lowercase()),
            Self::Arch { arch } => features.arch.contains(&arch.to_lowercase()),
            Self::Import { import } => features
                .apis
                .iter()
                .any(|api| api.to_lowercase().contains(&import.to_lowercase())),
            Self::Export { export } => features
                .apis
                .iter()
                .any(|api| api.to_lowercase().contains(&export.to_lowercase())),
            Self::Section { section } => features.section_entropies.contains_key(section),
            Self::Characteristic { characteristic }
                if characteristic.to_lowercase().contains("packed") =>
            {
                features.has_packer_sig
            }
            // this represents a catch all condition for the features
            // that are not currently unhandled or unsported
            Self::Other(map) => {
                for (key, value) in map {
                    // Ignore informational description fields inside logic trees
                    if key == "description" {
                        continue;
                    }

                    // Check if key is a count assertion, e.g. "count(api(SetHandleInformation))"
                    if key.starts_with("count(") && key.ends_with(")") {
                        let inner = &key[6..key.len() - 1]; // e.g. "api(SetHandleInformation)"
                        if inner.starts_with("api(") && inner.ends_with(")") {
                            let api_name = &inner[4..inner.len() - 1];
                            let threshold = parse_count_threshold(value);
                            let count = features
                                .apis
                                .iter()
                                .filter(|a| a.to_lowercase().contains(&api_name.to_lowercase()))
                                .count();
                            if count < threshold {
                                return false;
                            }
                        } else if inner.starts_with("string(") && inner.ends_with(")") {
                            let str_val = &inner[7..inner.len() - 1];
                            let threshold = parse_count_threshold(value);
                            let count = features
                                .strings
                                .iter()
                                .filter(|s| s.to_lowercase().contains(&str_val.to_lowercase()))
                                .count();
                            if count < threshold {
                                return false;
                            }
                        } else if inner.starts_with("mnemonic(") && inner.ends_with(")") {
                            let mnem = &inner[9..inner.len() - 1];
                            let threshold = parse_count_threshold(value);
                            let count = if features.mnemonics.iter().any(|m| m == mnem) {
                                1
                            } else {
                                0
                            };
                            if count < threshold {
                                return false;
                            }
                        } else {
                            // Return false for unsupported count types (e.g. characteristic, match)
                            return false;
                        }
                    }
                    // Check if key is "number"
                    else if key == "number" {
                        let target_num = parse_number_constant(value);
                        if !features.strings.iter().any(|s| s.contains(&target_num)) {
                            return false;
                        }
                    }
                    // Fallback for unhandled property
                    else {
                        return false;
                    }
                }
                true
            }
            _ => false,
        }
    }
}
