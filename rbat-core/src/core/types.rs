//! # Analysis Data Types
//!
//! This module defines the core data structures, enums, and utility structures
//! used throughout the binary analysis pipeline, reporting, and scoring engines.

use crate::{
    core::{FeatureSet, Rule, cfg::ControlFlowGraph},
    utils::rules::{StringOrVec, parse_count_threshold},
};

use aho_corasick::{AhoCorasick, PatternID};

use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};

/// Supported target operating systems for assembly syntax style selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOS {
    Win,
    Linux,
    Mac,
}

/// Supported CPU architectures for disassembly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryArch {
    X86,
    X64,
    Arm,
    Arm64,
}

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
    /// Matched library functions mapped by start virtual address.
    LibraryFunctions(HashMap<u64, String>),
}

/// Built-in binary assets embedded directly into the library compilation.
#[derive(RustEmbed)]
#[folder = "./assets/"]
#[exclude = "flirtdb/*"]
#[exclude = "signatures_embedded/*"]
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
    /// Matched library functions mapped by start virtual address.
    pub library_functions: HashMap<u64, String>,
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
pub struct AnalysisContext<'a> {
    /// Raw byte buffer of the binary.
    pub buffer: &'a [u8],
    /// Parsed representation of the executable headers and sections.
    pub binary_object: &'a object::File<'a, &'a [u8]>,
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

/// A generic view over a disassembled instruction.
#[cfg(feature = "backend-iced")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstructionInfo {
    pub inner: iced_x86::Instruction,
    pub os: BinaryOS,
    /// Pre-computed set of Aho-Corasick pattern IDs matched against this instruction's text.
    pub matched: Vec<PatternID>,
}

#[cfg(feature = "backend-iced")]
impl InstructionInfo {
    pub fn from_iced(inner: &iced_x86::Instruction, os: BinaryOS) -> Self {
        Self {
            inner: *inner,
            os,
            matched: Vec::new(),
        }
    }

    pub fn address(&self) -> u64 {
        self.inner.ip()
    }

    pub fn format_mnemonic_into(&self, buf: &mut String) {
        use std::fmt::Write;
        buf.clear();
        let _ = write!(buf, "{:?}", self.inner.mnemonic());
        buf.make_ascii_lowercase();
    }

    pub fn format_mnemonic(&self) -> String {
        let mut buf = String::new();
        self.format_mnemonic_into(&mut buf);
        buf
    }

    pub fn format_operands_into(&self, buf: &mut String) {
        use iced_x86::Formatter;
        use std::cell::RefCell;
        thread_local! {
            static INTEL_FMT: RefCell<iced_x86::IntelFormatter> = RefCell::new(iced_x86::IntelFormatter::new());
            static GAS_FMT: RefCell<iced_x86::GasFormatter> = RefCell::new(iced_x86::GasFormatter::new());
        }

        buf.clear();
        match self.os {
            BinaryOS::Linux => {
                GAS_FMT.with(|fmt| fmt.borrow_mut().format_all_operands(&self.inner, buf))
            }
            _ => INTEL_FMT.with(|fmt| fmt.borrow_mut().format_all_operands(&self.inner, buf)),
        }
    }

    pub fn format_operands(&self) -> String {
        let mut buf = String::new();
        self.format_operands_into(&mut buf);
        buf
    }
}

#[cfg(feature = "backend-iced")]
impl serde::Serialize for InstructionInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("InstructionInfo", 3)?;
        state.serialize_field("address", &self.address())?;
        state.serialize_field("mnemonic", &self.format_mnemonic())?;
        state.serialize_field("op_str", &self.format_operands())?;
        state.end()
    }
}

#[cfg(feature = "backend-iced")]
impl<'de> serde::Deserialize<'de> for InstructionInfo {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Deserialization is a stub because we cannot easily recreate the raw iced_x86 instruction
        // from formatted strings without the binary data.
        Err(serde::de::Error::custom(
            "Deserialize not supported for backend-iced InstructionInfo",
        ))
    }
}

#[cfg(feature = "backend-capstone")]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstructionInfo {
    pub address: u64,
    pub mnemonic: std::sync::Arc<str>,
    pub op_str: std::sync::Arc<str>,
    /// Pre-computed set of Aho-Corasick pattern IDs matched against this instruction's text.
    #[serde(skip)]
    pub matched: Vec<PatternID>,
}

#[cfg(feature = "backend-capstone")]
impl InstructionInfo {
    pub fn from_capstone(insn: &capstone::Insn) -> Self {
        Self {
            address: insn.address(),
            mnemonic: insn.mnemonic().unwrap_or("").into(),
            op_str: insn.op_str().unwrap_or("").into(),
            matched: Vec::new(),
        }
    }

    pub fn address(&self) -> u64 {
        self.address
    }

    pub fn format_mnemonic(&self) -> String {
        self.mnemonic.to_string()
    }

    pub fn format_operands(&self) -> String {
        self.op_str.to_string()
    }

    pub fn format_mnemonic_into(&self, buf: &mut String) {
        buf.clear();
        buf.push_str(&self.mnemonic);
    }

    pub fn format_operands_into(&self, buf: &mut String) {
        buf.clear();
        buf.push_str(&self.op_str);
    }
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
            Self::Other(mut map) => {
                if map.len() == 1 && map.contains_key("description") {
                    None
                } else {
                    if let Some(val) = map.remove("number") {
                        let target_num = crate::utils::rules::parse_number_constant(&val);
                        map.insert(
                            "number".to_string(),
                            serde_json::Value::String(target_num.to_lowercase()),
                        );
                    }
                    Some(Self::Other(map))
                }
            }
            Self::Api { api } => Some(Self::Api {
                api: api.to_lowercase(),
            }),
            Self::Import { import } => Some(Self::Import {
                import: import.to_lowercase(),
            }),
            Self::Export { export } => Some(Self::Export {
                export: export.to_lowercase(),
            }),
            Self::String { string } => Some(Self::String {
                string: string.to_lowercase(),
            }),
            Self::Mnemonic { mnemonic } => Some(Self::Mnemonic {
                mnemonic: mnemonic.to_lowercase(),
            }),
            Self::Match { match_name } => Some(Self::Match {
                match_name: match_name.to_lowercase(),
            }),
            Self::Os { os } => Some(Self::Os {
                os: os.to_lowercase(),
            }),
            Self::Arch { arch } => Some(Self::Arch {
                arch: arch.to_lowercase(),
            }),
            Self::Characteristic { characteristic } => Some(Self::Characteristic {
                characteristic: characteristic.to_lowercase(),
            }),
            other => Some(other),
        }
    }

    /// Recursively evaluates the condition against the feature set.
    pub fn matches(&self, features: &FeatureSet, needle: &NeedleIndex) -> bool {
        match self {
            // Logic Operators
            Self::And { and } => and.iter().all(|c| c.matches(features, needle)),
            Self::Or { or } => or.iter().any(|c| c.matches(features, needle)),
            Self::Not { not } => !not.matches(features, needle),
            // capa Supported Feature Assertions
            Self::Api { api } => features.apis.iter().any(|a| a.contains(api)),
            Self::String { string } => features.strings.iter().any(|s| s.contains(string)),
            Self::Mnemonic { mnemonic } => features.mnemonics.iter().any(|m| &**m == mnemonic),
            Self::Match { match_name } => features
                .apis
                .iter()
                .chain(features.strings.iter())
                .any(|s| s.contains(match_name)),
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
            Self::BasicBlockScope { conditions } => {
                if !conditions.iter().all(|cond| cond.is_present(needle)) {
                    return false;
                }
                features.blocks.iter().any(|block| {
                    conditions
                        .iter()
                        .all(|cond| cond.matches_block(block, needle))
                })
            }
            Self::CallScope { conditions } => {
                if !conditions.iter().all(|cond| cond.is_present(needle)) {
                    return false;
                }
                features.blocks.iter().any(|block| {
                    block.instructions.iter().any(|insn| {
                        conditions
                            .iter()
                            .all(|cond| cond.matches_instruction(insn, needle))
                    })
                })
            }
            // Minimally match OS and Arch if present
            Self::Os { os } => features.os.contains(os),
            Self::Arch { arch } => features.arch.contains(arch),
            Self::Import { import } => features.apis.iter().any(|api| api.contains(import)),
            Self::Export { export } => features.apis.iter().any(|api| api.contains(export)),
            Self::Section { section } => features.section_entropies.contains_key(section),
            Self::Characteristic { characteristic } if characteristic.contains("packed") => {
                features.has_packer_sig
            }
            // this represents a catch all condition for the features
            // that are not currently unhandled or supported
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
                                .filter(|a| a.contains(api_name))
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
                                .filter(|s| s.contains(str_val))
                                .count();
                            if count < threshold {
                                return false;
                            }
                        } else if inner.starts_with("mnemonic(") && inner.ends_with(")") {
                            let mnem = &inner[9..inner.len() - 1];
                            let threshold = parse_count_threshold(value);
                            let count = if features.mnemonics.iter().any(|m| **m == *mnem) {
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
                        let target_num = value.as_str().unwrap_or("");
                        if !features.strings.iter().any(|s| s.contains(target_num)) {
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

    /// Evaluates the condition directly against a single instruction via the pre-computed NeedleIndex match set.
    pub fn matches_instruction(
        &self,
        insn: &crate::core::types::InstructionInfo,
        needle: &NeedleIndex,
    ) -> bool {
        match self {
            Self::And { and } => and.iter().all(|c| c.matches_instruction(insn, needle)),
            Self::Or { or } => or.iter().any(|c| c.matches_instruction(insn, needle)),
            Self::Not { not } => !not.matches_instruction(insn, needle),
            Self::Api { api } | Self::Import { import: api } | Self::Export { export: api } => {
                needle
                    .lookup
                    .get(api)
                    .is_some_and(|id| insn.matched.contains(id))
            }
            Self::String { string } => needle
                .lookup
                .get(string)
                .is_some_and(|id| insn.matched.contains(id)),
            Self::Mnemonic { mnemonic } => needle
                .lookup
                .get(mnemonic)
                .is_some_and(|id| insn.matched.contains(id)),
            Self::Match { match_name } => needle
                .lookup
                .get(match_name)
                .is_some_and(|id| insn.matched.contains(id)),
            Self::Other(map) => {
                for (key, value) in map {
                    if key == "description" {
                        continue;
                    }
                    if key == "number" || key == "offset" {
                        let target_num = value.as_str().unwrap_or("");
                        if let Some(id) = needle.lookup.get(target_num) {
                            if !insn.matched.contains(id) {
                                return false;
                            }
                        } else {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                true
            }
            _ => false,
        }
    }

    /// Evaluates the condition directly against a basic block via the pre-computed NeedleIndex match sets.
    pub fn matches_block(
        &self,
        block: &crate::core::types::BasicBlock,
        needle: &NeedleIndex,
    ) -> bool {
        match self {
            Self::And { and } => and.iter().all(|c| c.matches_block(block, needle)),
            Self::Or { or } => or.iter().any(|c| c.matches_block(block, needle)),
            Self::Not { not } => !not.matches_block(block, needle),
            Self::Api { api } | Self::Import { import: api } | Self::Export { export: api } => {
                needle.lookup.get(api).is_some_and(|id| {
                    block
                        .instructions
                        .iter()
                        .any(|insn| insn.matched.contains(id))
                })
            }
            Self::String { string } => needle.lookup.get(string).is_some_and(|id| {
                block
                    .instructions
                    .iter()
                    .any(|insn| insn.matched.contains(id))
            }),
            Self::Mnemonic { mnemonic } => needle.lookup.get(mnemonic).is_some_and(|id| {
                block
                    .instructions
                    .iter()
                    .any(|insn| insn.matched.contains(id))
            }),
            Self::Match { match_name } => needle.lookup.get(match_name).is_some_and(|id| {
                block
                    .instructions
                    .iter()
                    .any(|insn| insn.matched.contains(id))
            }),
            Self::BasicBlockScope { conditions } => conditions
                .iter()
                .all(|cond| cond.matches_block(block, needle)),
            Self::CallScope { conditions } => block.instructions.iter().any(|insn| {
                conditions
                    .iter()
                    .all(|cond| cond.matches_instruction(insn, needle))
            }),
            Self::Other(map) => {
                for (key, value) in map {
                    if key == "description" {
                        continue;
                    }
                    if key == "number" || key == "offset" {
                        let target_num = crate::utils::rules::parse_number_constant(value);
                        if let Some(id) = needle.lookup.get(&target_num) {
                            let matched = block
                                .instructions
                                .iter()
                                .any(|insn| insn.matched.contains(id));
                            if !matched {
                                return false;
                            }
                        } else {
                            return false;
                        }
                    } else if key.starts_with("count(") && key.ends_with(")") {
                        let inner = &key[6..key.len() - 1];
                        let target_str = if inner.starts_with("api(") && inner.ends_with(")") {
                            &inner[4..inner.len() - 1]
                        } else if inner.starts_with("string(") && inner.ends_with(")") {
                            &inner[7..inner.len() - 1]
                        } else if inner.starts_with("mnemonic(") && inner.ends_with(")") {
                            &inner[9..inner.len() - 1]
                        } else {
                            ""
                        };

                        if let Some(id) = needle.lookup.get(&target_str.to_lowercase()) {
                            let count = block
                                .instructions
                                .iter()
                                .filter(|insn| insn.matched.contains(id))
                                .count();
                            let threshold = crate::utils::rules::parse_count_threshold(value);
                            if count < threshold {
                                return false;
                            }
                        } else {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                true
            }
            _ => false,
        }
    }

    /// Checks if the condition has a chance of matching based on globally present NeedleIndex patterns.
    pub fn is_present(&self, needle: &NeedleIndex) -> bool {
        match self {
            Self::And { and } => and.iter().all(|c| c.is_present(needle)),
            Self::Or { or } => or.iter().any(|c| c.is_present(needle)),
            Self::Not { .. } => true, // Conservative
            Self::Api { api } | Self::Import { import: api } | Self::Export { export: api } => {
                needle
                    .lookup
                    .get(api)
                    .is_some_and(|id| needle.present[id.as_usize()].load(Ordering::Relaxed))
            }
            Self::String { string } => needle
                .lookup
                .get(string)
                .is_some_and(|id| needle.present[id.as_usize()].load(Ordering::Relaxed)),
            Self::Mnemonic { mnemonic } => needle
                .lookup
                .get(mnemonic)
                .is_some_and(|id| needle.present[id.as_usize()].load(Ordering::Relaxed)),
            Self::Match { match_name } => needle
                .lookup
                .get(match_name)
                .is_some_and(|id| needle.present[id.as_usize()].load(Ordering::Relaxed)),
            Self::Other(map) => {
                for (key, value) in map {
                    if key == "number" || key == "offset" {
                        let target_num = crate::utils::rules::parse_number_constant(value);
                        if let Some(id) = needle.lookup.get(&target_num) {
                            if !needle.present[id.as_usize()]
                                .load(std::sync::atomic::Ordering::Relaxed)
                            {
                                return false;
                            }
                        } else {
                            return false;
                        }
                    }
                }
                true
            }
            _ => true,
        }
    }
}

/// Aho-Corasick based multi-pattern index for fast rule condition matching.
///
/// Built once from all loaded rules, this pre-compiles every string pattern
/// (api names, imports, exports, strings, mnemonics, match targets) into a
/// single finite-state automaton. The automaton is then run once per instruction
/// to populate `InstructionInfo::matched`, turning subsequent rule evaluation
/// lookups into O(1) `HashSet::contains` checks.
pub struct NeedleIndex {
    /// The compiled Aho-Corasick automaton (case-insensitive).
    pub automaton: AhoCorasick,
    pub lookup: HashMap<String, PatternID>,
    pub present: Vec<AtomicBool>,
}

impl NeedleIndex {
    /// Builds an Aho-Corasick automaton from all string-bearing conditions
    /// found recursively inside the loaded rule set.
    pub fn build_from_rules(rules: &[Rule]) -> Self {
        let mut pattern_set = HashSet::new();

        for r in rules {
            for cond in &r.rule.features {
                Self::collect_patterns(cond, &mut pattern_set);
            }
        }

        // Convert to a deterministic ordered vec so PatternID indices are stable
        let patterns: Vec<String> = pattern_set.into_iter().collect();

        let mut lookup = HashMap::with_capacity(patterns.len());
        for (idx, pat) in patterns.iter().enumerate() {
            lookup.insert(pat.clone(), PatternID::must(idx));
        }

        let automaton = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&patterns)
            .expect("NeedleIndex: failed to build Aho-Corasick automaton");

        let present = (0..patterns.len())
            .map(|_| AtomicBool::new(false))
            .collect();

        NeedleIndex {
            automaton,
            lookup,
            present,
        }
    }

    /// Recursively walks a condition tree and collects all string patterns
    /// (lowercased) that the rule engine needs to match against instruction text.
    fn collect_patterns(cond: &RuleCondition, patterns: &mut HashSet<String>) {
        match cond {
            RuleCondition::Api { api } => {
                patterns.insert(api.to_lowercase());
            }
            RuleCondition::Import { import } => {
                patterns.insert(import.to_lowercase());
            }
            RuleCondition::Export { export } => {
                patterns.insert(export.to_lowercase());
            }
            RuleCondition::String { string } => {
                patterns.insert(string.to_lowercase());
            }
            RuleCondition::Match { match_name } => {
                patterns.insert(match_name.to_lowercase());
            }
            RuleCondition::Mnemonic { mnemonic } => {
                patterns.insert(mnemonic.to_lowercase());
            }
            RuleCondition::And { and } => {
                and.iter().for_each(|c| Self::collect_patterns(c, patterns));
            }
            RuleCondition::Or { or } => {
                or.iter().for_each(|c| Self::collect_patterns(c, patterns));
            }
            RuleCondition::Not { not } => {
                Self::collect_patterns(not, patterns);
            }
            RuleCondition::BasicBlockScope { conditions } => {
                conditions
                    .iter()
                    .for_each(|c| Self::collect_patterns(c, patterns));
            }
            RuleCondition::CallScope { conditions } => {
                conditions
                    .iter()
                    .for_each(|c| Self::collect_patterns(c, patterns));
            }
            RuleCondition::Other(map) => {
                // Extract embedded patterns from count(...) assertions and numbers/offsets
                for (key, value) in map {
                    if key == "number" || key == "offset" {
                        let target_num = crate::utils::rules::parse_number_constant(value);
                        patterns.insert(target_num.to_lowercase());
                    } else if key.starts_with("count(") && key.ends_with(")") {
                        let inner = &key[6..key.len() - 1];
                        if inner.starts_with("api(") && inner.ends_with(")") {
                            patterns.insert(inner[4..inner.len() - 1].to_lowercase());
                        } else if inner.starts_with("string(") && inner.ends_with(")") {
                            patterns.insert(inner[7..inner.len() - 1].to_lowercase());
                        } else if inner.starts_with("mnemonic(") && inner.ends_with(")") {
                            patterns.insert(inner[9..inner.len() - 1].to_lowercase());
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// Runs the automaton once per instruction across all basic blocks in the CFG,
    /// populating each `InstructionInfo::matched` with the set of matched `PatternID`s.
    pub fn populate_cfg(&self, cfg: &mut ControlFlowGraph) {
        use rayon::prelude::*;

        // it performs Parallel over blocks, and sequential within each block (reusing buffers)
        let blocks: Vec<&mut BasicBlock> = cfg.blocks.values_mut().collect();
        blocks.into_par_iter().for_each(|block| {
            let mut buf_m = String::new();
            let mut buf_o = String::new();
            let mut haystack = String::new();

            for insn in &mut block.instructions {
                insn.format_mnemonic_into(&mut buf_m);
                insn.format_operands_into(&mut buf_o);

                haystack.clear();
                haystack.push_str(&buf_m);
                haystack.push(' ');
                haystack.push_str(&buf_o);

                for mat in self.automaton.find_iter(&haystack) {
                    let p = mat.pattern();
                    if !insn.matched.contains(&p) {
                        insn.matched.push(p);
                        self.present[p.as_usize()].store(true, Ordering::Relaxed);
                    }
                }
            }
        });
    }
}
