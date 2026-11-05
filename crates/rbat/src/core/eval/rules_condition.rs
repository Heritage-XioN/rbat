//! # Capa Rule Condition Abstract Syntax Tree (AST)
//!
//! Represents the boolean condition trees and localized feature assertions defining
//! Mandiant `capa` capability signatures.
//!
//! ## Core Types
//!
//! - [`RuleCondition`]: Untagged AST enum representing boolean operators (`and`, `or`, `not`),
//!   feature assertions (`api`, `string`, `mnemonic`, `number`, `offset`), subscopes (`basic block`, `call`),
//!   and count thresholds.
//!
//! ## Overview
//!
//! `capa` rules specify capability patterns using nested boolean logic over static binary features.
//! The condition tree is evaluated against extracted [`FeatureSet`] features at specific granularities:
//! - File scope: matches binary-wide metrics, hashes, and section entropies
//! - Function scope: matches intra-procedural call sites, cycles, and local complexity
//! - Basic block scope: matches localized instruction patterns, tight loops, and register operations
//! - Instruction scope: matches individual machine instructions

use super::{CapaCharacteristic, RuleScope, StringOrVec, rules::Rule};
use crate::core::{
    disassembler::InstructionInfo,
    features::{BlockScopeFeatures, FeatureSet, FunctionScopeFeatures},
    needle::NeedleIndex,
};
use ahash::{AHashMap, AHashSet};
use aho_corasick::PatternID;
use serde::{Deserialize, Serialize};
use std::sync::atomic::Ordering;

/// Boolean logic combinations of rule conditions aligned with the Mandiant `capa` specification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum RuleCondition {
    // Logic Operators
    /// Logical AND condition.
    And {
        /// List of conditions that must all be true.
        and: Vec<RuleCondition>,
    },
    /// Logical OR condition.
    Or {
        /// List of conditions where at least one must be true.
        or: Vec<RuleCondition>,
    },
    /// Logical NOT condition.
    Not {
        /// The condition that must be false.
        not: Box<RuleCondition>,
    },
    // capa Supported Feature Assertions
    /// Requires a specific API call.
    Api {
        /// The API name (e.g. `VirtualAlloc`).
        api: String,
    },
    /// Requires a specific string literal.
    String {
        /// The string literal to find.
        string: String,
    },
    /// Requires a specific assembly mnemonic.
    Mnemonic {
        /// The mnemonic (e.g. `mov`).
        mnemonic: String,
    },
    /// Matches against another rule by name.
    Match {
        /// The name of the rule to match.
        #[serde(rename = "match")]
        match_name: String,
    },
    /// Requires the section entropy to exceed a threshold.
    Entropy {
        /// The section name.
        section: String,
        /// The minimum entropy threshold.
        min: f64,
    },
    // CFG properties & localized scopes
    /// Requires a minimum number of basic blocks in the function.
    BasicBlocksCount {
        /// The minimum basic blocks count.
        #[serde(rename = "basic_blocks_count")]
        count: usize,
    },
    /// Requires a minimum cyclomatic complexity.
    CyclomaticComplexity {
        /// The minimum complexity score.
        #[serde(rename = "cyclomatic_complexity")]
        min: usize,
    },
    /// Requires conditions to be met within the same basic block.
    BasicBlockScope {
        /// The scoped conditions.
        #[serde(rename = "basic block")]
        conditions: Vec<RuleCondition>,
    },
    /// Requires conditions to be met within a specific function call.
    CallScope {
        /// The scoped conditions.
        #[serde(rename = "call")]
        conditions: Vec<RuleCondition>,
    },
    /// Requires conditions to be met within a single machine instruction.
    InstructionScope {
        /// The scoped conditions.
        #[serde(rename = "instruction")]
        conditions: Vec<RuleCondition>,
    },
    // other capa feature checks
    /// Requires a specific exported symbol.
    Export {
        /// The exported symbol name.
        export: String,
    },
    /// Requires a specific imported symbol.
    Import {
        /// The imported symbol name.
        import: String,
    },
    /// Requires a specific PE/ELF section.
    Section {
        /// The section name.
        section: String,
    },
    /// Requires a specific Operating System target.
    Os {
        /// The OS name (e.g. `windows`).
        os: String,
    },
    /// Requires a specific Architecture target.
    Arch {
        /// The architecture name (e.g. `i386`).
        arch: String,
    },
    /// Requires a specific binary format (e.g. `pe`, `elf`, `macho`).
    Format {
        /// The binary format name (e.g. `pe`).
        format: String,
    },
    /// Requires a specific Capa or binary heuristic characteristic flag.
    Characteristic {
        /// The characteristic kind.
        characteristic: CapaCharacteristic,
    },
    /// Requires a specific number constant.
    Number {
        /// The target number string.
        number: String,
    },
    /// Requires a specific offset constant.
    Offset {
        /// The target offset string.
        offset: String,
    },
    /// A count threshold for an underlying condition.
    Count {
        /// The condition being counted.
        condition: Box<RuleCondition>,
        /// The count threshold.
        count: usize,
    },
    // catch all variant for unhandled/unsupported rules
    /// A catch-all variant for unsupported or unknown CAPA rule types.
    Other(AHashMap<String, serde_json::Value>),
}

impl RuleCondition {
    /// Strips an inline capa-style description suffix (` = <text>`) from a feature value,
    /// returning the canonical token (e.g. `aesenc = Perform ...` -> `aesenc`).
    /// capa does not support inline descriptions; generated rules that include them would
    /// otherwise never match.
    fn strip_inline_desc(s: &str) -> &str {
        s.split(" = ").next().unwrap_or(s)
    }

    /// Recursively sanitizes the condition tree to remove informational description-only nodes.
    pub(crate) fn sanitize(self) -> Option<Self> {
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
            Self::InstructionScope { conditions } => {
                let sanitized: Vec<RuleCondition> = conditions
                    .into_iter()
                    .filter_map(|c| c.sanitize())
                    .collect();
                if sanitized.is_empty() {
                    None
                } else {
                    Some(Self::InstructionScope {
                        conditions: sanitized,
                    })
                }
            }
            Self::Api { api } => Some(Self::Api {
                api: Self::strip_inline_desc(&api).to_lowercase(),
            }),
            Self::Import { import } => Some(Self::Import {
                import: Self::strip_inline_desc(&import).to_lowercase(),
            }),
            Self::Export { export } => Some(Self::Export {
                export: Self::strip_inline_desc(&export).to_lowercase(),
            }),
            Self::String { string } => {
                let stripped = Self::strip_inline_desc(&string);
                if Self::parse_capa_regex(stripped).is_some() {
                    Some(Self::String {
                        string: stripped.to_string(),
                    })
                } else {
                    Some(Self::String {
                        string: stripped.to_lowercase(),
                    })
                }
            }
            Self::Mnemonic { mnemonic } => Some(Self::Mnemonic {
                mnemonic: Self::strip_inline_desc(&mnemonic).to_lowercase(),
            }),
            Self::Match { match_name } => Some(Self::Match {
                match_name: Self::strip_inline_desc(&match_name).to_lowercase(),
            }),
            Self::Os { os } => Some(Self::Os {
                os: Self::strip_inline_desc(&os).to_lowercase(),
            }),
            Self::Arch { arch } => Some(Self::Arch {
                arch: Self::strip_inline_desc(&arch).to_lowercase(),
            }),
            Self::Format { format } => Some(Self::Format {
                format: Self::strip_inline_desc(&format).to_lowercase(),
            }),
            Self::Characteristic { characteristic } => {
                Some(Self::Characteristic { characteristic })
            }
            Self::Count { condition, count } => condition.sanitize().map(|c| Self::Count {
                condition: Box::new(c),
                count,
            }),
            Self::Number { number } => Some(Self::Number {
                number: Self::strip_inline_desc(&number).to_lowercase(),
            }),
            Self::Offset { offset } => Some(Self::Offset {
                offset: Self::strip_inline_desc(&offset).to_lowercase(),
            }),
            Self::Other(mut map) => {
                if map.len() == 1 {
                    let key = map.keys().next().unwrap().clone();
                    let val = map.remove(&key).unwrap();

                    if key == "description" {
                        return None;
                    } else if key == "code_cave" || key == "code cave" {
                        return Some(Self::Characteristic {
                            characteristic: CapaCharacteristic::CodeCave,
                        });
                    } else if key == "packer_sig" || key == "packer sig" || key == "packed" {
                        return Some(Self::Characteristic {
                            characteristic: CapaCharacteristic::Packed,
                        });
                    } else if key == "loop" {
                        return Some(Self::Characteristic {
                            characteristic: CapaCharacteristic::Loop,
                        });
                    } else if key == "number" || key.ends_with(".number") {
                        let mut v = val.clone();
                        if let serde_json::Value::String(s) = &mut v {
                            *s = Self::strip_inline_desc(s).to_string();
                        }
                        let target_num = StringOrVec::parse_number_constant(&v);
                        return Some(Self::Number {
                            number: target_num.to_lowercase(),
                        });
                    } else if key == "offset" || key.ends_with(".offset") {
                        let mut v = val.clone();
                        if let serde_json::Value::String(s) = &mut v {
                            *s = Self::strip_inline_desc(s).to_string();
                        }
                        let target_num = StringOrVec::parse_number_constant(&v);
                        return Some(Self::Offset {
                            offset: target_num.to_lowercase(),
                        });
                    } else if key.starts_with("count(") && key.ends_with(")") {
                        let inner_str = &key[6..key.len() - 1]; // e.g. "api(VirtualAlloc)"
                        let inner_cond = if inner_str.starts_with("api(") {
                            Some(Self::Api {
                                api: inner_str[4..inner_str.len() - 1].to_string(),
                            })
                        } else if inner_str.starts_with("match(") {
                            Some(Self::Match {
                                match_name: inner_str[6..inner_str.len() - 1].to_string(),
                            })
                        } else if inner_str.starts_with("string(") {
                            Some(Self::String {
                                string: inner_str[7..inner_str.len() - 1].to_string(),
                            })
                        } else if inner_str.starts_with("mnemonic(") {
                            Some(Self::Mnemonic {
                                mnemonic: inner_str[9..inner_str.len() - 1].to_string(),
                            })
                        } else if inner_str.starts_with("characteristic(") {
                            Some(Self::Characteristic {
                                characteristic: CapaCharacteristic::parse(
                                    &inner_str[15..inner_str.len() - 1],
                                ),
                            })
                        } else if inner_str.starts_with("number(") {
                            Some(Self::Number {
                                number: inner_str[7..inner_str.len() - 1].to_string(),
                            })
                        } else if inner_str.starts_with("offset(") {
                            Some(Self::Offset {
                                offset: inner_str[7..inner_str.len() - 1].to_string(),
                            })
                        } else if inner_str == "basic block"
                            || inner_str == "basic_block"
                            || inner_str == "basic blocks"
                        {
                            Some(Self::BasicBlockScope {
                                conditions: Vec::new(),
                            })
                        } else if inner_str == "instruction" || inner_str == "instructions" {
                            Some(Self::InstructionScope {
                                conditions: Vec::new(),
                            })
                        } else if inner_str == "call" || inner_str == "calls" {
                            Some(Self::CallScope {
                                conditions: Vec::new(),
                            })
                        } else {
                            let characteristic = CapaCharacteristic::parse(inner_str);
                            if characteristic != CapaCharacteristic::Unsupported {
                                Some(Self::Characteristic { characteristic })
                            } else {
                                None
                            }
                        };

                        if let Some(cond) = inner_cond {
                            let count = StringOrVec::parse_count_threshold(&val);
                            if let Some(sanitized_cond) = cond.sanitize() {
                                return Some(Self::Count {
                                    condition: Box::new(sanitized_cond),
                                    count,
                                });
                            }
                        }
                    }
                    map.insert(key, val);
                    Some(Self::Other(map))
                } else {
                    Some(Self::Other(map))
                }
            }
            other => Some(other),
        }
    }

    /// Evaluates the condition against whole-binary file scope features.
    #[inline]
    pub(crate) fn matches_file_scope(
        &self,
        features: &FeatureSet,
        needle: &NeedleIndex,
        matched_rules: &AHashSet<&str>,
    ) -> bool {
        match self {
            // Logic Operators
            Self::And { and } => and
                .iter()
                .all(|c| c.matches_file_scope(features, needle, matched_rules)),
            Self::Or { or } => or
                .iter()
                .any(|c| c.matches_file_scope(features, needle, matched_rules)),
            Self::Not { not } => !not.matches_file_scope(features, needle, matched_rules),
            // capa Supported Feature Assertions
            Self::Api { api } => {
                if let Some(id) = needle.lookup.get(api) {
                    features.file_scope.apis.contains(id)
                        || needle.present[id.as_usize()].load(Ordering::Relaxed)
                } else {
                    false
                }
            }
            Self::String { string } => {
                if Self::parse_capa_regex(string).is_some() {
                    needle.matches_regex(
                        string,
                        features.file_scope.raw_buffer,
                        &features.file_scope.strings,
                    )
                } else {
                    let in_instructions = needle
                        .lookup
                        .get(string)
                        .is_some_and(|id| needle.present[id.as_usize()].load(Ordering::Relaxed));

                    in_instructions
                        || features.file_scope.strings.contains(string)
                        || features
                            .file_scope
                            .strings
                            .iter()
                            .any(|s| s.contains(string))
                }
            }
            Self::Mnemonic { mnemonic } => {
                if let Some(id) = needle.lookup.get(mnemonic) {
                    needle.present[id.as_usize()].load(Ordering::Relaxed)
                } else {
                    false
                }
            }
            Self::Match { match_name } => matched_rules.contains(match_name.as_str()),
            Self::Entropy { section, min } => features
                .file_scope
                .section_entropies
                .get(section.as_str())
                .map(|&e| e >= *min)
                .unwrap_or(false),
            // cfg and basic block checks
            Self::BasicBlocksCount { count } => features.file_scope.basic_blocks_count >= *count,
            Self::CyclomaticComplexity { min } => {
                features.file_scope.max_cyclomatic_complexity >= *min
            }
            Self::BasicBlockScope { conditions } => {
                if !conditions
                    .iter()
                    .all(|cond| cond.is_present(needle, features, matched_rules))
                {
                    return false;
                }
                let cand = Rule::candidates_for(
                    conditions,
                    features,
                    needle,
                    matched_rules,
                    RuleScope::BasicBlock,
                );
                if cand.is_empty() {
                    return false;
                }
                if let Some(candidates) = cand.as_slice() {
                    candidates.iter().any(|&idx| {
                        let block = &features.basic_block_scope[idx as usize];
                        conditions.iter().all(|cond| {
                            cond.matches_basic_block_scope(block, features, needle, matched_rules)
                        })
                    })
                } else {
                    features.basic_block_scope.iter().any(|block| {
                        conditions.iter().all(|cond| {
                            cond.matches_basic_block_scope(block, features, needle, matched_rules)
                        })
                    })
                }
            }
            Self::CallScope { conditions } | Self::InstructionScope { conditions } => {
                if !conditions
                    .iter()
                    .all(|cond| cond.is_present(needle, features, matched_rules))
                {
                    return false;
                }
                let cand = Rule::candidates_for(
                    conditions,
                    features,
                    needle,
                    matched_rules,
                    RuleScope::Instruction,
                );
                if cand.is_empty() {
                    return false;
                }
                if let Some(candidates) = cand.as_slice() {
                    candidates.iter().any(|&idx| {
                        let block = &features.basic_block_scope[idx as usize];
                        block.instructions.iter().any(|insn| {
                            conditions.iter().all(|cond| {
                                cond.matches_instruction_scope(
                                    insn,
                                    features,
                                    needle,
                                    matched_rules,
                                )
                            })
                        })
                    })
                } else {
                    features.basic_block_scope.iter().any(|block| {
                        block.instructions.iter().any(|insn| {
                            conditions.iter().all(|cond| {
                                cond.matches_instruction_scope(
                                    insn,
                                    features,
                                    needle,
                                    matched_rules,
                                )
                            })
                        })
                    })
                }
            }
            // Minimally match OS and Arch if present
            Self::Os { os } => features.file_scope.os.contains(os),
            Self::Arch { arch } => features.file_scope.arch.contains(arch),
            Self::Format { format } => features.file_scope.binary_format.contains(format),
            Self::Import { import } => {
                if let Some(id) = needle.lookup.get(import) {
                    features.file_scope.apis.contains(id)
                        || needle.present[id.as_usize()].load(Ordering::Relaxed)
                } else {
                    false
                }
            }
            Self::Export { export } => {
                if let Some(id) = needle.lookup.get(export) {
                    features.file_scope.apis.contains(id)
                        || needle.present[id.as_usize()].load(Ordering::Relaxed)
                } else {
                    false
                }
            }
            Self::Section { section } => features
                .file_scope
                .section_entropies
                .contains_key(section.as_str()),
            Self::Characteristic { characteristic } => match characteristic {
                CapaCharacteristic::Packed => features.file_scope.has_packer_sig,
                CapaCharacteristic::CodeCave => features.file_scope.has_code_cave,
                CapaCharacteristic::Loop => features.file_scope.has_loop,
                CapaCharacteristic::TightLoop => features.file_scope.has_tight_loop(),
                CapaCharacteristic::RecursiveCall => {
                    !features.recursive_functions().is_empty()
                        || features.function_scope.iter().any(|f| f.is_recursive)
                }
                CapaCharacteristic::CallsFrom => {
                    features.function_scope.iter().any(|f| f.calls_from > 0)
                }
                CapaCharacteristic::Nzxor => features.file_scope.has_nzxor(),
                CapaCharacteristic::PebAccess => features.file_scope.has_peb_access(),
                CapaCharacteristic::FsAccess => features.file_scope.has_fs_access(),
                CapaCharacteristic::GsAccess => features.file_scope.has_gs_access(),
                CapaCharacteristic::CrossSectionFlow
                | CapaCharacteristic::IndirectCall
                | CapaCharacteristic::UnmanagedCall
                | CapaCharacteristic::Unsupported => false,
            },
            // Supported count/offset/number features
            Self::Number { number } | Self::Offset { offset: number } => {
                if let Some(id) = needle.lookup.get(number) {
                    needle.present[id.as_usize()].load(Ordering::Relaxed)
                } else {
                    false
                }
            }
            Self::Count { condition, count } => match &**condition {
                Self::Api { api } | Self::Import { import: api } | Self::Export { export: api } => {
                    if let Some(id) = needle.lookup.get(api) {
                        if !needle.present[id.as_usize()].load(Ordering::Relaxed) {
                            0 == *count
                        } else if !features.indices.pattern_counts.is_empty() {
                            features
                                .indices
                                .pattern_counts
                                .get(id)
                                .copied()
                                .unwrap_or(0)
                                >= *count
                        } else {
                            let mut accumulated = 0;
                            'outer_api: for b in &features.basic_block_scope {
                                for insn in b.instructions {
                                    if insn.matched.contains(id) {
                                        accumulated += 1;
                                        if accumulated >= *count {
                                            break 'outer_api;
                                        }
                                    }
                                }
                            }
                            accumulated >= *count
                        }
                    } else {
                        false
                    }
                }
                Self::String { string } => {
                    if Self::parse_capa_regex(string).is_some() {
                        if !needle.is_regex_present(string) {
                            return 0 == *count;
                        }
                        if let Some((re, _)) = needle.regex_lookup.get(string) {
                            let mut accumulated = 0;
                            for s in &features.file_scope.strings {
                                if re.is_match(s.as_bytes()) {
                                    accumulated += 1;
                                    if accumulated >= *count {
                                        return true;
                                    }
                                }
                            }
                            if accumulated < *count && !features.file_scope.raw_buffer.is_empty() {
                                let buffer_matches = re
                                    .find_iter(features.file_scope.raw_buffer)
                                    .take(*count - accumulated)
                                    .count();
                                accumulated += buffer_matches;
                            }
                            accumulated >= *count
                        } else {
                            0 == *count
                        }
                    } else {
                        if let Some(id) = needle.lookup.get(string)
                            && !needle.present[id.as_usize()].load(Ordering::Relaxed)
                        {
                            return 0 == *count;
                        }
                        let mut accumulated = 0;
                        for s in &features.file_scope.strings {
                            if s.contains(string) {
                                accumulated += 1;
                                if accumulated >= *count {
                                    break;
                                }
                            }
                        }
                        accumulated >= *count
                    }
                }
                Self::Mnemonic { mnemonic } => {
                    if let Some(id) = needle.lookup.get(mnemonic) {
                        if !needle.present[id.as_usize()].load(Ordering::Relaxed) {
                            0 == *count
                        } else if !features.indices.pattern_counts.is_empty() {
                            features
                                .indices
                                .pattern_counts
                                .get(id)
                                .copied()
                                .unwrap_or(0)
                                >= *count
                        } else {
                            let mut accumulated = 0;
                            'outer_mnem: for b in &features.basic_block_scope {
                                for insn in b.instructions {
                                    if insn.matched.contains(id) {
                                        accumulated += 1;
                                        if accumulated >= *count {
                                            break 'outer_mnem;
                                        }
                                    }
                                }
                            }
                            accumulated >= *count
                        }
                    } else {
                        false
                    }
                }
                Self::Number { number } | Self::Offset { offset: number } => {
                    if let Some(id) = needle.lookup.get(number) {
                        if !needle.present[id.as_usize()].load(Ordering::Relaxed) {
                            0 == *count
                        } else if !features.indices.pattern_counts.is_empty() {
                            features
                                .indices
                                .pattern_counts
                                .get(id)
                                .copied()
                                .unwrap_or(0)
                                >= *count
                        } else {
                            let mut accumulated = 0;
                            'outer_num: for b in &features.basic_block_scope {
                                for insn in b.instructions {
                                    if insn.matched.contains(id) {
                                        accumulated += 1;
                                        if accumulated >= *count {
                                            break 'outer_num;
                                        }
                                    }
                                }
                            }
                            accumulated >= *count
                        }
                    } else {
                        false
                    }
                }
                Self::BasicBlockScope { conditions } => {
                    let cand = Rule::candidates_for(
                        conditions,
                        features,
                        needle,
                        matched_rules,
                        RuleScope::BasicBlock,
                    );
                    if cand.is_empty() {
                        return 0 == *count;
                    }
                    if let Some(candidates) = cand.as_slice() {
                        candidates
                            .iter()
                            .filter(|&&idx| {
                                let block = &features.basic_block_scope[idx as usize];
                                conditions.iter().all(|c| {
                                    c.matches_basic_block_scope(
                                        block,
                                        features,
                                        needle,
                                        matched_rules,
                                    )
                                })
                            })
                            .count()
                            >= *count
                    } else {
                        features
                            .basic_block_scope
                            .iter()
                            .filter(|block| {
                                conditions.iter().all(|c| {
                                    c.matches_basic_block_scope(
                                        block,
                                        features,
                                        needle,
                                        matched_rules,
                                    )
                                })
                            })
                            .count()
                            >= *count
                    }
                }
                Self::CallScope { conditions } | Self::InstructionScope { conditions } => {
                    let cand = Rule::candidates_for(
                        conditions,
                        features,
                        needle,
                        matched_rules,
                        RuleScope::Instruction,
                    );
                    if cand.is_empty() {
                        return 0 == *count;
                    }
                    let mut accumulated = 0;
                    if let Some(candidates) = cand.as_slice() {
                        'outer_file_insn_cand: for &idx in candidates {
                            let b = &features.basic_block_scope[idx as usize];
                            for insn in b.instructions {
                                if conditions.iter().all(|c| {
                                    c.matches_instruction_scope(
                                        insn,
                                        features,
                                        needle,
                                        matched_rules,
                                    )
                                }) {
                                    accumulated += 1;
                                    if accumulated >= *count {
                                        break 'outer_file_insn_cand;
                                    }
                                }
                            }
                        }
                    } else {
                        'outer_file_insn: for b in &features.basic_block_scope {
                            for insn in b.instructions {
                                if conditions.iter().all(|c| {
                                    c.matches_instruction_scope(
                                        insn,
                                        features,
                                        needle,
                                        matched_rules,
                                    )
                                }) {
                                    accumulated += 1;
                                    if accumulated >= *count {
                                        break 'outer_file_insn;
                                    }
                                }
                            }
                        }
                    }
                    accumulated >= *count
                }
                Self::Characteristic { characteristic } => match characteristic {
                    CapaCharacteristic::Nzxor => features.file_scope.nzxor_count >= *count,
                    CapaCharacteristic::CallsFrom => {
                        features
                            .function_scope
                            .iter()
                            .map(|f| f.calls_from)
                            .sum::<usize>()
                            >= *count
                    }
                    CapaCharacteristic::TightLoop => features.file_scope.tight_loop_count >= *count,
                    CapaCharacteristic::PebAccess => features.file_scope.peb_access_count >= *count,
                    CapaCharacteristic::FsAccess => features.file_scope.fs_access_count >= *count,
                    CapaCharacteristic::GsAccess => features.file_scope.gs_access_count >= *count,
                    _ => false,
                },
                Self::Match { match_name } => {
                    let matched_cnt = if matched_rules.contains(match_name.as_str()) {
                        1
                    } else {
                        0
                    };
                    matched_cnt >= *count
                }
                _ => false,
            },
            // Explicit unhandled / unsupported variant.
            Self::Other(_) => false,
        }
    }

    /// Evaluates the condition against a single function and its constituent basic blocks.
    #[inline]
    pub(crate) fn matches_function_scope(
        &self,
        func: &FunctionScopeFeatures,
        features: &FeatureSet,
        needle: &NeedleIndex,
        matched_rules: &AHashSet<&str>,
    ) -> bool {
        match self {
            Self::And { and } => and
                .iter()
                .all(|c| c.matches_function_scope(func, features, needle, matched_rules)),
            Self::Or { or } => or
                .iter()
                .any(|c| c.matches_function_scope(func, features, needle, matched_rules)),
            Self::Not { not } => !not.matches_function_scope(func, features, needle, matched_rules),
            Self::Api { api } | Self::Import { import: api } | Self::Export { export: api } => {
                if let Some(id) = needle.lookup.get(api) {
                    func.apis.contains(id) || func.patterns.contains(id)
                } else {
                    false
                }
            }
            Self::String { string } => {
                if Self::parse_capa_regex(string).is_some() {
                    func.block_indices.iter().any(|&i| {
                        features.basic_block_scope[i]
                            .instructions
                            .iter()
                            .any(|insn| needle.matches_regex_instruction(string, insn))
                    })
                } else if let Some(id) = needle.lookup.get(string) {
                    func.patterns.contains(id)
                } else {
                    false
                }
            }
            Self::Mnemonic { mnemonic } => {
                if let Some(id) = needle.lookup.get(mnemonic) {
                    func.patterns.contains(id)
                } else {
                    false
                }
            }
            Self::Match { match_name } => matched_rules.contains(match_name.as_str()),
            Self::Entropy { section, min } => features
                .file_scope
                .section_entropies
                .get(section.as_str())
                .map(|&e| e >= *min)
                .unwrap_or(false),
            Self::BasicBlocksCount { count } => func.basic_blocks_count >= *count,
            Self::CyclomaticComplexity { min } => func.cyclomatic_complexity >= *min,
            Self::BasicBlockScope { conditions } => {
                if !conditions
                    .iter()
                    .all(|cond| cond.is_present(needle, features, matched_rules))
                {
                    return false;
                }
                let mut req = Vec::new();
                for c in conditions {
                    c.collect_required_patterns(needle, &mut req);
                }
                if !req.is_empty() && !req.iter().all(|p| func.patterns.contains(p)) {
                    return false;
                }
                func.block_indices.iter().any(|&i| {
                    conditions.iter().all(|cond| {
                        cond.matches_basic_block_scope(
                            &features.basic_block_scope[i],
                            features,
                            needle,
                            matched_rules,
                        )
                    })
                })
            }
            Self::CallScope { conditions } | Self::InstructionScope { conditions } => {
                if !conditions
                    .iter()
                    .all(|cond| cond.is_present(needle, features, matched_rules))
                {
                    return false;
                }
                let mut req = Vec::new();
                for c in conditions {
                    c.collect_required_patterns(needle, &mut req);
                }
                if !req.is_empty() && !req.iter().all(|p| func.patterns.contains(p)) {
                    return false;
                }
                func.block_indices.iter().any(|&i| {
                    features.basic_block_scope[i]
                        .instructions
                        .iter()
                        .any(|insn| {
                            conditions.iter().all(|cond| {
                                cond.matches_instruction_scope(
                                    insn,
                                    features,
                                    needle,
                                    matched_rules,
                                )
                            })
                        })
                })
            }
            Self::Os { os } => features.file_scope.os.contains(os),
            Self::Arch { arch } => features.file_scope.arch.contains(arch),
            Self::Format { format } => features.file_scope.binary_format.contains(format),
            Self::Section { section } => features
                .file_scope
                .section_entropies
                .contains_key(section.as_str()),
            Self::Characteristic { characteristic } => match characteristic {
                CapaCharacteristic::Packed => features.file_scope.has_packer_sig,
                CapaCharacteristic::CodeCave => features.file_scope.has_code_cave,
                CapaCharacteristic::Loop => func.has_loop,
                CapaCharacteristic::TightLoop => func.has_tight_loop(),
                CapaCharacteristic::RecursiveCall => func.is_recursive,
                CapaCharacteristic::CallsFrom => func.calls_from > 0,
                CapaCharacteristic::Nzxor => func.has_nzxor(),
                CapaCharacteristic::PebAccess => func.has_peb_access(),
                CapaCharacteristic::FsAccess => func.has_fs_access(),
                CapaCharacteristic::GsAccess => func.has_gs_access(),
                CapaCharacteristic::CrossSectionFlow
                | CapaCharacteristic::IndirectCall
                | CapaCharacteristic::UnmanagedCall
                | CapaCharacteristic::Unsupported => false,
            },
            Self::Number { number } | Self::Offset { offset: number } => {
                if let Some(id) = needle.lookup.get(number) {
                    func.patterns.contains(id)
                } else {
                    false
                }
            }
            Self::Count { condition, count } => match &**condition {
                Self::Api { api } | Self::Import { import: api } | Self::Export { export: api } => {
                    if let Some(id) = needle.lookup.get(api) {
                        if !func.patterns.contains(id) {
                            0 == *count
                        } else {
                            let mut accumulated = 0;
                            'outer_fn_api: for &i in &func.block_indices {
                                for insn in features.basic_block_scope[i].instructions {
                                    if insn.matched.contains(id) {
                                        accumulated += 1;
                                        if accumulated >= *count {
                                            break 'outer_fn_api;
                                        }
                                    }
                                }
                            }
                            accumulated >= *count
                        }
                    } else {
                        false
                    }
                }
                Self::String { string } => {
                    let mut accumulated = 0;
                    if Self::parse_capa_regex(string).is_some() {
                        'outer_fn_re: for &i in &func.block_indices {
                            for insn in features.basic_block_scope[i].instructions {
                                if needle.matches_regex_instruction(string, insn) {
                                    accumulated += 1;
                                    if accumulated >= *count {
                                        break 'outer_fn_re;
                                    }
                                }
                            }
                        }
                    } else if let Some(id) = needle.lookup.get(string) {
                        'outer_fn_str: for &i in &func.block_indices {
                            for insn in features.basic_block_scope[i].instructions {
                                if insn.matched.contains(id) {
                                    accumulated += 1;
                                    if accumulated >= *count {
                                        break 'outer_fn_str;
                                    }
                                }
                            }
                        }
                    }
                    accumulated >= *count
                }
                Self::Mnemonic { mnemonic } => {
                    if let Some(id) = needle.lookup.get(mnemonic) {
                        if !func.patterns.contains(id) {
                            0 == *count
                        } else {
                            let mut accumulated = 0;
                            'outer_fn_mnem: for &i in &func.block_indices {
                                for insn in features.basic_block_scope[i].instructions {
                                    if insn.matched.contains(id) {
                                        accumulated += 1;
                                        if accumulated >= *count {
                                            break 'outer_fn_mnem;
                                        }
                                    }
                                }
                            }
                            accumulated >= *count
                        }
                    } else {
                        false
                    }
                }
                Self::Number { number } | Self::Offset { offset: number } => {
                    if let Some(id) = needle.lookup.get(number) {
                        if !func.patterns.contains(id) {
                            0 == *count
                        } else {
                            let mut accumulated = 0;
                            'outer_fn_num: for &i in &func.block_indices {
                                for insn in features.basic_block_scope[i].instructions {
                                    if insn.matched.contains(id) {
                                        accumulated += 1;
                                        if accumulated >= *count {
                                            break 'outer_fn_num;
                                        }
                                    }
                                }
                            }
                            accumulated >= *count
                        }
                    } else {
                        false
                    }
                }
                Self::BasicBlockScope { conditions } => {
                    func.block_indices
                        .iter()
                        .filter(|&&i| {
                            conditions.iter().all(|c| {
                                c.matches_basic_block_scope(
                                    &features.basic_block_scope[i],
                                    features,
                                    needle,
                                    matched_rules,
                                )
                            })
                        })
                        .count()
                        >= *count
                }
                Self::CallScope { conditions } | Self::InstructionScope { conditions } => {
                    let mut accumulated = 0;
                    'outer_fn_insn_cnt: for &i in &func.block_indices {
                        for insn in features.basic_block_scope[i].instructions {
                            if conditions.iter().all(|c| {
                                c.matches_instruction_scope(insn, features, needle, matched_rules)
                            }) {
                                accumulated += 1;
                                if accumulated >= *count {
                                    break 'outer_fn_insn_cnt;
                                }
                            }
                        }
                    }
                    accumulated >= *count
                }
                Self::Characteristic { characteristic } => match characteristic {
                    CapaCharacteristic::Nzxor => func.nzxor_count >= *count,
                    CapaCharacteristic::CallsFrom => func.calls_from >= *count,
                    CapaCharacteristic::TightLoop => func.tight_loop_count >= *count,
                    CapaCharacteristic::PebAccess => func.peb_access_count >= *count,
                    CapaCharacteristic::FsAccess => func.fs_access_count >= *count,
                    CapaCharacteristic::GsAccess => func.gs_access_count >= *count,
                    _ => false,
                },
                Self::BasicBlocksCount { count: bb_min } => {
                    func.basic_blocks_count >= *bb_min && func.basic_blocks_count >= *count
                }
                Self::Match { match_name } => {
                    let matched_cnt = if matched_rules.contains(match_name.as_str()) {
                        1
                    } else {
                        0
                    };
                    matched_cnt >= *count
                }
                _ => false,
            },
            // Explicit unhandled / unsupported variant.
            Self::Other(_) => false,
        }
    }

    /// Evaluates the condition against a single basic block.
    #[inline]
    pub(crate) fn matches_basic_block_scope(
        &self,
        block: &BlockScopeFeatures,
        features: &FeatureSet,
        needle: &NeedleIndex,
        matched_rules: &AHashSet<&str>,
    ) -> bool {
        match self {
            Self::And { and } => and
                .iter()
                .all(|c| c.matches_basic_block_scope(block, features, needle, matched_rules)),
            Self::Or { or } => or
                .iter()
                .any(|c| c.matches_basic_block_scope(block, features, needle, matched_rules)),
            Self::Not { not } => {
                !not.matches_basic_block_scope(block, features, needle, matched_rules)
            }
            Self::Api { api } | Self::Import { import: api } | Self::Export { export: api } => {
                if let Some(id) = needle.lookup.get(api) {
                    block.has_pattern(id)
                } else {
                    false
                }
            }
            Self::String { string } => {
                if Self::parse_capa_regex(string).is_some() {
                    block
                        .instructions
                        .iter()
                        .any(|insn| needle.matches_regex_instruction(string, insn))
                } else if let Some(id) = needle.lookup.get(string) {
                    block.has_pattern(id)
                } else {
                    false
                }
            }
            Self::Mnemonic { mnemonic } => {
                if let Some(id) = needle.lookup.get(mnemonic) {
                    block.has_pattern(id)
                } else {
                    false
                }
            }
            Self::Match { match_name } => matched_rules.contains(match_name.as_str()),
            Self::Entropy { section, min } => features
                .file_scope
                .section_entropies
                .get(section.as_str())
                .map(|&e| e >= *min)
                .unwrap_or(false),
            Self::BasicBlockScope { conditions } => conditions
                .iter()
                .all(|cond| cond.matches_basic_block_scope(block, features, needle, matched_rules)),
            Self::CallScope { conditions } | Self::InstructionScope { conditions } => {
                block.instructions.iter().any(|insn| {
                    conditions.iter().all(|cond| {
                        cond.matches_instruction_scope(insn, features, needle, matched_rules)
                    })
                })
            }
            Self::Os { os } => features.file_scope.os.contains(os),
            Self::Arch { arch } => features.file_scope.arch.contains(arch),
            Self::Format { format } => features.file_scope.binary_format.contains(format),
            Self::Section { section } => features
                .file_scope
                .section_entropies
                .contains_key(section.as_str()),
            Self::Characteristic { characteristic } => match characteristic {
                CapaCharacteristic::Packed => features.file_scope.has_packer_sig,
                CapaCharacteristic::CodeCave => features.file_scope.has_code_cave,
                CapaCharacteristic::TightLoop | CapaCharacteristic::Loop => block.is_tight_loop,
                CapaCharacteristic::Nzxor => block.has_nzxor(),
                CapaCharacteristic::PebAccess => block.has_peb_access(),
                CapaCharacteristic::FsAccess => block.has_fs_access(),
                CapaCharacteristic::GsAccess => block.has_gs_access(),
                _ => false,
            },
            Self::Number { number } | Self::Offset { offset: number } => {
                if let Some(id) = needle.lookup.get(number) {
                    block.has_pattern(id)
                } else {
                    false
                }
            }
            Self::Count { condition, count } => match &**condition {
                Self::Api { api } | Self::Import { import: api } | Self::Export { export: api } => {
                    let cnt = if let Some(id) = needle.lookup.get(api) {
                        block
                            .instructions
                            .iter()
                            .filter(|insn| insn.matched.contains(id))
                            .count()
                    } else {
                        0
                    };
                    cnt >= *count
                }
                Self::String { string } => {
                    let cnt = if Self::parse_capa_regex(string).is_some() {
                        block
                            .instructions
                            .iter()
                            .filter(|insn| needle.matches_regex_instruction(string, insn))
                            .count()
                    } else if let Some(id) = needle.lookup.get(string) {
                        block
                            .instructions
                            .iter()
                            .filter(|insn| insn.matched.contains(id))
                            .count()
                    } else {
                        0
                    };
                    cnt >= *count
                }
                Self::Mnemonic { mnemonic } => {
                    let cnt = if let Some(id) = needle.lookup.get(mnemonic) {
                        block
                            .instructions
                            .iter()
                            .filter(|insn| insn.matched.contains(id))
                            .count()
                    } else {
                        0
                    };
                    cnt >= *count
                }
                Self::Number { number } | Self::Offset { offset: number } => {
                    let cnt = if let Some(id) = needle.lookup.get(number) {
                        block
                            .instructions
                            .iter()
                            .filter(|insn| insn.matched.contains(id))
                            .count()
                    } else {
                        0
                    };
                    cnt >= *count
                }
                Self::Characteristic { characteristic } => match characteristic {
                    CapaCharacteristic::Nzxor => block.nzxor_count >= *count,
                    CapaCharacteristic::TightLoop | CapaCharacteristic::Loop => {
                        (if block.is_tight_loop { 1 } else { 0 }) >= *count
                    }
                    CapaCharacteristic::PebAccess => block.peb_access_count >= *count,
                    CapaCharacteristic::FsAccess => block.fs_access_count >= *count,
                    CapaCharacteristic::GsAccess => block.gs_access_count >= *count,
                    _ => false,
                },
                Self::Match { match_name } => {
                    let matched_cnt = if matched_rules.contains(match_name.as_str()) {
                        1
                    } else {
                        0
                    };
                    matched_cnt >= *count
                }
                _ => {
                    let mut actual = 0;
                    for insn in block.instructions {
                        if condition.matches_instruction_scope(
                            insn,
                            features,
                            needle,
                            matched_rules,
                        ) {
                            actual += 1;
                            if actual >= *count {
                                return true;
                            }
                        }
                    }
                    actual >= *count
                }
            },
            Self::BasicBlocksCount { .. } | Self::CyclomaticComplexity { .. } | Self::Other(_) => {
                false
            }
        }
    }

    /// Evaluates the condition against a single machine instruction.
    #[inline]
    pub(crate) fn matches_instruction_scope(
        &self,
        insn: &InstructionInfo,
        features: &FeatureSet,
        needle: &NeedleIndex,
        matched_rules: &AHashSet<&str>,
    ) -> bool {
        match self {
            Self::And { and } => and
                .iter()
                .all(|c| c.matches_instruction_scope(insn, features, needle, matched_rules)),
            Self::Or { or } => or
                .iter()
                .any(|c| c.matches_instruction_scope(insn, features, needle, matched_rules)),
            Self::Not { not } => {
                !not.matches_instruction_scope(insn, features, needle, matched_rules)
            }
            Self::Api { api } | Self::Import { import: api } | Self::Export { export: api } => {
                needle
                    .lookup
                    .get(api)
                    .is_some_and(|id| insn.matched.contains(id))
            }
            Self::String { string } => {
                if Self::parse_capa_regex(string).is_some() {
                    needle.matches_regex_instruction(string, insn)
                } else {
                    needle
                        .lookup
                        .get(string)
                        .is_some_and(|id| insn.matched.contains(id))
                }
            }
            Self::Mnemonic { mnemonic } => needle
                .lookup
                .get(mnemonic)
                .is_some_and(|id| insn.matched.contains(id)),
            Self::Match { match_name } => matched_rules.contains(match_name.as_str()),
            Self::Entropy { section, min } => features
                .file_scope
                .section_entropies
                .get(section.as_str())
                .map(|&e| e >= *min)
                .unwrap_or(false),
            Self::InstructionScope { conditions } | Self::CallScope { conditions } => conditions
                .iter()
                .all(|c| c.matches_instruction_scope(insn, features, needle, matched_rules)),
            Self::Os { os } => features.file_scope.os.contains(os),
            Self::Arch { arch } => features.file_scope.arch.contains(arch),
            Self::Format { format } => features.file_scope.binary_format.contains(format),
            Self::Section { section } => features
                .file_scope
                .section_entropies
                .contains_key(section.as_str()),
            Self::Characteristic { characteristic } => match characteristic {
                CapaCharacteristic::Packed => features.file_scope.has_packer_sig,
                CapaCharacteristic::CodeCave => features.file_scope.has_code_cave,
                CapaCharacteristic::Nzxor => FeatureSet::is_nzxor(insn),
                CapaCharacteristic::PebAccess => FeatureSet::is_peb_access(insn),
                CapaCharacteristic::FsAccess => FeatureSet::is_fs_access(insn),
                CapaCharacteristic::GsAccess => FeatureSet::is_gs_access(insn),
                _ => false,
            },
            Self::Number { number } | Self::Offset { offset: number } => needle
                .lookup
                .get(number)
                .is_some_and(|id| insn.matched.contains(id)),
            Self::Count { condition, count } => {
                let actual =
                    if condition.matches_instruction_scope(insn, features, needle, matched_rules) {
                        1
                    } else {
                        0
                    };
                actual >= *count
            }
            Self::BasicBlocksCount { .. }
            | Self::CyclomaticComplexity { .. }
            | Self::BasicBlockScope { .. }
            | Self::Other(_) => false,
        }
    }

    /// Checks if the condition has a chance of matching based on globally present NeedleIndex patterns and extracted file-level features.
    #[inline]
    pub(crate) fn is_present(
        &self,
        needle: &NeedleIndex,
        features: &FeatureSet,
        matched_rules: &AHashSet<&str>,
    ) -> bool {
        match self {
            Self::And { and } => and
                .iter()
                .all(|c| c.is_present(needle, features, matched_rules)),
            Self::Or { or } => or
                .iter()
                .any(|c| c.is_present(needle, features, matched_rules)),
            Self::Not { .. } => true, // Conservative
            Self::Api { api } | Self::Import { import: api } | Self::Export { export: api } => {
                needle.lookup.get(api).is_some_and(|id| {
                    needle.present[id.as_usize()].load(Ordering::Relaxed)
                        || features.file_scope.apis.contains(id)
                })
            }
            Self::String { string } => {
                if Self::parse_capa_regex(string).is_some() {
                    needle.is_regex_present(string)
                } else {
                    let in_instructions = needle
                        .lookup
                        .get(string)
                        .is_some_and(|id| needle.present[id.as_usize()].load(Ordering::Relaxed));

                    in_instructions
                        || features.file_scope.strings.contains(string)
                        || features
                            .file_scope
                            .strings
                            .iter()
                            .any(|s| s.contains(string))
                }
            }
            Self::Mnemonic { mnemonic } => needle
                .lookup
                .get(mnemonic)
                .is_some_and(|id| needle.present[id.as_usize()].load(Ordering::Relaxed)),
            Self::Match { match_name } => matched_rules.contains(match_name.as_str()),
            Self::Number { number } | Self::Offset { offset: number } => needle
                .lookup
                .get(number)
                .is_some_and(|id| needle.present[id.as_usize()].load(Ordering::Relaxed)),
            Self::Count { condition, count } => {
                if *count == 0 {
                    true
                } else {
                    condition.is_present(needle, features, matched_rules)
                }
            }
            Self::Characteristic { characteristic } => match characteristic {
                CapaCharacteristic::Nzxor => features.file_scope.has_nzxor(),
                CapaCharacteristic::PebAccess => features.file_scope.has_peb_access(),
                CapaCharacteristic::FsAccess => features.file_scope.has_fs_access(),
                CapaCharacteristic::GsAccess => features.file_scope.has_gs_access(),
                CapaCharacteristic::TightLoop => features.file_scope.has_tight_loop(),
                CapaCharacteristic::Loop => features.file_scope.has_loop,
                CapaCharacteristic::Packed => features.file_scope.has_packer_sig,
                CapaCharacteristic::CodeCave => features.file_scope.has_code_cave,
                _ => true,
            },
            Self::BasicBlockScope { conditions }
            | Self::CallScope { conditions }
            | Self::InstructionScope { conditions } => conditions
                .iter()
                .all(|c| c.is_present(needle, features, matched_rules)),
            Self::Os { os } => {
                features.file_scope.os.is_empty() || features.file_scope.os.contains(os)
            }
            Self::Arch { arch } => {
                features.file_scope.arch.is_empty() || features.file_scope.arch.contains(arch)
            }
            Self::Format { format } => {
                features.file_scope.binary_format.is_empty()
                    || features.file_scope.binary_format.contains(format)
            }
            _ => true,
        }
    }

    /// Collects required pattern IDs that MUST be matched for this condition to be satisfied.
    pub(crate) fn collect_required_patterns(&self, needle: &NeedleIndex, out: &mut Vec<PatternID>) {
        match self {
            Self::Api { api } | Self::Import { import: api } | Self::Export { export: api } => {
                if let Some(&id) = needle.lookup.get(api) {
                    out.push(id);
                }
            }
            Self::String { string } => {
                if Self::parse_capa_regex(string).is_none()
                    && let Some(&id) = needle.lookup.get(string)
                {
                    out.push(id);
                }
            }
            Self::Mnemonic { mnemonic } => {
                if let Some(&id) = needle.lookup.get(mnemonic) {
                    out.push(id);
                }
            }
            Self::Number { number } | Self::Offset { offset: number } => {
                if let Some(&id) = needle.lookup.get(number) {
                    out.push(id);
                }
            }
            Self::And { and } => {
                for cond in and {
                    cond.collect_required_patterns(needle, out);
                }
            }
            Self::BasicBlockScope { conditions }
            | Self::CallScope { conditions }
            | Self::InstructionScope { conditions } => {
                for cond in conditions {
                    cond.collect_required_patterns(needle, out);
                }
            }
            Self::Count { condition, count } if *count > 0 => {
                condition.collect_required_patterns(needle, out);
            }
            _ => {}
        }
    }

    /// Returns true if this condition tree contains any `match:` rule dependencies.
    pub(crate) fn has_match_dependency(&self) -> bool {
        match self {
            Self::Match { .. } => true,
            Self::And { and } => and.iter().any(|c| c.has_match_dependency()),
            Self::Or { or } => or.iter().any(|c| c.has_match_dependency()),
            Self::Not { not } => not.has_match_dependency(),
            Self::Count { condition, .. } => condition.has_match_dependency(),
            Self::BasicBlockScope { conditions }
            | Self::CallScope { conditions }
            | Self::InstructionScope { conditions } => {
                conditions.iter().any(|c| c.has_match_dependency())
            }
            _ => false,
        }
    }

    /// Parses a Capa regular expression string literal in `/pattern/flags` syntax.
    ///
    /// Distinguishes Capa regular expression literals from ordinary string values and Unix filesystem paths
    /// (e.g. `"/etc/os-release"` or `"/proc/self/maps"`). Validates that the string starts and terminates
    /// with a delimiter slash, that only supported flags (`i`, `s`, `m`) follow the terminating slash,
    /// and that the inner pattern is non-empty.
    ///
    /// # Parameters
    ///
    /// - `s`: Raw string slice to test and parse.
    ///
    /// # Returns
    ///
    /// `Some((pattern, is_case_insensitive))` containing the extracted inner regex slice and a boolean
    /// indicating whether case insensitivity (`i` flag) was specified, or `None` if the input is not a regex literal.
    pub(crate) fn parse_capa_regex(s: &str) -> Option<(&str, bool)> {
        if !s.starts_with('/') || s.len() < 2 {
            return None;
        }
        let last_slash = s.rfind('/')?;
        if last_slash == 0 {
            return None;
        }
        let flags = &s[last_slash + 1..];
        if !flags.chars().all(|c| matches!(c, 'i' | 's' | 'm')) {
            return None;
        }
        let pattern = &s[1..last_slash];
        if pattern.is_empty() {
            return None;
        }
        let is_case_insensitive = flags.contains('i');
        Some((pattern, is_case_insensitive))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::eval::test_helpers::*;
    use crate::core::eval::{RuleInner, RuleMeta, RuleScope};
    use crate::core::{cfg::BasicBlock, disassembler::InstructionInfo, needle::NeedleIndex};
    use ahash::{AHashMap, AHashSet};
    use rustc_hash::FxHashSet;
    use std::sync::Arc;

    #[test]
    fn test_format_condition_matching() {
        let empty_entropy = AHashMap::new();
        let mut file_scope =
            make_test_file_scope(FxHashSet::default(), &empty_entropy, 0, false, 0);
        file_scope.os = "windows pe".to_owned();
        file_scope.arch = "x86".to_owned();
        file_scope.binary_format = "pe".to_owned();

        let features = make_test_feature_set(file_scope, Vec::new(), Vec::new(), Arc::from([]));

        let rule_pe = RuleCondition::Format {
            format: "pe".to_owned(),
        };
        let rule_elf = RuleCondition::Format {
            format: "elf".to_owned(),
        };
        let needle = NeedleIndex::new(&[]);

        let empty_set = ahash::AHashSet::new();
        assert!(rule_pe.matches_file_scope(&features, &needle, &empty_set));
        assert!(!rule_elf.matches_file_scope(&features, &needle, &empty_set));
    }

    #[test]
    fn test_count_api_multiple_occurrences() {
        let rule_count = Rule {
            rule: RuleInner {
                meta: RuleMeta {
                    name: "MultipleAllocations".to_owned(),
                    ..Default::default()
                },
                features: vec![RuleCondition::Count {
                    condition: Box::new(RuleCondition::Api {
                        api: "VirtualAlloc".to_owned(),
                    }),
                    count: 2,
                }],
            },
        };

        let rules = vec![rule_count];
        let needle = NeedleIndex::new(&rules);
        let alloc_id = *needle.lookup.get("VirtualAlloc").unwrap();

        let mut insn1 = InstructionInfo {
            address: 0x1000,
            mnemonic: "call".into(),
            op_str: "VirtualAlloc".into(),
            api_resolution: Some("VirtualAlloc".into()),
            matched: smallvec::SmallVec::new(),
            inst_class: Default::default(),
        };
        insn1.matched.push(alloc_id);

        let mut insn2 = InstructionInfo {
            address: 0x1020,
            mnemonic: "call".into(),
            op_str: "VirtualAlloc".into(),
            api_resolution: Some("VirtualAlloc".into()),
            matched: smallvec::SmallVec::new(),
            inst_class: Default::default(),
        };
        insn2.matched.push(alloc_id);

        needle.present[alloc_id.as_usize()].store(true, std::sync::atomic::Ordering::Relaxed);

        let insns = vec![insn1, insn2];
        let block = BasicBlock {
            start_address: 0x1000,
            end_address: 0x1030,
            start_idx: 0,
            end_idx: insns.len(),
        };

        let empty_entropy = AHashMap::new();
        let cfg_instructions: Arc<[InstructionInfo]> = insns.clone().into();
        let block_scope = make_test_block(block.start_address, block.end_address, &insns, false);
        let mut file_scope =
            make_test_file_scope(FxHashSet::default(), &empty_entropy, 1, false, 1);
        file_scope.os = "windows".to_owned();
        file_scope.arch = "x86_64".to_owned();
        file_scope.binary_format = "pe".to_owned();

        let features_two_calls =
            make_test_feature_set(file_scope, Vec::new(), vec![block_scope], cfg_instructions);

        let matched = Rule::evaluate(&features_two_calls, &rules, &needle);
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].name, "MultipleAllocations");
    }

    #[test]
    fn test_regex_rule_evaluation() {
        let regex_rule = Rule {
            rule: RuleInner {
                meta: RuleMeta {
                    name: "DeleteShadowCopies".to_owned(),
                    ..Default::default()
                },
                features: vec![RuleCondition::String {
                    string: "/vssadmin.* delete shadows/i".to_owned(),
                }],
            },
        };

        let rules = vec![regex_rule];
        let needle = NeedleIndex::new(&rules);

        let buf = b"cmd.exe /c vssadmin.exe delete shadows /all /quiet";
        needle.scan_buffer(buf);

        let empty_entropy = AHashMap::new();
        let mut file_scope =
            make_test_file_scope(FxHashSet::default(), &empty_entropy, 0, false, 0);
        file_scope.raw_buffer = buf;
        file_scope.os = "windows".to_owned();
        file_scope.arch = "x86_64".to_owned();
        file_scope.binary_format = "pe".to_owned();

        let features = make_test_feature_set(file_scope, Vec::new(), Vec::new(), Arc::from([]));

        let matches = Rule::evaluate(&features, &rules, &needle);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name, "DeleteShadowCopies");
    }

    #[test]
    fn test_function_scope_false_positive_prevention() {
        let yaml = br#"
rule:
  meta:
    name: process injection
    scopes:
      static: function
  features:
    - and:
      - api: CreateProcessA
      - api: VirtualAllocEx
"#;
        let rule = Rule::from_slice(yaml).unwrap();
        assert_eq!(rule.static_scope(), RuleScope::Function);

        let rules = vec![rule.clone()];
        let needle = NeedleIndex::new(&rules);
        let pid_create_process = needle.lookup.get("createprocessa").copied().unwrap();
        let pid_virtual_alloc = needle.lookup.get("virtualallocex").copied().unwrap();

        needle.present[pid_create_process.as_usize()].store(true, Ordering::Relaxed);
        needle.present[pid_virtual_alloc.as_usize()].store(true, Ordering::Relaxed);

        let insns_fn1 = vec![make_test_insn(
            0x1000,
            "call",
            "CreateProcessA",
            &[pid_create_process],
        )];
        let insns_fn2 = vec![make_test_insn(
            0x2000,
            "call",
            "VirtualAllocEx",
            &[pid_virtual_alloc],
        )];

        let blocks = vec![
            make_test_block(0x1000, 0x1005, &insns_fn1, false),
            make_test_block(0x2000, 0x2005, &insns_fn2, false),
        ];

        let fn1 = make_test_function(0x1000, 0x1005, vec![0], &blocks, false, false, 0);
        let fn2 = make_test_function(0x2000, 0x2005, vec![1], &blocks, false, false, 0);

        let empty_entropy = AHashMap::new();
        let mut file_apis = FxHashSet::default();
        file_apis.insert(pid_create_process);
        file_apis.insert(pid_virtual_alloc);

        let mut file_scope = make_test_file_scope(file_apis, &empty_entropy, 2, false, 1);
        file_scope.os = "windows".to_owned();
        file_scope.arch = "x86".to_owned();
        file_scope.binary_format = "pe".to_owned();

        let features = make_test_feature_set(file_scope, vec![fn1, fn2], blocks, Arc::from([]));

        let empty_matched = AHashSet::new();
        assert!(!rule.matches(&features, &needle, &empty_matched));
    }

    #[test]
    fn test_function_scope_positive_match() {
        let yaml = br#"
  rule:
    meta:
      name: process injection
      scopes:
        static: function
    features:
      - and:
        - api: CreateProcessA
        - api: VirtualAllocEx
  "#;
        let rule = Rule::from_slice(yaml).unwrap();
        let rules = vec![rule.clone()];
        let needle = NeedleIndex::new(&rules);
        let pid_create_process = needle.lookup.get("createprocessa").copied().unwrap();
        let pid_virtual_alloc = needle.lookup.get("virtualallocex").copied().unwrap();

        needle.present[pid_create_process.as_usize()].store(true, Ordering::Relaxed);
        needle.present[pid_virtual_alloc.as_usize()].store(true, Ordering::Relaxed);

        let insns_b0 = vec![make_test_insn(
            0x1000,
            "call",
            "CreateProcessA",
            &[pid_create_process],
        )];
        let insns_b1 = vec![make_test_insn(
            0x1010,
            "call",
            "VirtualAllocEx",
            &[pid_virtual_alloc],
        )];

        let blocks = vec![
            make_test_block(0x1000, 0x1005, &insns_b0, false),
            make_test_block(0x1010, 0x1015, &insns_b1, false),
        ];

        let func = make_test_function(0x1000, 0x1015, vec![0, 1], &blocks, false, false, 0);

        let empty_entropy = AHashMap::new();
        let mut file_apis = FxHashSet::default();
        file_apis.insert(pid_create_process);
        file_apis.insert(pid_virtual_alloc);

        let mut file_scope = make_test_file_scope(file_apis, &empty_entropy, 2, false, 1);
        file_scope.os = "windows".to_owned();
        file_scope.arch = "x86".to_owned();
        file_scope.binary_format = "pe".to_owned();

        let features = make_test_feature_set(file_scope, vec![func], blocks, Arc::from([]));

        let empty_matched = AHashSet::new();
        assert!(rule.matches(&features, &needle, &empty_matched));
    }

    #[test]
    fn test_basic_block_scope_rule() {
        let yaml = br#"
rule:
  meta:
    name: xor decrypt loop
    scopes:
      static: basic block
  features:
    - and:
      - mnemonic: xor
      - number: 0x5a
"#;
        let rule = Rule::from_slice(yaml).unwrap();
        assert_eq!(rule.static_scope(), RuleScope::BasicBlock);

        let rules = vec![rule.clone()];
        let needle = NeedleIndex::new(&rules);
        let pid_xor = needle.lookup.get("xor").copied().unwrap();
        let pid_num = needle.lookup.get("90").copied().unwrap();

        needle.present[pid_xor.as_usize()].store(true, Ordering::Relaxed);
        needle.present[pid_num.as_usize()].store(true, Ordering::Relaxed);

        let insns_b1 = vec![make_test_insn(
            0x1000,
            "xor",
            "eax, 0x5a",
            &[pid_xor, pid_num],
        )];
        let insns_b2 = vec![make_test_insn(0x2000, "xor", "eax, ebx", &[pid_xor])];
        let insns_b3 = vec![make_test_insn(0x3000, "mov", "eax, 0x5a", &[pid_num])];

        let blocks_disjoint = vec![
            make_test_block(0x2000, 0x2005, &insns_b2, false),
            make_test_block(0x3000, 0x3005, &insns_b3, false),
        ];

        let empty_entropy = AHashMap::new();
        let file_scope_disjoint =
            make_test_file_scope(FxHashSet::default(), &empty_entropy, 2, false, 1);
        let features_disjoint = make_test_feature_set(
            file_scope_disjoint,
            Vec::new(),
            blocks_disjoint,
            Arc::from([]),
        );

        let empty_matched = AHashSet::new();
        assert!(!rule.matches(&features_disjoint, &needle, &empty_matched));

        let blocks_match = vec![make_test_block(0x1000, 0x1005, &insns_b1, false)];
        let file_scope_match =
            make_test_file_scope(FxHashSet::default(), &empty_entropy, 1, false, 1);
        let features_match =
            make_test_feature_set(file_scope_match, Vec::new(), blocks_match, Arc::from([]));

        assert!(rule.matches(&features_match, &needle, &empty_matched));
    }

    #[test]
    fn test_instruction_scope_rule() {
        let yaml = br#"
rule:
  meta:
    name: test cmp int3
    scopes:
      static: instruction
  features:
    - and:
      - mnemonic: cmp
      - number: 0xcc
"#;
        let rule = Rule::from_slice(yaml).unwrap();
        assert_eq!(rule.static_scope(), RuleScope::Instruction);

        let rules = vec![rule.clone()];
        let needle = NeedleIndex::new(&rules);
        let pid_cmp = needle.lookup.get("cmp").copied().unwrap();
        let pid_num = needle.lookup.get("204").copied().unwrap();

        needle.present[pid_cmp.as_usize()].store(true, Ordering::Relaxed);
        needle.present[pid_num.as_usize()].store(true, Ordering::Relaxed);

        let insns_match = vec![make_test_insn(
            0x1000,
            "cmp",
            "byte ptr [rax], 0xcc",
            &[pid_cmp, pid_num],
        )];
        let blocks_match = vec![make_test_block(0x1000, 0x1004, &insns_match, false)];

        let empty_entropy = AHashMap::new();
        let file_scope_match =
            make_test_file_scope(FxHashSet::default(), &empty_entropy, 1, false, 1);
        let features_match =
            make_test_feature_set(file_scope_match, Vec::new(), blocks_match, Arc::from([]));

        let empty_matched = AHashSet::new();
        assert!(rule.matches(&features_match, &needle, &empty_matched));

        let insns_split = vec![
            make_test_insn(0x1000, "cmp", "eax, ebx", &[pid_cmp]),
            make_test_insn(0x1002, "mov", "edx, 0xcc", &[pid_num]),
        ];
        let blocks_split = vec![make_test_block(0x1000, 0x1007, &insns_split, false)];

        let file_scope_split =
            make_test_file_scope(FxHashSet::default(), &empty_entropy, 1, false, 1);
        let features_split =
            make_test_feature_set(file_scope_split, Vec::new(), blocks_split, Arc::from([]));

        assert!(!rule.matches(&features_split, &needle, &empty_matched));
    }

    #[test]
    fn test_scope_characteristics() {
        let insn_zeroing = make_test_insn(0x1000, "xor", "eax, eax", &[]);
        let insn_nonzeroing = make_test_insn(0x1002, "xor", "eax, ebx", &[]);
        let insn_not_xor = make_test_insn(0x1004, "mov", "eax, ebx", &[]);

        assert!(!FeatureSet::is_nzxor(&insn_zeroing));
        assert!(FeatureSet::is_nzxor(&insn_nonzeroing));
        assert!(!FeatureSet::is_nzxor(&insn_not_xor));

        let yaml_loop = br#"
rule:
  meta:
    name: has loop
    scopes:
      static: function
  features:
    - characteristic: loop
"#;
        let rule_loop = Rule::from_slice(yaml_loop).unwrap();
        let needle_loop = NeedleIndex::new(std::slice::from_ref(&rule_loop));

        let insns = vec![insn_nonzeroing];
        let blocks = vec![make_test_block(0x1000, 0x1005, &insns, true)];
        let func = make_test_function(0x1000, 0x1005, vec![0], &blocks, true, true, 3);

        let empty_entropy = AHashMap::new();
        let file_scope = make_test_file_scope(FxHashSet::default(), &empty_entropy, 1, true, 1);
        let features = make_test_feature_set(file_scope, vec![func], blocks, Arc::from([]));

        let empty_matched = AHashSet::new();
        assert!(rule_loop.matches(&features, &needle_loop, &empty_matched));

        let yaml_tight = br#"
rule:
  meta:
    name: tight loop block
    scopes:
      static: basic block
  features:
    - characteristic: tight loop
"#;
        let rule_tight = Rule::from_slice(yaml_tight).unwrap();
        let needle_tight = NeedleIndex::new(std::slice::from_ref(&rule_tight));
        assert!(rule_tight.matches(&features, &needle_tight, &empty_matched));

        let yaml_rec = br#"
rule:
  meta:
    name: recursive function
    scopes:
      static: function
  features:
    - characteristic: recursive call
"#;
        let rule_rec = Rule::from_slice(yaml_rec).unwrap();
        let needle_rec = NeedleIndex::new(std::slice::from_ref(&rule_rec));
        assert!(rule_rec.matches(&features, &needle_rec, &empty_matched));

        let yaml_insn_block = br#"
rule:
  meta:
    name: nzxor instruction block
  features:
    - instruction:
      - mnemonic: xor
      - characteristic: nzxor
"#;
        let rule_insn_block = Rule::from_slice(yaml_insn_block).unwrap();
        let needle_insn_block = NeedleIndex::new(std::slice::from_ref(&rule_insn_block));
        let pid_xor = needle_insn_block.lookup.get("xor").copied().unwrap();
        needle_insn_block.present[pid_xor.as_usize()].store(true, Ordering::Relaxed);

        let insns_with_xor = vec![make_test_insn(0x1002, "xor", "eax, ebx", &[pid_xor])];
        let blocks_with_xor = vec![make_test_block(0x1000, 0x1005, &insns_with_xor, false)];
        let file_scope_insn =
            make_test_file_scope(FxHashSet::default(), &empty_entropy, 1, false, 1);
        let features_insn_block =
            make_test_feature_set(file_scope_insn, Vec::new(), blocks_with_xor, Arc::from([]));

        assert!(rule_insn_block.matches(&features_insn_block, &needle_insn_block, &empty_matched));
    }
}
