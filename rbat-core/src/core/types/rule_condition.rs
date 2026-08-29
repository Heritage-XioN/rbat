//! Rule condition tree, evaluation, and sanitization.

use crate::{
    core::{BasicBlock, FeatureSet, NeedleIndex, RuleTag, disassembler::InstructionInfo},
    utils::rules::parse_number_constant,
};
use ahash::{AHashMap, AHashSet};
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
    // codebase heuristics feature
    /// Requires a specific heuristic tag to be present.
    Tag(RuleTag),
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
    /// Requires a specific PE characteristic flag.
    Characteristic {
        /// The characteristic flag name.
        characteristic: String,
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
            Self::Api { api } => Some(Self::Api {
                api: Self::strip_inline_desc(&api).to_lowercase(),
            }),
            Self::Import { import } => Some(Self::Import {
                import: Self::strip_inline_desc(&import).to_lowercase(),
            }),
            Self::Export { export } => Some(Self::Export {
                export: Self::strip_inline_desc(&export).to_lowercase(),
            }),
            Self::String { string } => Some(Self::String {
                string: Self::strip_inline_desc(&string).to_lowercase(),
            }),
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
            Self::Characteristic { characteristic } => Some(Self::Characteristic {
                characteristic: Self::strip_inline_desc(&characteristic).to_lowercase(),
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
                    } else if key == "number" {
                        let mut v = val.clone();
                        if let serde_json::Value::String(s) = &mut v {
                            *s = Self::strip_inline_desc(s).to_string();
                        }
                        let target_num = parse_number_constant(&v);
                        return Some(Self::Number {
                            number: target_num.to_lowercase(),
                        });
                    } else if key == "offset" {
                        let mut v = val.clone();
                        if let serde_json::Value::String(s) = &mut v {
                            *s = Self::strip_inline_desc(s).to_string();
                        }
                        let target_num = parse_number_constant(&v);
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
                        } else {
                            None
                        };

                        if let Some(cond) = inner_cond {
                            let count = crate::utils::rules::parse_count_threshold(&val);
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

    /// Recursively evaluates the condition against the feature set and previously matched rule dependencies.
    pub fn matches(
        &self,
        features: &FeatureSet,
        needle: &NeedleIndex,
        matched_rules: &AHashSet<&str>,
    ) -> bool {
        match self {
            // Logic Operators
            Self::And { and } => and
                .iter()
                .all(|c| c.matches(features, needle, matched_rules)),
            Self::Or { or } => or
                .iter()
                .any(|c| c.matches(features, needle, matched_rules)),
            Self::Not { not } => !not.matches(features, needle, matched_rules),
            // capa Supported Feature Assertions
            Self::Api { api } => {
                if let Some(id) = needle.lookup.get(api) {
                    features.apis.contains(id)
                        || needle.present[id.as_usize()].load(Ordering::Relaxed)
                } else {
                    false
                }
            }
            Self::String { string } => features.strings.iter().any(|s| s.contains(string)),
            Self::Mnemonic { mnemonic } => {
                if let Some(id) = needle.lookup.get(mnemonic) {
                    needle.present[id.as_usize()].load(Ordering::Relaxed)
                } else {
                    false
                }
            }
            Self::Match { match_name } => matched_rules.contains(match_name.as_str()),
            Self::Entropy { section, min } => features
                .section_entropies
                .get(section.as_str())
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
            Self::Format { format } => features.binary_format.contains(format),
            Self::Import { import } => {
                if let Some(id) = needle.lookup.get(import) {
                    features.apis.contains(id)
                        || needle.present[id.as_usize()].load(Ordering::Relaxed)
                } else {
                    false
                }
            }
            Self::Export { export } => {
                if let Some(id) = needle.lookup.get(export) {
                    features.apis.contains(id)
                        || needle.present[id.as_usize()].load(Ordering::Relaxed)
                } else {
                    false
                }
            }
            Self::Section { section } => features.section_entropies.contains_key(section.as_str()),
            Self::Characteristic { characteristic } if characteristic.contains("packed") => {
                features.has_packer_sig
            }
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
                        } else {
                            features
                                .blocks
                                .iter()
                                .flat_map(|b| b.instructions.iter())
                                .filter(|insn| insn.matched.contains(id))
                                .count()
                                >= *count
                        }
                    } else {
                        false
                    }
                }
                Self::String { string } => {
                    features
                        .strings
                        .iter()
                        .filter(|s| s.contains(string))
                        .count()
                        >= *count
                }
                Self::Mnemonic { mnemonic } => {
                    if let Some(id) = needle.lookup.get(mnemonic) {
                        if !needle.present[id.as_usize()].load(Ordering::Relaxed) {
                            return 0 == *count;
                        }
                        features
                            .blocks
                            .iter()
                            .flat_map(|b| b.instructions.iter())
                            .filter(|insn| insn.matched.contains(id))
                            .count()
                            >= *count
                    } else {
                        false
                    }
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
            // this represents a catch all condition for the features
            // that are currently unhandled or supported
            Self::Other(_) => false,
            _ => false,
        }
    }

    /// Evaluates the condition directly against a single instruction via the pre-computed NeedleIndex match set.
    pub fn matches_instruction(&self, insn: &InstructionInfo, needle: &NeedleIndex) -> bool {
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
            Self::Match { .. } => false,
            Self::Number { number } | Self::Offset { offset: number } => needle
                .lookup
                .get(number)
                .is_some_and(|id| insn.matched.contains(id)),
            Self::Count { condition, count } => {
                let actual = if condition.matches_instruction(insn, needle) {
                    1
                } else {
                    0
                };
                actual >= *count
            }
            Self::Other(_) => false,
            _ => false,
        }
    }

    /// Evaluates the condition directly against a basic block via the pre-computed NeedleIndex match sets.
    pub fn matches_block(&self, block: &BasicBlock, needle: &NeedleIndex) -> bool {
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
            Self::Match { .. } => false,
            Self::BasicBlockScope { conditions } => conditions
                .iter()
                .all(|cond| cond.matches_block(block, needle)),
            Self::CallScope { conditions } => block.instructions.iter().any(|insn| {
                conditions
                    .iter()
                    .all(|cond| cond.matches_instruction(insn, needle))
            }),
            Self::Number { number } | Self::Offset { offset: number } => {
                needle.lookup.get(number).is_some_and(|id| {
                    block
                        .instructions
                        .iter()
                        .any(|insn| insn.matched.contains(id))
                })
            }
            Self::Count { condition, count } => {
                let actual = block
                    .instructions
                    .iter()
                    .filter(|insn| condition.matches_instruction(insn, needle))
                    .count();
                actual >= *count
            }
            Self::Other(_) => false,
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
            Self::Match { .. } => true,
            Self::Number { number } | Self::Offset { offset: number } => needle
                .lookup
                .get(number)
                .is_some_and(|id| needle.present[id.as_usize()].load(Ordering::Relaxed)),
            Self::Count { condition, .. } => condition.is_present(needle),
            Self::Other(_) => true,
            _ => true,
        }
    }
}
