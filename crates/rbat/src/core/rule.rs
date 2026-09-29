//! # Declarative Threat Detection Rules
//!
//! This module implements the `Rule` struct, nested logic conditions,
//! rule evaluation, and embedded template loader.

use crate::core::disassembler::InstructionInfo;
use crate::core::{
    features::FeatureSet,
    types::{NeedleIndex, RbatError},
};
use ahash::{AHashMap, AHashSet};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::Ordering;

/// Embedded capa rules message pack bytes
const CAPA_RULES_MP: &[u8] = include_bytes!("../../assets/embedded_rules.mp");

/// The unified top-level structure starting with the standard `rule:` key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// The inner rule structure containing metadata and evaluation conditions.
    pub rule: RuleInner,
}

impl Rule {
    /// Parses a Rule from raw bytes, supporting native JSON and YAML Capa rules.
    pub fn from_slice(bytes: &[u8]) -> crate::core::types::RbatResult<Self> {
        let mut rule_var = if let Ok(rule) = yaml_serde::from_slice::<Rule>(bytes) {
            rule
        } else {
            serde_json::from_slice::<Rule>(bytes)
                .map_err(|e| RbatError::RuleError(e.to_string()))?
        };
        rule_var.rule.features = rule_var
            .rule
            .features
            .into_iter()
            .filter_map(|c| c.sanitize())
            .collect();
        Ok(rule_var)
    }

    /// Evaluates if the feature set matches this rule's conditions given previously matched rule dependencies.
    pub fn matches(
        &self,
        features: &FeatureSet,
        needle: &crate::core::types::NeedleIndex,
        matched_rules: &ahash::AHashSet<&str>,
    ) -> bool {
        self.rule
            .features
            .iter()
            .all(|c| c.matches(features, needle, matched_rules))
    }

    /// Returns true if this rule contains any `match:` rule dependencies.
    pub fn has_match_dependency(&self) -> bool {
        self.rule.features.iter().any(|c| c.has_match_dependency())
    }

    /// Loads all embedded Capa rules from the pre-compiled MessagePack bundle.
    pub fn load_embedded() -> Vec<Self> {
        match rmp_serde::from_slice::<Vec<Rule>>(CAPA_RULES_MP) {
            Ok(rules) => return rules,
            Err(e) => eprintln!("Warning: Failed to decode pre-compiled rules: {e}"),
        }
        Vec::new()
    }

    pub fn extend(path: &Option<PathBuf>) -> Vec<Self> {
        let mut rules = Self::load_embedded();
        if let Some(rules_dir) = path {
            let custom_rules = Rule::load_from_directory(rules_dir);
            rules.extend(custom_rules);
        }
        rules
    }

    /// Loads custom JSON and YAML rules from a directory on the local filesystem.
    pub fn load_from_directory(dir: &std::path::Path) -> Vec<Self> {
        let mut rules = Vec::new();
        Self::load_from_directory_recursive(dir, &mut rules);
        rules
    }

    fn load_from_directory_recursive(dir: &std::path::Path, rules: &mut Vec<Self>) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|name| name.starts_with('.'))
                {
                    continue;
                }
                if path.is_dir() {
                    Self::load_from_directory_recursive(&path, rules);
                } else if path.is_file() {
                    let is_rule_ext = path
                        .extension()
                        .is_some_and(|ext| ext == "json" || ext == "yaml" || ext == "yml");
                    if is_rule_ext
                        && let Ok(data) = std::fs::read(&path)
                        && let Ok(rule) = Self::from_slice(&data)
                    {
                        rules.push(rule);
                    }
                }
            }
        }
    }

    /// Evaluates a set of rules against the feature set and returns matching rule metadata.
    /// Uses two-tier partitioned evaluation:
    /// 1. Evaluates all independent rules (no `match:` dependency) once in parallel via Rayon.
    /// 2. Iteratively evaluates only the remaining dependent rules until fixpoint.
    pub fn evaluate<'rule>(
        features: &FeatureSet,
        rules: &'rule [Self],
        needle: &crate::core::types::NeedleIndex,
    ) -> Vec<&'rule RuleMeta> {
        let mut matched_names: ahash::AHashSet<&str> = ahash::AHashSet::new();
        let mut matched_indices: rustc_hash::FxHashSet<usize> = rustc_hash::FxHashSet::default();

        // Partition rules into dependent (containing match:) vs independent rules
        let (dep_rules, indep_rules): (Vec<_>, Vec<_>) = rules
            .iter()
            .enumerate()
            .partition(|(_, r)| r.has_match_dependency());

        // Pass 1: Evaluate all independent rules in parallel
        let initial_matches: Vec<(usize, &'rule str)> = indep_rules
            .into_par_iter()
            .filter(|(_, rule)| rule.matches(features, needle, &matched_names))
            .map(|(i, rule)| (i, rule.rule.meta.name.as_str()))
            .collect();

        for (idx, name) in initial_matches {
            matched_indices.insert(idx);
            matched_names.insert(name);
        }

        // Pass 2..N: Iteratively evaluate only remaining dependent rules until fixpoint
        let mut pending_deps = dep_rules;
        while !pending_deps.is_empty() {
            let (newly_matched, mut still_pending): (Vec<_>, Vec<_>) = pending_deps
                .into_par_iter()
                .partition(|(_, rule)| rule.matches(features, needle, &matched_names));

            if newly_matched.is_empty() {
                break;
            }

            for (idx, rule) in newly_matched {
                matched_indices.insert(idx);
                matched_names.insert(rule.rule.meta.name.as_str());
            }
            // Restore deterministic ordering after Rayon's unordered partition
            still_pending.sort_unstable_by_key(|(i, _)| *i);
            pending_deps = still_pending;
        }

        rules
            .iter()
            .enumerate()
            .filter(|(i, rule)| matched_indices.contains(i) && !rule.rule.meta.lib.unwrap_or(false))
            .map(|(_, rule)| &rule.rule.meta)
            .collect()
    }
}

/// The inner structure of the rules struct containing rule metadata and feature triggers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleInner {
    /// The rule metadata.
    pub meta: RuleMeta,
    /// The condition tree/features to evaluate.
    pub features: Vec<RuleCondition>,
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
    pub scopes: Option<AHashMap<String, String>>,
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
                        let target_num = StringOrVec::parse_number_constant(&v);
                        return Some(Self::Number {
                            number: target_num.to_lowercase(),
                        });
                    } else if key == "offset" {
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
                        } else {
                            None
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
                    let instructions = block.instructions(&features.cfg_instructions);
                    conditions
                        .iter()
                        .all(|cond| cond.matches_block(instructions, needle))
                })
            }
            Self::CallScope { conditions } => {
                if !conditions.iter().all(|cond| cond.is_present(needle)) {
                    return false;
                }
                features.blocks.iter().any(|block| {
                    let instructions = block.instructions(&features.cfg_instructions);
                    instructions.iter().any(|insn| {
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
                            let mut accumulated = 0;
                            'outer_api: for b in &features.blocks {
                                for insn in b.instructions(&features.cfg_instructions) {
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
                    let mut accumulated = 0;
                    for s in &features.strings {
                        if s.contains(string) {
                            accumulated += 1;
                            if accumulated >= *count {
                                break;
                            }
                        }
                    }
                    accumulated >= *count
                }
                Self::Mnemonic { mnemonic } => {
                    if let Some(id) = needle.lookup.get(mnemonic) {
                        if !needle.present[id.as_usize()].load(Ordering::Relaxed) {
                            return 0 == *count;
                        }
                        let mut accumulated = 0;
                        'outer_mnem: for b in &features.blocks {
                            for insn in b.instructions(&features.cfg_instructions) {
                                if insn.matched.contains(id) {
                                    accumulated += 1;
                                    if accumulated >= *count {
                                        break 'outer_mnem;
                                    }
                                }
                            }
                        }
                        accumulated >= *count
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
    pub fn matches_block(&self, instructions: &[InstructionInfo], needle: &NeedleIndex) -> bool {
        match self {
            Self::And { and } => and.iter().all(|c| c.matches_block(instructions, needle)),
            Self::Or { or } => or.iter().any(|c| c.matches_block(instructions, needle)),
            Self::Not { not } => !not.matches_block(instructions, needle),
            Self::Api { api } | Self::Import { import: api } | Self::Export { export: api } => {
                needle
                    .lookup
                    .get(api)
                    .is_some_and(|id| instructions.iter().any(|insn| insn.matched.contains(id)))
            }
            Self::String { string } => needle
                .lookup
                .get(string)
                .is_some_and(|id| instructions.iter().any(|insn| insn.matched.contains(id))),
            Self::Mnemonic { mnemonic } => needle
                .lookup
                .get(mnemonic)
                .is_some_and(|id| instructions.iter().any(|insn| insn.matched.contains(id))),
            Self::Match { .. } => false,
            Self::BasicBlockScope { conditions } => conditions
                .iter()
                .all(|cond| cond.matches_block(instructions, needle)),
            Self::CallScope { conditions } => instructions.iter().any(|insn| {
                conditions
                    .iter()
                    .all(|cond| cond.matches_instruction(insn, needle))
            }),
            Self::Number { number } | Self::Offset { offset: number } => needle
                .lookup
                .get(number)
                .is_some_and(|id| instructions.iter().any(|insn| insn.matched.contains(id))),
            Self::Count { condition, count } => {
                let mut actual = 0;
                for insn in instructions.iter() {
                    if condition.matches_instruction(insn, needle) {
                        actual += 1;
                        if actual >= *count {
                            return true;
                        }
                    }
                }
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

    /// Returns true if this condition tree contains any `match:` rule dependencies.
    pub fn has_match_dependency(&self) -> bool {
        match self {
            Self::Match { .. } => true,
            Self::And { and } => and.iter().any(|c| c.has_match_dependency()),
            Self::Or { or } => or.iter().any(|c| c.has_match_dependency()),
            Self::Not { not } => not.has_match_dependency(),
            Self::Count { condition, .. } => condition.has_match_dependency(),
            Self::BasicBlockScope { conditions } | Self::CallScope { conditions } => {
                conditions.iter().any(|c| c.has_match_dependency())
            }
            _ => false,
        }
    }
}

/// Supported tag-based feature conditions represented as raw strings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleTag {
    /// Signifies a code cave (NOP sled or null padding).
    CodeCave,
    /// Signifies a known packer signature.
    PackerSig,
    /// Signifies a tight loop construct.
    Loop,
}

/// Helper enum to deserialize either a single String or a `Vec<String>` from Serde
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum StringOrVec {
    /// Single string value.
    Single(String),
    /// List of string values.
    List(Vec<String>),
}

impl StringOrVec {
    /// Returns the contents as a `Vec<String>`.
    pub fn as_vec(&self) -> Vec<String> {
        match self {
            Self::Single(s) => vec![s.clone()],
            Self::List(v) => v.clone(),
        }
    }

    /// Extracts a MITRE ATT&CK technique ID from a single formatted string such as
    /// `"Execution::Command Shell [T1059.003]"` or raw `"T1059.003"`.
    pub fn extract_mitre_id_from(entry: &str) -> String {
        if let Some(start) = entry.find('[')
            && let Some(end) = entry[start..].find(']')
        {
            return entry[start + 1..start + end].to_string();
        }
        entry.to_string()
    }

    /// Parses threshold count values (e.g. `"2 or more"`, `3`, or raw integers) from rule condition properties.
    pub fn parse_count_threshold(val: &serde_json::Value) -> usize {
        if let Some(n) = val.as_u64() {
            return n as usize;
        }
        if let Some(s) = val.as_str() {
            let s = s.trim();
            if let Some(pos) = s.find(" or more")
                && let Ok(n) = s[..pos].trim().parse::<usize>()
            {
                return n;
            }
            if let Ok(n) = s.parse::<usize>() {
                return n;
            }
        }
        1
    }

    /// Parses number constraints (e.g. `"1 = HANDLE_FLAG_INHERIT"`, `-1`, or raw integers) from rule condition constants.
    pub fn parse_number_constant(val: &serde_json::Value) -> String {
        if let Some(n) = val.as_u64() {
            return n.to_string();
        }
        if let Some(n) = val.as_i64() {
            return n.to_string();
        }
        if let Some(s) = val.as_str() {
            let parts: Vec<&str> = s.split('=').collect();
            if !parts.is_empty() {
                return parts[0].trim().to_string();
            }
        }
        String::new()
    }
}

impl Default for StringOrVec {
    fn default() -> Self {
        Self::List(Vec::new())
    }
}

#[cfg(all(test, feature = "backend-capstone"))]
mod tests {
    use crate::core::{
        cfg::{BasicBlock, ControlFlowGraph},
        disassembler::InstructionInfo,
    };

    use super::*;
    use ahash::{AHashMap, AHashSet};
    use rustc_hash::FxHashSet;
    use std::sync::Arc;

    #[test]
    fn test_rule_evaluation() {
        let mut section_entropies = AHashMap::new();
        section_entropies.insert(".text", 7.8);

        let features = FeatureSet {
            apis: FxHashSet::from_iter([aho_corasick::PatternID::must(0)]),
            strings: AHashSet::new(),
            section_entropies: &section_entropies,
            has_code_cave: false,
            has_packer_sig: false,
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            binary_format: "elf".to_string(),
            basic_blocks_count: 0,
            has_loop: false,
            max_cyclomatic_complexity: 0,
            blocks: Vec::new(),
            cfg_instructions: Arc::from([]),
        };

        // Simple API Match Rule
        let rule_api = Rule {
            rule: RuleInner {
                meta: RuleMeta {
                    name: "ApiMatch".to_owned(),
                    description: Some("".to_owned()),
                    mitre_attack: Some(StringOrVec::Single("".to_owned())),
                    severity: Some("".to_owned()),
                    ..Default::default()
                },
                features: vec![RuleCondition::Api {
                    api: "VirtualAlloc".to_owned(),
                }],
            },
        };

        // Entropy Match Rule
        let rule_entropy = Rule {
            rule: RuleInner {
                meta: RuleMeta {
                    name: "EntropyMatch".to_owned(),
                    description: Some("".to_owned()),
                    mitre_attack: Some(StringOrVec::Single("".to_owned())),
                    severity: Some("".to_owned()),
                    ..Default::default()
                },
                features: vec![RuleCondition::Entropy {
                    section: ".text".to_owned(),
                    min: 7.0,
                }],
            },
        };

        let rules = vec![rule_api, rule_entropy];
        let needle = crate::core::types::NeedleIndex::build_from_rules(&rules);
        let matches = Rule::evaluate(&features, &rules, &needle);

        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].name, "ApiMatch");
        assert_eq!(matches[1].name, "EntropyMatch");
    }

    #[test]
    fn test_cfg_rules_matching() {
        // Create instructions & block representing:
        // SetHandleInformation (call)
        // SetHandleInformation (call)
        // arg: 1 = HANDLE_FLAG_INHERIT (mov/push parameter)
        let mut insns = vec![
            InstructionInfo {
                address: 0x1000,
                mnemonic: "mov".into(),
                op_str: "1 = HANDLE_FLAG_INHERIT".into(),
                api_resolution: None,
                matched: smallvec::SmallVec::new(),
                inst_class: Default::default(),
            },
            InstructionInfo {
                address: 0x1005,
                mnemonic: "call".into(),
                op_str: "SetHandleInformation".into(),
                api_resolution: None,
                matched: smallvec::SmallVec::new(),
                inst_class: Default::default(),
            },
            InstructionInfo {
                address: 0x1010,
                mnemonic: "call".into(),
                op_str: "SetHandleInformation".into(),
                api_resolution: None,
                matched: smallvec::SmallVec::new(),
                inst_class: Default::default(),
            },
        ];

        let block1 = BasicBlock {
            start_address: 0x1000,
            end_address: 0x1010,
            start_idx: 0,
            end_idx: insns.len(),
        };

        // Rule checking Loop presence & Cyclomatic Complexity
        let rule_cfg = Rule {
            rule: RuleInner {
                meta: RuleMeta {
                    name: "CfgRule".to_owned(),
                    severity: Some("High".to_owned()),
                    ..Default::default()
                },
                features: vec![
                    RuleCondition::Tag(RuleTag::Loop),
                    RuleCondition::CyclomaticComplexity { min: 4 },
                ],
            },
        };

        // Complex Rule checking local basic block scope & dynamic count(api(...))
        let rule_scope = Rule {
            rule: RuleInner {
                meta: RuleMeta {
                    name: "ScopeRule".to_owned(),
                    severity: Some("Critical".to_owned()),
                    ..Default::default()
                },
                features: vec![RuleCondition::BasicBlockScope {
                    conditions: vec![RuleCondition::And {
                        and: vec![
                            // count(api(SetHandleInformation)) >= 2
                            RuleCondition::Count {
                                condition: Box::new(RuleCondition::Api {
                                    api: "sethandleinformation".to_string(),
                                }),
                                count: 2,
                            },
                            RuleCondition::Number {
                                number: "1 = handle_flag_inherit".to_string(),
                            },
                        ],
                    }],
                }],
            },
        };

        let rules = vec![rule_cfg, rule_scope];
        let needle = crate::core::types::NeedleIndex::build_from_rules(&rules);

        // Manually populate matched sets since we bypass CFG in this test
        for insn in insns.iter_mut() {
            let haystack = format!("{} {}", insn.format_mnemonic(), insn.format_operands());
            for mat in needle.automaton.find_iter(&haystack) {
                let p = mat.pattern();
                needle.present[p.as_usize()].store(true, std::sync::atomic::Ordering::Relaxed);
                if !insn.matched.contains(&p) {
                    insn.matched.push(p);
                }
            }
        }

        let empty_entropy = AHashMap::new();
        let features = FeatureSet {
            apis: FxHashSet::default(),
            strings: AHashSet::new(),
            section_entropies: &empty_entropy,
            has_code_cave: false,
            has_packer_sig: false,
            os: "Windows".to_owned(),
            arch: "x86_64".to_owned(),
            binary_format: "pe".to_owned(),
            basic_blocks_count: 1,
            has_loop: true,
            max_cyclomatic_complexity: 5,
            blocks: vec![&block1],
            cfg_instructions: insns.into(),
        };

        let matches = Rule::evaluate(&features, &rules, &needle);

        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].name, "CfgRule");
        assert_eq!(matches[1].name, "ScopeRule");
    }

    #[test]
    fn test_format_condition_matching() {
        let empty_entropy = AHashMap::new();
        let features = FeatureSet {
            apis: FxHashSet::default(),
            strings: AHashSet::new(),
            section_entropies: &empty_entropy,
            has_code_cave: false,
            has_packer_sig: false,
            os: "windows pe".to_owned(),
            arch: "x86".to_owned(),
            binary_format: "pe".to_owned(),
            basic_blocks_count: 0,
            has_loop: false,
            max_cyclomatic_complexity: 0,
            blocks: Vec::new(),
            cfg_instructions: Arc::from([]),
        };

        let rule_pe = RuleCondition::Format {
            format: "pe".to_owned(),
        };
        let rule_elf = RuleCondition::Format {
            format: "elf".to_owned(),
        };
        let needle = crate::core::types::NeedleIndex::build_from_rules(&[]);

        let empty_set = ahash::AHashSet::new();
        assert!(rule_pe.matches(&features, &needle, &empty_set));
        assert!(!rule_elf.matches(&features, &needle, &empty_set));
    }

    #[test]
    fn test_rule_dependency_chaining_with_match() {
        // Lib rule that matches on VirtualAlloc API
        let lib_rule = Rule {
            rule: RuleInner {
                meta: RuleMeta {
                    name: "allocate memory".to_owned(),
                    lib: Some(true),
                    ..Default::default()
                },
                features: vec![RuleCondition::Api {
                    api: "VirtualAlloc".to_owned(),
                }],
            },
        };

        // Consumer rule that matches on the lib rule dependency via match:
        let consumer_rule = Rule {
            rule: RuleInner {
                meta: RuleMeta {
                    name: "allocate executable memory".to_owned(),
                    ..Default::default()
                },
                features: vec![
                    RuleCondition::Match {
                        match_name: "allocate memory".to_owned(),
                    },
                    RuleCondition::Format {
                        format: "pe".to_owned(),
                    },
                ],
            },
        };

        let rules = vec![consumer_rule, lib_rule];
        let needle = crate::core::types::NeedleIndex::build_from_rules(&rules);

        let empty_entropy = AHashMap::new();
        let mut api_pattern = None;
        if let Some(&id) = needle.lookup.get("VirtualAlloc") {
            api_pattern = Some(id);
        }

        let mut apis = FxHashSet::default();
        if let Some(id) = api_pattern {
            apis.insert(id);
        }

        let features = FeatureSet {
            apis,
            strings: AHashSet::new(),
            section_entropies: &empty_entropy,
            has_code_cave: false,
            has_packer_sig: false,
            os: "windows pe".to_owned(),
            arch: "x86_64".to_owned(),
            binary_format: "pe".to_owned(),
            basic_blocks_count: 0,
            has_loop: false,
            max_cyclomatic_complexity: 0,
            blocks: Vec::new(),
            cfg_instructions: Arc::from([]),
        };

        let matched = Rule::evaluate(&features, &rules, &needle);
        // Only the consumer rule should be returned (lib rules are filtered from final results)
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].name, "allocate executable memory");
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
        let needle = crate::core::types::NeedleIndex::build_from_rules(&rules);
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
        let features_two_calls = FeatureSet {
            apis: FxHashSet::default(),
            strings: AHashSet::new(),
            section_entropies: &empty_entropy,
            has_code_cave: false,
            has_packer_sig: false,
            os: "windows".to_owned(),
            arch: "x86_64".to_owned(),
            binary_format: "pe".to_owned(),
            basic_blocks_count: 1,
            has_loop: false,
            max_cyclomatic_complexity: 1,
            blocks: vec![&block],
            cfg_instructions: insns.into(),
        };

        let matched = Rule::evaluate(&features_two_calls, &rules, &needle);
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].name, "MultipleAllocations");
    }

    #[test]
    fn test_overlapping_needle_matching() {
        let rule_short = Rule {
            rule: RuleInner {
                meta: RuleMeta {
                    name: "AllocRule".to_owned(),
                    ..Default::default()
                },
                features: vec![RuleCondition::Api {
                    api: "alloc".to_owned(),
                }],
            },
        };

        let rule_long = Rule {
            rule: RuleInner {
                meta: RuleMeta {
                    name: "VirtualAllocRule".to_owned(),
                    ..Default::default()
                },
                features: vec![RuleCondition::Api {
                    api: "virtualalloc".to_owned(),
                }],
            },
        };

        let rules = vec![rule_short, rule_long];
        let needle = crate::core::types::NeedleIndex::build_from_rules(&rules);

        let insn = InstructionInfo {
            address: 0x1000,
            mnemonic: "call".into(),
            op_str: "0x4010".into(),
            api_resolution: Some("VirtualAlloc".into()),
            matched: smallvec::SmallVec::new(),
            inst_class: Default::default(),
        };

        let block = BasicBlock {
            start_address: 0x1000,
            end_address: 0x1005,
            start_idx: 0,
            end_idx: 1,
        };

        let mut cfg = ControlFlowGraph {
            instructions: vec![insn].into(),
            blocks: [(0x1000, block)].into_iter().collect(),
            edges: vec![],
        };

        needle.populate_cfg(&mut cfg);

        let insn_matched = &cfg.instructions[0].matched;
        // Both overlapping patterns ("alloc" and "virtualalloc") must match
        assert_eq!(
            insn_matched.len(),
            2,
            "Both overlapping patterns must be present in matched"
        );
    }

    #[test]
    fn test_load_embedded_rules() {
        let rules = Rule::load_embedded();
        assert_eq!(rules.len(), 1052, "Expected 1,052 embedded Capa rules");
        assert!(
            rules
                .iter()
                .any(|r| r.rule.meta.name.contains("encrypt data using RC4 PRGA"))
        );
    }
}
