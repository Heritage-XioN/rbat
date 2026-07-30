//! # Declarative Threat Detection Rules
//!
//! This module implements the `Rule` struct, nested logic conditions,
//! rule evaluation, and embedded template loader.

use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::core::{Asset, RuleInner, RuleMeta, features::FeatureSet};

/// The unified top-level structure starting with the standard `rule:` key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// The inner rule structure containing metadata and evaluation conditions.
    pub rule: RuleInner,
}

impl Rule {
    /// Parses a Rule from raw bytes, supporting native JSON and YAML Capa rules.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, String> {
        let mut rule_var = if let Ok(rule) = yaml_serde::from_slice::<Rule>(bytes) {
            rule
        } else {
            serde_json::from_slice::<Rule>(bytes).map_err(|e| e.to_string())?
        };
        rule_var.rule.features = rule_var
            .rule
            .features
            .into_iter()
            .filter_map(|c| c.sanitize())
            .collect();
        Ok(rule_var)
    }

    /// Evaluates if the feature set matches this rule's conditions.
    pub fn matches(&self, features: &FeatureSet, needle: &crate::core::types::NeedleIndex) -> bool {
        self.rule
            .features
            .iter()
            .all(|c| c.matches(features, needle))
    }

    /// Loads all embedded JSON and YAML rules from assets.
    pub fn load_embedded() -> Vec<Self> {
        Asset::iter()
            .filter(|p| {
                (p.starts_with("rules/") || p.starts_with("capa-rules/"))
                    && (p.ends_with(".json") || p.ends_with(".yaml") || p.ends_with(".yml"))
                    && !p.contains("/.")
            })
            .filter_map(|p| Asset::get(&p))
            .filter_map(|f| Self::from_slice(&f.data).ok())
            .collect()
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
                    if is_rule_ext {
                        let parsed = std::fs::read(&path)
                            .map_err(|e| e.to_string())
                            .and_then(|data| Self::from_slice(&data));
                        if let Ok(rule) = parsed {
                            rules.push(rule);
                        }
                    }
                }
            }
        }
    }

    /// Evaluates a set of rules against the feature set and returns matching rule metadata.
    pub fn evaluate(
        features: &FeatureSet,
        rules: &[Self],
        needle: &crate::core::types::NeedleIndex,
    ) -> Vec<RuleMeta> {
        rules
            .par_iter()
            .filter(|rule| rule.matches(features, needle))
            .map(|rule| rule.rule.meta.clone())
            .collect()
    }
}

#[cfg(all(test, feature = "backend-capstone"))]
mod tests {
    use crate::core::{RuleCondition, RuleTag};

    use super::*;
    use std::collections::{HashMap, HashSet};

    #[test]
    fn test_rule_evaluation() {
        let mut section_entropies = HashMap::new();
        section_entropies.insert(".text".to_owned(), 7.8);

        let features = FeatureSet {
            apis: HashSet::from([aho_corasick::PatternID::must(0)]),
            strings: HashSet::new(),
            mnemonics: HashSet::new(),
            section_entropies,
            has_code_cave: false,
            has_packer_sig: false,
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            basic_blocks_count: 0,
            has_loop: false,
            max_cyclomatic_complexity: 0,
            blocks: Vec::new(),
        };

        // Simple API Match Rule
        let rule_api = Rule {
            rule: RuleInner {
                meta: RuleMeta {
                    name: "ApiMatch".to_owned(),
                    description: Some("".to_owned()),
                    mitre_attack: Some(crate::utils::rules::StringOrVec::Single("".to_owned())),
                    severity: Some("".to_owned()),
                    category: Some(String::new()),
                    weight: Some(0),
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
                    mitre_attack: Some(crate::utils::rules::StringOrVec::Single("".to_owned())),
                    severity: Some("".to_owned()),
                    category: Some(String::new()),
                    weight: Some(0),
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
        use crate::core::types::{BasicBlock, InstructionInfo};

        // Create instructions & block representing:
        // SetHandleInformation (call)
        // SetHandleInformation (call)
        // arg: 1 = HANDLE_FLAG_INHERIT (mov/push parameter)
        let mut block1 = BasicBlock {
            start_address: 0x1000,
            end_address: 0x1010,
            instructions: vec![
                InstructionInfo {
                    address: 0x1000,
                    mnemonic: "mov".into(),
                    op_str: "1 = HANDLE_FLAG_INHERIT".into(),
                    matched: smallvec::SmallVec::new(),
                },
                InstructionInfo {
                    address: 0x1005,
                    mnemonic: "call".into(),
                    op_str: "SetHandleInformation".into(),
                    matched: smallvec::SmallVec::new(),
                },
                InstructionInfo {
                    address: 0x1010,
                    mnemonic: "call".into(),
                    op_str: "SetHandleInformation".into(),
                    matched: smallvec::SmallVec::new(),
                },
            ],
        };

        // Rule checking Loop presence & Cyclomatic Complexity
        let rule_cfg = Rule {
            rule: RuleInner {
                meta: RuleMeta {
                    name: "CfgRule".to_owned(),
                    severity: Some("High".to_owned()),
                    category: Some("defense_evasion".to_owned()),
                    weight: Some(40),
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
                    category: Some("persistence".to_owned()),
                    weight: Some(90),
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
        for insn in block1.instructions.iter_mut() {
            let haystack = format!("{} {}", insn.format_mnemonic(), insn.format_operands());
            for mat in needle.automaton.find_iter(&haystack) {
                let p = mat.pattern();
                needle.present[p.as_usize()].store(true, std::sync::atomic::Ordering::Relaxed);
                if !insn.matched.contains(&p) {
                    insn.matched.push(p);
                }
            }
        }

        let features = FeatureSet {
            apis: HashSet::new(),
            strings: HashSet::new(),
            mnemonics: HashSet::new(),
            section_entropies: HashMap::new(),
            has_code_cave: false,
            has_packer_sig: false,
            os: "Windows".to_owned(),
            arch: "x86_64".to_owned(),
            basic_blocks_count: 1,
            has_loop: true,
            max_cyclomatic_complexity: 5,
            blocks: vec![&block1],
        };

        let matches = Rule::evaluate(&features, &rules, &needle);

        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].name, "CfgRule");
        assert_eq!(matches[1].name, "ScopeRule");
    }
}
