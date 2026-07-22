//! # Declarative Threat Detection Rules
//!
//! This module implements the `Rule` struct, nested logic conditions,
//! rule evaluation, and embedded template loader.

use serde::{Deserialize, Serialize};

use crate::core::{Asset, RuleInner, RuleMeta, features::FeatureSet};

/// The unified top-level structure starting with the standard `rule:` key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
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
    pub fn matches(&self, features: &FeatureSet) -> bool {
        self.rule.features.iter().all(|c| c.matches(features))
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
    pub fn evaluate(features: &FeatureSet, rules: &[Self]) -> Vec<RuleMeta> {
        rules
            .iter()
            .filter(|rule| rule.matches(features))
            .map(|rule| rule.rule.meta.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::core::{RuleCondition, RuleTag};

    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_rule_evaluation() {
        let mut section_entropies = HashMap::new();
        section_entropies.insert(".text".to_owned(), 7.8);

        let features = FeatureSet {
            apis: vec!["VirtualAlloc".to_owned()],
            strings: Vec::new(),
            mnemonics: Vec::new(),
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
        let matches = Rule::evaluate(&features, &rules);

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
        let block1 = BasicBlock {
            start_address: 0x1000,
            end_address: 0x1010,
            instructions: vec![
                InstructionInfo {
                    address: 0x1000,
                    mnemonic: "mov".to_string(),
                    op_str: "1 = HANDLE_FLAG_INHERIT".to_string(),
                },
                InstructionInfo {
                    address: 0x1005,
                    mnemonic: "call".to_string(),
                    op_str: "SetHandleInformation".to_string(),
                },
                InstructionInfo {
                    address: 0x1010,
                    mnemonic: "call".to_string(),
                    op_str: "SetHandleInformation".to_string(),
                },
            ],
        };

        let features = FeatureSet {
            apis: Vec::new(),
            strings: Vec::new(),
            mnemonics: Vec::new(),
            section_entropies: HashMap::new(),
            has_code_cave: false,
            has_packer_sig: false,
            os: "windows".to_string(),
            arch: "x86".to_string(),
            basic_blocks_count: 1,
            has_loop: true,
            max_cyclomatic_complexity: 5,
            blocks: vec![block1],
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
                            RuleCondition::Other({
                                let mut m = std::collections::HashMap::new();
                                m.insert(
                                    "count(api(SetHandleInformation))".to_string(),
                                    serde_json::Value::String("2 or more".to_string()),
                                );
                                m.insert(
                                    "number".to_string(),
                                    serde_json::Value::String(
                                        "1 = HANDLE_FLAG_INHERIT".to_string(),
                                    ),
                                );
                                m
                            }),
                        ],
                    }],
                }],
            },
        };

        let rules = vec![rule_cfg, rule_scope];
        let matches = Rule::evaluate(&features, &rules);

        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].name, "CfgRule");
        assert_eq!(matches[1].name, "ScopeRule");
    }
}
