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
        if let Some(file) = Asset::get("embedded_rules.mp") {
            match rmp_serde::from_slice::<Vec<Rule>>(&file.data) {
                Ok(rules) => return rules,
                Err(e) => eprintln!("Warning: Failed to decode pre-compiled rules: {e}"),
            }
        }
        Vec::new()
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
            let (newly_matched, still_pending): (Vec<_>, Vec<_>) = pending_deps
                .into_par_iter()
                .partition(|(_, rule)| rule.matches(features, needle, &matched_names));

            if newly_matched.is_empty() {
                break;
            }

            for (idx, rule) in newly_matched {
                matched_indices.insert(idx);
                matched_names.insert(rule.rule.meta.name.as_str());
            }
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

#[cfg(all(test, feature = "backend-capstone"))]
mod tests {
    use crate::core::{RuleCondition, RuleTag, disassembler::InstructionInfo};

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
                    mitre_attack: Some(crate::utils::rules::StringOrVec::Single("".to_owned())),
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
                    mitre_attack: Some(crate::utils::rules::StringOrVec::Single("".to_owned())),
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
        use crate::core::types::BasicBlock;

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
        use crate::core::types::BasicBlock;

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
        use crate::core::{ControlFlowGraph, types::BasicBlock};

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
