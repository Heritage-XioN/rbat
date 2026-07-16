//! # Declarative Threat Detection Rules
//!
//! This module implements the `Rule` struct, nested logic conditions,
//! rule evaluation, and embedded template loader.

use serde::{Deserialize, Serialize};

use crate::core::{Asset, FeatureCondition, RuleMeta, features::FeatureSet};

/// Boolean logic combinations of rule conditions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RuleCondition {
    /// True if all subconditions are true.
    And(Vec<RuleCondition>),
    /// True if any subcondition is true.
    Or(Vec<RuleCondition>),
    /// Negation of subcondition.
    Not(Box<RuleCondition>),
    /// A single feature assertion check.
    Feature(FeatureCondition),
}

impl RuleCondition {
    /// Recursively evaluates the condition against the feature set.
    pub fn matches(&self, features: &FeatureSet) -> bool {
        match self {
            Self::And(conds) => conds.iter().all(|c| c.matches(features)),
            Self::Or(conds) => conds.iter().any(|c| c.matches(features)),
            Self::Not(cond) => !cond.matches(features),
            Self::Feature(feat) => match feat {
                FeatureCondition::Api(name) => features
                    .apis
                    .iter()
                    .any(|api| api.to_lowercase().contains(&name.to_lowercase())),
                FeatureCondition::String(val) => features
                    .strings
                    .iter()
                    .any(|s| s.to_lowercase().contains(&val.to_lowercase())),
                FeatureCondition::Mnemonic(name) => features.mnemonics.contains(name),
                FeatureCondition::Entropy { section, min } => features
                    .section_entropies
                    .get(section)
                    .map(|&e| e >= *min)
                    .unwrap_or(false),
                FeatureCondition::CodeCave => features.has_code_cave,
                FeatureCondition::PackerSig => features.has_packer_sig,
            },
        }
    }
}

/// A structured threat indicator rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// The rule metadata.
    pub meta: RuleMeta,
    /// The condition tree to evaluate.
    pub condition: RuleCondition,
}

impl Rule {
    /// Evaluates if the feature set matches this rule's conditions.
    pub fn matches(&self, features: &FeatureSet) -> bool {
        self.condition.matches(features)
    }

    /// Loads all embedded JSON rules from assets.
    pub fn load_embedded() -> Vec<Self> {
        Asset::iter()
            .filter(|p| p.starts_with("rules/") && p.ends_with(".json"))
            .filter_map(|p| Asset::get(&p))
            .filter_map(|f| serde_json::from_slice::<Rule>(&f.data).ok())
            .collect()
    }

    /// Evaluates a set of rules against the feature set and returns matching rule metadata.
    pub fn evaluate(features: &FeatureSet, rules: &[Self]) -> Vec<RuleMeta> {
        rules
            .iter()
            .filter(|rule| rule.matches(features))
            .map(|rule| rule.meta.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    #[test]
    fn test_rule_evaluation() {
        let mut apis = HashSet::new();
        apis.insert("VirtualAllocEx".to_owned());
        let mut section_entropies = HashMap::new();
        section_entropies.insert(".text".to_owned(), 7.5);

        let features = FeatureSet {
            apis,
            strings: HashSet::new(),
            mnemonics: HashSet::new(),
            section_entropies,
            has_code_cave: false,
            has_packer_sig: false,
        };

        // Simple API Match Rule
        let rule_api = Rule {
            meta: RuleMeta {
                name: "ApiMatch".to_owned(),
                description: "".to_owned(),
                mitre_attack: "".to_owned(),
                severity: "".to_owned(),
                category: String::new(),
                weight: 0,
            },
            condition: RuleCondition::Feature(FeatureCondition::Api("VirtualAlloc".to_owned())),
        };

        // Entropy Match Rule
        let rule_entropy = Rule {
            meta: RuleMeta {
                name: "EntropyMatch".to_owned(),
                description: "".to_owned(),
                mitre_attack: "".to_owned(),
                severity: "".to_owned(),
                category: String::new(),
                weight: 0,
            },
            condition: RuleCondition::Feature(FeatureCondition::Entropy {
                section: ".text".to_owned(),
                min: 7.0,
            }),
        };

        let rules = vec![rule_api, rule_entropy];
        let matches = Rule::evaluate(&features, &rules);
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].name, "ApiMatch");
        assert_eq!(matches[1].name, "EntropyMatch");
    }
}
