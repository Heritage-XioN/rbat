//! # Structural Feature Extraction
//!
//! This module implements the `FeatureSet` structure which extracts and flattens
//! binary analysis results into fast-lookup sets and maps for rule evaluation.

use crate::core::AnalysisResult;
use std::collections::{HashMap, HashSet};

/// Collected metrics and indicators extracted from the binary for rule evaluation.
#[derive(Debug, Clone)]
pub struct FeatureSet {
    /// Mapped API imports and suspicious dynamic symbol links.
    pub apis: HashSet<String>,
    /// Mapped string constants.
    pub strings: HashSet<String>,
    /// Blacklisted instruction mnemonics.
    pub mnemonics: HashSet<String>,
    /// Section Shannon entropies.
    pub section_entropies: HashMap<String, f64>,
    /// Whether any code caves (NOP/zero/trap runs) were mapped.
    pub has_code_cave: bool,
    /// Whether any packer/crypter signature was matched.
    pub has_packer_sig: bool,
}

impl FeatureSet {
    /// Populates a `FeatureSet` from the aggregate analysis findings.
    pub fn from_analysis_result(res: &AnalysisResult) -> Self {
        let mut apis = HashSet::new();
        for api_name in res.api_hooking.keys() {
            apis.insert(api_name.clone());
        }
        for api_name in &res.process_injection {
            apis.insert(api_name.clone());
        }

        let mut strings = HashSet::new();
        for instances in res.string_values.values() {
            for inst in instances {
                strings.insert(inst.data.clone());
            }
        }

        let mut mnemonics = HashSet::new();
        for m in res.blacklisted_mnemonics.keys() {
            mnemonics.insert(m.clone());
        }

        Self {
            apis,
            strings,
            mnemonics,
            section_entropies: res.section_entropy.clone(),
            has_code_cave: !res.code_cave.is_empty(),
            has_packer_sig: !res.packer_signatures.is_empty(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::{AnalysisResult, YaraMatches};

    #[test]
    fn test_feature_set_creation_populated() {
        let mut res = AnalysisResult::default();

        // Setup API Hooking
        res.api_hooking.insert("VirtualAlloc".to_string(), 1);

        // Setup Process Injection
        res.process_injection
            .insert("WriteProcessMemory".to_string());

        // Setup Strings
        let yara_match = YaraMatches {
            offset: 0,
            section: ".data".to_string(),
            length: 4,
            data: "http://malicious.com".to_string(),
        };
        res.string_values
            .insert("url".to_string(), vec![yara_match]);

        // Setup Mnemonics
        res.blacklisted_mnemonics
            .insert("cpuid".to_string(), vec![1000, 1004]);

        // Setup Section Entropies
        res.section_entropy.insert(".text".to_string(), 6.8);

        // Setup Code Cave
        res.code_cave
            .insert("nop_addr".to_string(), vec![2000, 2001]);

        // Setup Packer Signatures
        res.packer_signatures.insert("UPX".to_string(), vec![]);

        let fs = FeatureSet::from_analysis_result(&res);

        // Test APIs (both hooking and process injection should be merged)
        assert!(fs.apis.contains("VirtualAlloc"));
        assert!(fs.apis.contains("WriteProcessMemory"));
        assert_eq!(fs.apis.len(), 2);

        // Test Strings
        assert!(fs.strings.contains("http://malicious.com"));
        assert_eq!(fs.strings.len(), 1);

        // Test Mnemonics
        assert!(fs.mnemonics.contains("cpuid"));
        assert_eq!(fs.mnemonics.len(), 1);

        // Test Section Entropies
        assert_eq!(fs.section_entropies.get(".text"), Some(&6.8));

        // Test booleans
        assert!(fs.has_code_cave);
        assert!(fs.has_packer_sig);
    }

    #[test]
    fn test_feature_set_creation_empty() {
        let res = AnalysisResult::default();
        let fs = FeatureSet::from_analysis_result(&res);

        assert!(fs.apis.is_empty());
        assert!(fs.strings.is_empty());
        assert!(fs.mnemonics.is_empty());
        assert!(fs.section_entropies.is_empty());
        assert!(!fs.has_code_cave);
        assert!(!fs.has_packer_sig);
    }
}
