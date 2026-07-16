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
