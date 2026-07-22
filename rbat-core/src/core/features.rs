//! # Structural Feature Extraction
//!
//! This module implements the `FeatureSet` structure which extracts and flattens
//! binary analysis results into fast-lookup sets and maps for rule evaluation.

use crate::core::AnalysisResult;
use crate::core::types::{BasicBlock, InstructionInfo};
use std::collections::HashMap;

/// Collected metrics and indicators extracted from the binary for rule evaluation.
#[derive(Debug, Clone)]
pub struct FeatureSet {
    /// Mapped API imports and suspicious dynamic symbol links.
    pub apis: Vec<String>,
    /// Mapped string constants.
    pub strings: Vec<String>,
    /// Blacklisted instruction mnemonics.
    pub mnemonics: Vec<String>,
    /// Section Shannon entropies.
    pub section_entropies: HashMap<String, f64>,
    /// Whether any code caves (NOP/zero/trap runs) were mapped.
    pub has_code_cave: bool,
    /// Whether any packer/crypter signature was matched.
    pub has_packer_sig: bool,
    /// Mapped target OS string.
    pub os: String,
    /// Mapped CPU architecture string.
    pub arch: String,
    // CFG structural fields
    pub basic_blocks_count: usize,
    pub has_loop: bool,
    pub max_cyclomatic_complexity: usize,
    // Captured basic blocks for scope evaluation
    pub blocks: Vec<BasicBlock>,
}

impl FeatureSet {
    /// Populates a `FeatureSet` from the aggregate analysis findings.
    pub fn from_analysis_result(res: &AnalysisResult) -> Self {
        let mut apis = Vec::new();
        for api_name in res.api_hooking.keys() {
            apis.push(api_name.clone());
        }
        for api_name in &res.process_injection {
            apis.push(api_name.clone());
        }

        let mut strings = Vec::new();
        for instances in res.string_values.values() {
            for inst in instances {
                strings.push(inst.data.clone());
            }
        }

        let mut mnemonics = Vec::new();
        for m in res.blacklisted_mnemonics.keys() {
            mnemonics.push(m.clone());
        }

        let mut basic_blocks_count = 0;
        let mut has_loop = false;
        let mut max_cyclomatic_complexity = 0;
        let mut blocks = Vec::new();

        if let Some(ref cfg) = res.cfg {
            basic_blocks_count = cfg.blocks.len();
            blocks = cfg.blocks.values().cloned().collect();

            // Cycle/Loop detection via petgraph
            let graph = cfg.to_petgraph();
            has_loop = petgraph::algo::toposort(&graph, None).is_err();

            // McCabe complexity: E - V + 2
            let edges_count = cfg.edges.len();
            if basic_blocks_count > 0 {
                max_cyclomatic_complexity = if edges_count >= basic_blocks_count {
                    edges_count - basic_blocks_count + 2
                } else {
                    1
                };
            }
        }

        Self {
            apis,
            strings,
            mnemonics,
            section_entropies: res.section_entropy.clone(),
            has_code_cave: !res.code_cave.is_empty(),
            has_packer_sig: !res.packer_signatures.is_empty(),
            os: res.metadata.binary_type.to_lowercase(),
            arch: res.metadata.architecture_name().to_lowercase(),
            basic_blocks_count,
            has_loop,
            max_cyclomatic_complexity,
            blocks,
        }
    }

    /// Extracts localized features from a single basic block.
    pub fn from_basic_block(block: &BasicBlock, binary_os: &str, binary_arch: &str) -> Self {
        let mut apis = Vec::new();
        let mut strings = Vec::new();
        let mut mnemonics = Vec::new();

        for insn in &block.instructions {
            mnemonics.push(insn.mnemonic.clone());

            // Capture API names from call targets
            if insn.mnemonic.to_lowercase() == "call" {
                apis.push(insn.op_str.clone());
            }

            // Capture any numeric/constants/strings used as instruction arguments
            strings.push(insn.op_str.clone());
        }

        Self {
            apis,
            strings,
            mnemonics,
            section_entropies: HashMap::new(),
            has_code_cave: false,
            has_packer_sig: false,
            os: binary_os.to_string(),
            arch: binary_arch.to_string(),
            basic_blocks_count: 1,
            has_loop: false,
            max_cyclomatic_complexity: 1,
            blocks: Vec::new(),
        }
    }

    /// Extracts localized features from a single instruction.
    pub fn from_instruction(insn: &InstructionInfo, binary_os: &str, binary_arch: &str) -> Self {
        let apis = if insn.mnemonic.to_lowercase() == "call" {
            vec![insn.op_str.clone()]
        } else {
            Vec::new()
        };
        let strings = vec![insn.op_str.clone()];
        let mnemonics = vec![insn.mnemonic.clone()];

        Self {
            apis,
            strings,
            mnemonics,
            section_entropies: HashMap::new(),
            has_code_cave: false,
            has_packer_sig: false,
            os: binary_os.to_string(),
            arch: binary_arch.to_string(),
            basic_blocks_count: 0,
            has_loop: false,
            max_cyclomatic_complexity: 0,
            blocks: Vec::new(),
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
        assert!(fs.apis.contains(&"VirtualAlloc".to_string()));
        assert!(fs.apis.contains(&"WriteProcessMemory".to_string()));
        assert_eq!(fs.apis.len(), 2);

        // Test Strings
        assert!(fs.strings.contains(&"http://malicious.com".to_string()));
        assert_eq!(fs.strings.len(), 1);

        // Test Mnemonics
        assert!(fs.mnemonics.contains(&"cpuid".to_string()));
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
