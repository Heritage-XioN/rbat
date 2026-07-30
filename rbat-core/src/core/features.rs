//! # Structural Feature Extraction
//!
//! This module implements the `FeatureSet` structure which extracts and flattens
//! binary analysis results into fast-lookup sets and maps for rule evaluation.

use crate::core::{AnalysisResult, BasicBlock, EdgeType, InstructionInfo};
use crate::utils::flirt::find_function_range;
use aho_corasick::PatternID;
use std::collections::{HashMap, HashSet};

/// Collected metrics and indicators extracted from the binary for rule evaluation.
#[derive(Debug, Clone)]
pub struct FeatureSet<'a> {
    /// Mapped API imports and suspicious dynamic symbol links.
    pub apis: HashSet<PatternID>,
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
    /// Mapped target OS string.
    pub os: String,
    /// Mapped CPU architecture string.
    pub arch: String,
    // CFG structural fields
    /// The total count of basic blocks.
    pub basic_blocks_count: usize,
    /// Indicates if a loop structure was detected.
    pub has_loop: bool,
    /// The maximum cyclomatic complexity across blocks.
    pub max_cyclomatic_complexity: usize,
    /// A list of references to the basic blocks.
    pub blocks: Vec<&'a BasicBlock>,
}

impl<'a> FeatureSet<'a> {
    /// Populates a `FeatureSet` from the aggregate analysis findings.
    pub fn from_analysis_result(res: &'a AnalysisResult) -> Self {
        // Calculate library ranges if any library functions are matched
        let mut library_ranges = Vec::new();
        if let Some(ref cfg) = res.cfg {
            // Collect all instructions across all basic blocks
            let mut all_instructions: Vec<&InstructionInfo> = cfg
                .blocks
                .values()
                .flat_map(|block| block.instructions.iter())
                .collect();
            all_instructions.sort_unstable_by_key(|insn| insn.address());
            all_instructions.dedup_by_key(|insn| insn.address());

            // Reconstruct all entry points (matched library functions + basic block starts)
            let mut all_entry_points = HashSet::new();
            for &addr in res.library_functions.keys() {
                all_entry_points.insert(addr);
            }
            for block in cfg.blocks.values() {
                all_entry_points.insert(block.start_address);
            }

            let arch_enum = match res.metadata.architecture_name().as_str() {
                "x86_64" => crate::core::BinaryArch::X64,
                "x86" => crate::core::BinaryArch::X86,
                "arm" => crate::core::BinaryArch::Arm,
                _ => crate::core::BinaryArch::Arm64,
            };

            for &start_addr in res.library_functions.keys() {
                let range = find_function_range(
                    start_addr,
                    &all_instructions,
                    &all_entry_points,
                    &arch_enum,
                );
                library_ranges.push(range);
            }
        }

        let is_lib_block = |addr: u64| {
            for &(start, end) in &library_ranges {
                if addr >= start && addr <= end {
                    return true;
                }
            }
            false
        };

        let mut apis = HashSet::new();
        let mut strings = HashSet::new();

        for &api_id in &res.imports {
            apis.insert(PatternID::must(api_id));
        }
        for &api_id in &res.exports {
            apis.insert(PatternID::must(api_id));
        }

        for instances in res.string_values.values() {
            for inst in instances {
                if !is_lib_block(inst.offset as u64) {
                    strings.insert(inst.data.to_lowercase());
                }
            }
        }

        let mut basic_blocks_count = 0;
        let mut has_loop = false;
        let mut max_cyclomatic_complexity = 0;
        let mut blocks = Vec::new();

        if let Some(ref cfg) = res.cfg {
            let filtered_blocks: Vec<&'a BasicBlock> = cfg
                .blocks
                .values()
                .filter(|block| !is_lib_block(block.start_address))
                .collect();

            basic_blocks_count = filtered_blocks.len();
            blocks = filtered_blocks;

            // Reconstruct the petgraph containing only non-library blocks
            let mut graph = petgraph::graph::DiGraph::<u64, EdgeType>::new();
            let mut indices = std::collections::HashMap::new();

            for block in &blocks {
                let idx = graph.add_node(block.start_address);
                indices.insert(block.start_address, idx);
            }

            let mut filtered_edges_count = 0;
            for &(src, dst, edge_type) in &cfg.edges {
                if let (Some(&src_idx), Some(&dst_idx)) = (indices.get(&src), indices.get(&dst)) {
                    graph.add_edge(src_idx, dst_idx, edge_type);
                    filtered_edges_count += 1;
                }
            }

            // Cycle/Loop detection via petgraph on user code only
            has_loop = petgraph::algo::toposort(&graph, None).is_err();

            // McCabe complexity on user code only
            if basic_blocks_count > 0 {
                max_cyclomatic_complexity = if filtered_edges_count >= basic_blocks_count {
                    filtered_edges_count - basic_blocks_count + 2
                } else {
                    1
                };
            }
        }

        Self {
            apis,
            strings,
            mnemonics: HashSet::new(),
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
}

#[cfg(all(test, feature = "backend-capstone"))]
mod tests {
    use super::*;
    use crate::core::types::{AnalysisResult, YaraMatches};

    #[test]
    fn test_feature_set_creation_populated() {
        let mut res = AnalysisResult::default();

        // Setup Imports & Exports
        res.imports.push(10);
        res.exports.push(20);

        // Setup Strings
        let yara_match = YaraMatches {
            offset: 0,
            section: ".data".to_string(),
            length: 4,
            data: "http://malicious.com".to_string(),
        };
        res.string_values
            .insert("url".to_string(), vec![yara_match]);

        // Setup Section Entropies
        res.section_entropy.insert(".text".to_string(), 6.8);

        // Setup Code Cave
        res.code_cave
            .insert("nop_addr".to_string(), vec![2000, 2001]);

        // Setup Packer Signatures
        res.packer_signatures.insert("UPX".to_string(), vec![]);

        let fs = FeatureSet::from_analysis_result(&res);

        // Test APIs (both hooking and process injection should be merged)
        assert!(fs.apis.contains(&PatternID::must(10)));
        assert!(fs.apis.contains(&PatternID::must(20)));
        assert_eq!(fs.apis.len(), 2);

        // Test Strings
        assert!(fs.strings.contains("http://malicious.com"));
        assert_eq!(fs.strings.len(), 1);

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

    #[test]
    fn test_feature_set_library_exclusion() {
        use crate::core::cfg::ControlFlowGraph;
        use crate::core::types::InstructionInfo;

        let mut res = AnalysisResult::default();
        res.metadata.architecture = 62;

        let insns = vec![
            InstructionInfo {
                address: 0x1000,
                mnemonic: "mov".into(),
                op_str: "1 = HANDLE_FLAG_INHERIT".into(),
                matched: smallvec::SmallVec::new(),
            },
            InstructionInfo {
                address: 0x2000,
                mnemonic: "ret".into(),
                op_str: "".into(),
                matched: smallvec::SmallVec::new(),
            },
        ];

        let cfg = ControlFlowGraph::new(&insns, &crate::core::BinaryArch::X64);
        res.cfg = Some(cfg);

        // Add library function at 0x2000
        res.library_functions.insert(0x2000, "strlen".to_string());

        let fs = FeatureSet::from_analysis_result(&res);

        // The user block at 0x1000 should be retained
        assert!(fs.blocks.iter().any(|b| b.start_address == 0x1000));

        // The library block at 0x2000 should be excluded
        assert!(!fs.blocks.iter().any(|b| b.start_address == 0x2000));
        assert_eq!(fs.basic_blocks_count, 1);
    }
}
