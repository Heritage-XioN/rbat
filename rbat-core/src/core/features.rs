//! # Structural Feature Extraction
//!
//! This module implements the `FeatureSet` structure which extracts and flattens
//! binary analysis results into fast-lookup sets and maps for rule evaluation.

use crate::core::disassembler::InstructionInfo;
use crate::core::{AnalysisResult, BasicBlock, EdgeType};
use crate::utils::flirt::find_function_range;
use ahash::{AHashMap, AHashSet};
use aho_corasick::PatternID;
use rustc_hash::{FxHashMap, FxHashSet};

/// Collected metrics and indicators extracted from the binary for rule evaluation.
#[derive(Debug, Clone)]
pub struct FeatureSet<'buf> {
    /// Mapped API imports and suspicious dynamic symbol links.
    pub apis: FxHashSet<PatternID>,
    /// Mapped string constants.
    pub strings: AHashSet<String>,
    /// Section Shannon entropies.
    pub section_entropies: &'buf AHashMap<&'buf str, f64>,
    /// Whether any code caves (NOP/zero/trap runs) were mapped.
    pub has_code_cave: bool,
    /// Whether any packer/crypter signature was matched.
    pub has_packer_sig: bool,
    /// Mapped target OS string.
    pub os: String,
    /// Mapped CPU architecture string.
    pub arch: String,
    /// Canonical binary format identifier (`pe`, `elf`, or `macho`).
    pub binary_format: String,
    // CFG structural fields
    /// The total count of basic blocks.
    pub basic_blocks_count: usize,
    /// Indicates if a loop structure was detected.
    pub has_loop: bool,
    /// The maximum cyclomatic complexity across blocks.
    pub max_cyclomatic_complexity: usize,
    /// A list of references to the basic blocks.
    pub blocks: Vec<&'buf BasicBlock>,
}

impl<'buf> FeatureSet<'buf> {
    /// Populates a `FeatureSet` from the aggregate analysis findings.
    pub fn from_analysis_result(res: &'buf AnalysisResult<'buf>) -> Self {
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
            let mut all_entry_points = FxHashSet::default();
            for &addr in res.library_functions.keys() {
                all_entry_points.insert(addr);
            }
            let arch_enum = match res.metadata.architecture_name().as_str() {
                "x86_64" => crate::core::BinaryArch::X64,
                "x86" => crate::core::BinaryArch::X86,
                "arm" => crate::core::BinaryArch::Arm,
                _ => crate::core::BinaryArch::Arm64,
            };

            for &lib_addr in res.library_functions.keys() {
                let (start, end) =
                    find_function_range(lib_addr, &all_instructions, &all_entry_points, &arch_enum);
                library_ranges.push((start, end));
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

        let mut apis = FxHashSet::default();
        let mut strings = AHashSet::new();

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
            let filtered_blocks: Vec<&'buf BasicBlock> = cfg
                .blocks
                .values()
                .filter(|block| !is_lib_block(block.start_address))
                .collect();

            basic_blocks_count = filtered_blocks.len();
            blocks = filtered_blocks;

            // Reconstruct the petgraph containing only non-library blocks
            let mut graph = petgraph::graph::DiGraph::<u64, EdgeType>::new();
            let mut indices = FxHashMap::default();

            for block in &blocks {
                let idx = graph.add_node(block.start_address);
                indices.insert(block.start_address, idx);
            }

            for &(src, dst, edge_type) in &cfg.edges {
                if let (Some(&src_idx), Some(&dst_idx)) = (indices.get(&src), indices.get(&dst)) {
                    graph.add_edge(src_idx, dst_idx, edge_type);
                }
            }

            // Cycle/Loop detection via petgraph on user code only
            has_loop = petgraph::algo::toposort(&graph, None).is_err();

            // McCabe complexity per connected component (subgraph/function) on user code only
            if basic_blocks_count > 0 {
                let mut uf = petgraph::unionfind::UnionFind::new(graph.node_count());
                for edge in graph.edge_indices() {
                    let (src, dst) = graph.edge_endpoints(edge).unwrap();
                    uf.union(src.index(), dst.index());
                }

                let mut component_nodes = FxHashMap::default();
                let mut component_edges = FxHashMap::default();

                for node in graph.node_indices() {
                    let root = uf.find(node.index());
                    *component_nodes.entry(root).or_insert(0) += 1;
                }

                for edge in graph.edge_indices() {
                    let (src, _dst) = graph.edge_endpoints(edge).unwrap();
                    let root = uf.find(src.index());
                    *component_edges.entry(root).or_insert(0) += 1;
                }

                max_cyclomatic_complexity = component_nodes
                    .into_iter()
                    .map(|(root, n)| {
                        let e = component_edges.get(&root).copied().unwrap_or(0);
                        if e >= n { e - n + 2 } else { 1 }
                    })
                    .max()
                    .unwrap_or(1);
            }
        }

        let binary_type = res.metadata.binary_type.to_lowercase();
        let binary_format = if binary_type.contains("mach") {
            "macho"
        } else if binary_type.contains("elf") {
            "elf"
        } else if binary_type.contains("pe") {
            "pe"
        } else {
            "unknown"
        };

        Self {
            apis,
            strings,
            section_entropies: &res.section_entropy,
            has_code_cave: !res.code_cave.is_empty(),
            has_packer_sig: !res.packer_signatures.is_empty(),
            os: binary_type,
            arch: res.metadata.architecture_name().to_lowercase(),
            binary_format: binary_format.to_string(),
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
    use crate::core::{
        disassembler::InstructionInfo,
        types::{AnalysisResult, YaraMatches},
    };

    #[test]
    fn test_feature_set_creation_populated() {
        let mut res = AnalysisResult::default();

        // Setup Imports & Exports
        res.imports.push(10);
        res.exports.push(20);

        // Setup Strings
        let yara_match = YaraMatches {
            offset: 0,
            section: ".data",
            length: 10,
            data: "http://malicious.com".into(),
        };
        res.string_values.insert("url", vec![yara_match]);

        // Setup Section Entropies
        res.section_entropy.insert(".text", 6.8);

        // Setup Code Cave
        res.code_cave.insert("nop_addr", vec![2000, 2001]);

        // simulate packer match
        res.packer_signatures.insert("UPX", vec![]);

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
        assert!(fs.section_entropies.is_empty());
        assert!(!fs.has_code_cave);
        assert!(!fs.has_packer_sig);
    }

    #[test]
    fn test_feature_set_library_exclusion() {
        use crate::core::cfg::ControlFlowGraph;

        let mut res = AnalysisResult::default();
        res.metadata.architecture = 62;

        let insns = vec![
            InstructionInfo {
                address: 0x1000,
                mnemonic: "mov".into(),
                op_str: "1 = HANDLE_FLAG_INHERIT".into(),
                api_resolution: None,
                matched: smallvec::SmallVec::new(),
                inst_class: Default::default(),
            },
            InstructionInfo {
                address: 0x2000,
                mnemonic: "ret".into(),
                op_str: "".into(),
                api_resolution: None,
                matched: smallvec::SmallVec::new(),
                inst_class: Default::default(),
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

    #[test]
    fn test_cyclomatic_complexity_per_component() {
        use crate::core::cfg::ControlFlowGraph;

        let mut res = AnalysisResult::default();
        res.metadata.architecture = 62;

        // Function 1 at 0x1000: single straight-line block (complexity 1)
        // Function 2 at 0x2000: conditional jump splitting into 3 blocks, 3 edges (complexity 3 - 3 + 2 = 2)
        let insns = vec![
            // Function 1
            InstructionInfo {
                address: 0x1000,
                mnemonic: "mov".into(),
                op_str: "eax, 1".into(),
                api_resolution: None,
                matched: smallvec::SmallVec::new(),
                inst_class: Default::default(),
            },
            InstructionInfo {
                address: 0x1005,
                mnemonic: "ret".into(),
                op_str: "".into(),
                api_resolution: None,
                matched: smallvec::SmallVec::new(),
                inst_class: crate::core::InstructionClass::Return,
            },
            // Function 2
            InstructionInfo {
                address: 0x2000,
                mnemonic: "cmp".into(),
                op_str: "eax, 0".into(),
                api_resolution: None,
                matched: smallvec::SmallVec::new(),
                inst_class: Default::default(),
            },
            InstructionInfo {
                address: 0x2002,
                mnemonic: "je".into(),
                op_str: "0x2006".into(),
                api_resolution: None,
                matched: smallvec::SmallVec::new(),
                inst_class: crate::core::InstructionClass::ConditionalJump,
            },
            InstructionInfo {
                address: 0x2004,
                mnemonic: "nop".into(),
                op_str: "".into(),
                api_resolution: None,
                matched: smallvec::SmallVec::new(),
                inst_class: Default::default(),
            },
            InstructionInfo {
                address: 0x2006,
                mnemonic: "ret".into(),
                op_str: "".into(),
                api_resolution: None,
                matched: smallvec::SmallVec::new(),
                inst_class: crate::core::InstructionClass::Return,
            },
        ];

        let cfg = ControlFlowGraph::new(&insns, &crate::core::BinaryArch::X64);
        res.cfg = Some(cfg);

        let fs = FeatureSet::from_analysis_result(&res);
        assert_eq!(fs.max_cyclomatic_complexity, 2);
    }
}
