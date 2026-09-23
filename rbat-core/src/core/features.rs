//! # Structural Feature Extraction
//!
//! This module implements the `FeatureSet` structure which extracts and flattens
//! binary analysis results into fast-lookup sets and maps for rule evaluation.

use crate::core::disassembler::InstructionInfo;
use crate::core::{AnalysisResult, BasicBlock};
use crate::utils::flirt::find_function_range;
use ahash::{AHashMap, AHashSet, HashMapExt, HashSetExt};
use aho_corasick::PatternID;
use petgraph::unionfind::UnionFind;
use rustc_hash::{FxHashMap, FxHashSet};
use smallvec::SmallVec;
use std::sync::Arc;

type Adj = Vec<SmallVec<[u32; 2]>>;

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
    /// Shared backing instructions for CFG basic block inspection.
    pub cfg_instructions: Arc<[InstructionInfo]>,
}

impl<'buf> FeatureSet<'buf> {
    /// Populates a `FeatureSet` from the aggregate analysis findings.
    pub fn from_analysis_result(res: &'buf AnalysisResult<'buf>) -> Self {
        let arch_name = res.metadata.architecture_name();

        // ---- Library ranges (only when library functions were matched) ----
        let library_ranges: Vec<(u64, u64)> = match res.cfg.as_ref() {
            Some(cfg) if !res.library_functions.is_empty() => {
                let all_entry_points: FxHashSet<u64> =
                    res.library_functions.keys().copied().collect();

                let arch_enum = match arch_name.as_str() {
                    "x86_64" => crate::core::BinaryArch::X64,
                    "x86" => crate::core::BinaryArch::X86,
                    "arm" => crate::core::BinaryArch::Arm,
                    _ => crate::core::BinaryArch::Arm64,
                };

                let ranges = res
                    .library_functions
                    .keys()
                    .map(|&lib_addr| {
                        find_function_range(
                            lib_addr,
                            &cfg.instructions,
                            &all_entry_points,
                            &arch_enum,
                        )
                    })
                    .collect();

                // Sorts and merges overlapping ranges so
                // membership can be checked with a binary
                // search instead of a linear scan.
                FeatureSet::merge_ranges(ranges)
            }
            _ => Vec::new(),
        };

        // Binary search over merged, sorted, non-overlapping ranges.
        let is_lib_block = |addr: u64| {
            let i = library_ranges.partition_point(|&(s, _)| s <= addr);
            i > 0 && addr <= library_ranges[i - 1].1
        };

        // ---- APIs and strings ----
        let mut apis = FxHashSet::with_capacity(res.imports.len() + res.exports.len());
        for &api_id in res.imports.iter().chain(res.exports.iter()) {
            apis.insert(PatternID::must(api_id));
        }

        let string_capacity: usize = res.string_values.values().map(|v| v.len()).sum();
        let mut strings = AHashSet::with_capacity(string_capacity);
        for instances in res.string_values.values() {
            for inst in instances {
                strings.insert(inst.data.to_lowercase());
            }
        }

        // ---- User-code blocks and graph metrics ----
        let (blocks, has_loop, max_cyclomatic_complexity) = match res.cfg.as_ref() {
            Some(cfg) => {
                let blocks: Vec<&'buf BasicBlock> = cfg
                    .blocks
                    .values()
                    .filter(|block| !is_lib_block(block.start_address))
                    .collect();

                if blocks.is_empty() {
                    (blocks, false, 0)
                } else {
                    let n = blocks.len();
                    let mut addr_to_idx = FxHashMap::with_capacity(n);
                    for (idx, block) in blocks.iter().enumerate() {
                        addr_to_idx.insert(block.start_address, idx);
                    }

                    let mut adj: Adj = vec![SmallVec::new(); n];
                    for &(src, dst, _) in &cfg.edges {
                        if let (Some(&s), Some(&d)) = (addr_to_idx.get(&src), addr_to_idx.get(&dst))
                        {
                            adj[s].push(d as u32);
                        }
                    }

                    // Collapse duplicate edges (e.g. a conditional branch whose target
                    // equals its fallthrough) to prevent artificially inflating McCabe complexity
                    // and to ensure deterministic, non-redundant DFS traversal.
                    for succs in adj.iter_mut() {
                        succs.sort_unstable();
                        succs.dedup();
                    }

                    let has_loop = FeatureSet::has_cycle(&adj);
                    let cc = FeatureSet::max_cyclomatic_complexity(&adj);
                    (blocks, has_loop, cc)
                }
            }
            None => (Vec::new(), false, 0),
        };

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
            basic_blocks_count: blocks.len(),
            has_loop,
            max_cyclomatic_complexity,
            blocks,
            cfg_instructions: res
                .cfg
                .as_ref()
                .map(|c| Arc::clone(&c.instructions))
                .unwrap_or_else(|| Arc::from([])),
        }
    }

    /// Sorts and merges overlapping ranges
    fn merge_ranges(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
        ranges.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
        for (s, e) in ranges {
            match merged.last_mut() {
                Some(last) if s <= last.1 => last.1 = last.1.max(e),
                _ => merged.push((s, e)),
            }
        }
        merged
    }

    /// Iterative 3-state DFS with a per-node edge cursor.
    /// Returns true if the graph contains a cycle (a self-loop counts).
    fn has_cycle(adj: &[SmallVec<[u32; 2]>]) -> bool {
        let n = adj.len();
        let mut state = vec![0u8; n]; // 0 = unvisited, 1 = on stack, 2 = done
        let mut cursor = vec![0usize; n];
        let mut stack: Vec<u32> = Vec::new();

        for start in 0..n {
            if state[start] != 0 {
                continue;
            }
            state[start] = 1;
            stack.push(start as u32);

            while let Some(&u) = stack.last() {
                let u = u as usize;
                if cursor[u] < adj[u].len() {
                    let v = adj[u][cursor[u]] as usize;
                    cursor[u] += 1;
                    match state[v] {
                        1 => return true,
                        0 => {
                            state[v] = 1;
                            stack.push(v as u32);
                        }
                        _ => {}
                    }
                } else {
                    state[u] = 2;
                    stack.pop();
                }
            }
        }
        false
    }

    /// Max McCabe complexity (E - N + 2) across weakly connected components.
    fn max_cyclomatic_complexity(adj: &[SmallVec<[u32; 2]>]) -> usize {
        let n = adj.len();
        let mut uf = UnionFind::new(n);
        for (s, succs) in adj.iter().enumerate() {
            for &d in succs {
                uf.union(s, d as usize);
            }
        }
        let labels = uf.into_labeling();

        let mut comp_nodes = vec![0u32; n];
        let mut comp_edges = vec![0u32; n];
        for (s, succs) in adj.iter().enumerate() {
            let r = labels[s];
            comp_nodes[r] += 1;
            comp_edges[r] += succs.len() as u32;
        }

        (0..n)
            .filter(|&r| comp_nodes[r] > 0)
            .map(|r| (comp_edges[r] + 2).saturating_sub(comp_nodes[r]).max(1) as usize)
            .max()
            .unwrap_or(1)
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

        let cfg = ControlFlowGraph::new(insns.into(), &crate::core::BinaryArch::X64);
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

        let cfg = ControlFlowGraph::new(insns.into(), &crate::core::BinaryArch::X64);
        res.cfg = Some(cfg);

        let fs = FeatureSet::from_analysis_result(&res);
        assert_eq!(fs.max_cyclomatic_complexity, 2);
    }
}
