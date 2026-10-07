//! # Structural Feature Extraction
//!
//! Flattens and normalizes raw static binary analysis findings into structured,
//! high-speed lookup sets for capa behavioral rule evaluation.
//!
//! ## Core Types
//!
//! - [`FeatureSet`]: Normalized container of APIs, strings, section entropies, and CFG metrics.
//!
//! ## Overview
//!
//! Feature extraction bridges raw disassembler, parser, and plugin outputs to the declarative
//! rule evaluation engine (`Rule::evaluate`). Extraction proceeds through several coordinated stages:
//!
//! 1. **FLIRT Library Range Filtering**: Discovers compiler runtime and standard library functions
//!    (e.g., libc, MSVCRT) and traces their address ranges. Basic blocks falling within library
//!    boundaries are excluded from rule evaluation to prevent false-positive capability matches on
//!    standard library code.
//! 2. **Interval Compaction**: Sorts and compacts identified library ranges with [`FeatureSet::merge_ranges`]
//!    to enable $O(\log K)$ partition-point binary searches per basic block.
//! 3. **API & String Normalization**: Flattens imported and exported APIs into Aho-Corasick [`PatternID`]
//!    sets, and extracts lowercased string literals discovered across binary data sections.
//! 4. **Graph Topometrics & Complexity**: Constructs an adjacency graph over non-library basic blocks,
//!    deduplicates parallel edges, detects execution loops using an iterative 3-state DFS
//!    ([`FeatureSet::has_cycle`]), and calculates McCabe cyclomatic complexity per weakly connected
//!    component ([`FeatureSet::max_cyclomatic_complexity`]).
//!
//! ## Examples
//!
//! Extracting a `FeatureSet` from aggregated analysis results:
//!
//! ```rust
//! use rbat::core::features::FeatureSet;
//! use rbat::core::types::analysis::AnalysisResult;
//!
//! let result = AnalysisResult::default();
//! let _features = FeatureSet::from_analysis_result(&result);
//! ```

use crate::core::{
    cfg::BasicBlock, disassembler::InstructionInfo, flirt::FlirtMatcher, parser::BinaryArch,
    types::analysis::AnalysisResult,
};
use ahash::{AHashMap, AHashSet, HashMapExt, HashSetExt};
use aho_corasick::PatternID;
use petgraph::unionfind::UnionFind;
use rustc_hash::{FxHashMap, FxHashSet};
use smallvec::SmallVec;
use std::sync::Arc;

/// this type represents the adjacency vector.
type Adj = Vec<SmallVec<[u32; 2]>>;

/// Collected metrics, symbols, and structural indicators extracted from an analyzed binary.
///
/// `FeatureSet` organizes binary characteristics into pre-indexed sets and normalized metrics
/// tailored for high-speed evaluation against capa rule syntax trees:
/// - Imports and exports are pre-mapped into Aho-Corasick [`PatternID`] sets for $O(1)$ presence testing.
/// - Matched string constants are lowercased and deduplicated.
/// - Basic blocks are filtered to exclude statically-linked standard library functions identified via FLIRT.
/// - Control flow graph topologies are characterized by block count, loop presence, and maximum McCabe
///   cyclomatic complexity across weakly connected components.
///
/// # Lifetime
///
/// The `'buf` lifetime binds section entropy maps and basic block references to the lifetime of
/// the source [`AnalysisResult`].
///
/// # Examples
///
/// ```rust
/// use rbat::core::features::FeatureSet;
/// use rbat::core::types::analysis::AnalysisResult;
///
/// let result = AnalysisResult::default();
/// let _features = FeatureSet::from_analysis_result(&result);
/// ```
#[derive(Debug, Clone)]
pub struct FeatureSet<'buf> {
    /// Mapped API imports and suspicious dynamic symbol links.
    pub(crate) apis: FxHashSet<PatternID>,
    /// Mapped string constants.
    pub(crate) strings: AHashSet<String>,
    /// Section Shannon entropies.
    pub(crate) section_entropies: &'buf AHashMap<&'buf str, f64>,
    /// Whether any code caves (NOP/zero/trap runs) were mapped.
    pub(crate) has_code_cave: bool,
    /// Whether any packer/crypter signature was matched.
    pub(crate) has_packer_sig: bool,
    /// Mapped target OS string.
    pub(crate) os: String,
    /// Mapped CPU architecture string.
    pub(crate) arch: String,
    /// Canonical binary format identifier (`pe`, `elf`, or `macho`).
    pub(crate) binary_format: String,
    // CFG structural fields
    /// The total count of basic blocks.
    pub(crate) basic_blocks_count: usize,
    /// Indicates if a loop structure was detected.
    pub(crate) has_loop: bool,
    /// The maximum cyclomatic complexity across blocks.
    pub(crate) max_cyclomatic_complexity: usize,
    /// A list of references to the basic blocks.
    pub(crate) blocks: Vec<&'buf BasicBlock>,
    /// Shared backing instructions for CFG basic block inspection.
    pub(crate) cfg_instructions: Arc<[InstructionInfo]>,
}

impl<'buf> FeatureSet<'buf> {
    /// Populates a `FeatureSet` from the aggregate analysis findings.
    ///
    /// Executes the multi-stage extraction pipeline:
    /// 1. Determines architecture and discovers FLIRT library function boundaries.
    /// 2. Sorts and merges overlapping library ranges to filter out library basic blocks.
    /// 3. Normalizes imports and exports into Aho-Corasick [`PatternID`] search sets.
    /// 4. Collects and lowercases matched YARA string values.
    /// 5. Filters non-library blocks, builds an adjacency graph, collapses parallel edges,
    ///    detects loops via DFS, and computes maximum McCabe cyclomatic complexity.
    /// 6. Normalizes target OS, architecture, and binary format strings.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rbat::core::features::FeatureSet;
    /// use rbat::core::types::analysis::AnalysisResult;
    ///
    /// let res = AnalysisResult::default();
    /// let features = FeatureSet::from_analysis_result(&res);
    /// ```
    pub fn from_analysis_result(res: &'buf AnalysisResult<'buf>) -> Self {
        let arch_name = res.metadata.architecture_name();

        // ---- Library ranges ----
        let library_ranges: Vec<(u64, u64)> = match res.cfg.as_ref() {
            Some(cfg) if !res.library_functions.is_empty() => {
                let all_entry_points: FxHashSet<u64> =
                    res.library_functions.keys().copied().collect();

                let arch_enum = match arch_name.as_str() {
                    "x86_64" => BinaryArch::X64,
                    "x86" => BinaryArch::X86,
                    "arm" => BinaryArch::Arm,
                    _ => BinaryArch::Arm64,
                };

                let ranges = res
                    .library_functions
                    .keys()
                    .map(|&lib_addr| {
                        FlirtMatcher::find_function_range(
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

        // ---- Non lib code blocks and graph metrics ----
        let (blocks, has_loop, max_cyclomatic_complexity) = match res.cfg.as_ref() {
            Some(cfg) => {
                let mut blocks: Vec<&'buf BasicBlock> = cfg
                    .blocks
                    .values()
                    .filter(|block| !is_lib_block(block.start_address))
                    .collect();
                blocks.sort_unstable_by_key(|b| b.start_address);

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
            arch: arch_name.to_lowercase(),
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

    /// Sorts and merges overlapping or contiguous address ranges.
    ///
    /// Takes an unsorted vector of `(start, end)` virtual memory address intervals,
    /// sorts them in ascending order, and merges overlapping or adjacent intervals
    /// into a compacted, strictly ascending list of disjoint ranges in $O(N \log N)$ time.
    ///
    /// # Invariants
    ///
    /// Returns a list of ranges where for all `i`: `merged[i].0 <= merged[i].1` and
    /// `merged[i].1 < merged[i + 1].0`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rbat::core::features::FeatureSet;
    ///
    /// let ranges = vec![(0x1000, 0x1050), (0x1040, 0x1100), (0x2000, 0x2050)];
    /// let merged = FeatureSet::merge_ranges(ranges);
    /// assert_eq!(merged, vec![(0x1000, 0x1100), (0x2000, 0x2050)]);
    /// ```
    pub fn merge_ranges(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
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

    /// Detects execution loops in an adjacency graph using an iterative 3-state DFS.
    ///
    /// Explores graph nodes using explicit depth-first search states:
    /// - `0`: Unvisited node.
    /// - `1`: Visiting / on recursion stack. Encountering a node in this state indicates a back-edge (cycle).
    /// - `2`: Visited and fully explored.
    ///
    /// Uses an explicit edge cursor array instead of call-stack recursion to guarantee
    /// safety against stack overflows on deeply nested or recursive CFGs.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rbat::core::features::FeatureSet;
    /// use smallvec::smallvec;
    ///
    /// // Acyclic DAG: 0 -> 1 -> 2
    /// let dag = vec![smallvec![1], smallvec![2], smallvec![]];
    /// assert!(!FeatureSet::has_cycle(&dag));
    ///
    /// // Cyclic graph: 0 -> 1 -> 0
    /// let cycle = vec![smallvec![1], smallvec![0]];
    /// assert!(FeatureSet::has_cycle(&cycle));
    /// ```
    pub fn has_cycle(adj: &Adj) -> bool {
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

    /// Computes the maximum McCabe cyclomatic complexity across weakly connected components.
    ///
    /// Partitions the graph into weakly connected components using [`UnionFind`], counts the
    /// number of nodes $N$ and edges $E$ per component, and calculates:
    ///
    /// $$M = E - N + 2$$
    ///
    /// Clamped to a minimum of 1. Returns the maximum score across all components in the graph.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rbat::core::features::FeatureSet;
    /// use smallvec::smallvec;
    ///
    /// // Linear sequence (1 decision path): E=2, N=3 => M = 2 - 3 + 2 = 1
    /// let linear = vec![smallvec![1], smallvec![2], smallvec![]];
    /// assert_eq!(FeatureSet::max_cyclomatic_complexity(&linear), 1);
    ///
    /// // Branching diamond (2 decision paths): E=4, N=4 => M = 4 - 4 + 2 = 2
    /// let branch = vec![smallvec![1, 2], smallvec![3], smallvec![3], smallvec![]];
    /// assert_eq!(FeatureSet::max_cyclomatic_complexity(&branch), 2);
    /// ```
    pub fn max_cyclomatic_complexity(adj: &Adj) -> usize {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{
        cfg::InstructionClass, disassembler::InstructionInfo, parser::BinaryArch,
        types::analysis::AnalysisResult, yarahandler::YaraMatches,
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
        res.code_cave.nop_sleds = vec![2000, 2001];

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

        let cfg = ControlFlowGraph::new(insns.into(), &BinaryArch::X64);
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
                inst_class: InstructionClass::Return,
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
                inst_class: InstructionClass::ConditionalJump,
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
                inst_class: InstructionClass::Return,
            },
        ];

        let cfg = ControlFlowGraph::new(insns.into(), &BinaryArch::X64);
        res.cfg = Some(cfg);

        let fs = FeatureSet::from_analysis_result(&res);
        assert_eq!(fs.max_cyclomatic_complexity, 2);
    }
}
