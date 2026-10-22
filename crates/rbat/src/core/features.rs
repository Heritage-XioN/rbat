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
//! let _features = FeatureSet::new(&result, &[]);
//! ```

use crate::core::{
    cfg::{BasicBlock, ControlFlowGraph, EdgeType},
    disassembler::InstructionInfo,
    flirt::FlirtMatcher,
    parser::BinaryArch,
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

/// Collected metrics, symbols, and structural indicators partitioned by scope.
///
/// `FeatureSet` organizes binary characteristics into pre-indexed sets and normalized metrics
/// partitioned by Capa scope tiers:
/// - [`FileScopeFeatures`]: Whole-binary structural metrics, imports, exports, and YARA strings.
/// - [`FunctionScopeFeatures`]: Per-function control-flow topology, local cycles, complexity, and localized patterns.
/// - [`BlockScopeFeatures`]: Per-basic-block instruction slices, tight loops, and localized pattern hits.
/// - [`GlobalScopeFeatures`]: Universal architecture, OS, and format metadata.
///
/// # Lifetime
///
/// The `'buf` lifetime binds section entropy maps, raw buffers, and instruction slices to the
/// source [`AnalysisResult`].
///
/// # Examples
///
/// ```rust
/// use rbat::core::features::FeatureSet;
/// use rbat::core::types::analysis::AnalysisResult;
///
/// let result = AnalysisResult::default();
/// let _features = FeatureSet::new(&result, &[]);
/// ```
#[derive(Debug, Clone)]
pub struct FeatureSet<'buf> {
    /// File-level structural and symbol features.
    pub(crate) file_scope: FileScopeFeatures<'buf>,
    /// Reconstructed non-library functions and their scoped features.
    pub(crate) function_scope: Vec<FunctionScopeFeatures<'buf>>,
    /// All non-library basic blocks and their scoped features.
    pub(crate) basic_block_scope: Vec<BlockScopeFeatures<'buf>>,
    /// Global architecture, OS, and format features valid across all scopes.
    pub(crate) global_scope: GlobalScopeFeatures,
    /// Shared backing instructions for CFG basic block inspection.
    pub(crate) cfg_instructions: Arc<[InstructionInfo]>,
}

impl<'buf> FeatureSet<'buf> {
    /// Populates a [`FeatureSet`] from the aggregate analysis findings and raw binary buffer.
    ///
    /// Executes the multi-stage extraction pipeline:
    /// 1. Discovers and merges overlapping FLIRT runtime library address ranges.
    /// 2. Extracts localized basic block scopes, instruction slices, and tight-loop indicators.
    /// 3. Reconstructs function scopes, calculating local cycle presence, McCabe complexity, and recursion.
    /// 4. Aggregates file-level structural metrics, APIs, and matched strings.
    /// 5. Normalizes global binary format, architecture, and OS metadata.
    ///
    /// # Parameters
    ///
    /// - `res`: Aggregated static analysis findings from heuristic plugins, FLIRT identification, and CFG extraction.
    /// - `raw_buffer`: Raw executable binary byte slice used for direct regex evaluation and wide-character scanning.
    ///
    /// # Returns
    ///
    /// A fully populated [`FeatureSet`] ready for security rule evaluation.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rbat::core::features::FeatureSet;
    /// use rbat::core::types::analysis::AnalysisResult;
    ///
    /// let res = AnalysisResult::default();
    /// let features = FeatureSet::new(&res, &[]);
    /// ```
    pub fn new(res: &'buf AnalysisResult<'buf>, raw_buffer: &'buf [u8]) -> Self {
        let arch_name = res.metadata.architecture_name();
        let library_ranges = Self::extract_library_ranges(res, &arch_name);
        let is_lib_block = |addr: u64| {
            let i = library_ranges.partition_point(|&(s, _)| s <= addr);
            i > 0 && addr <= library_ranges[i - 1].1
        };

        let mut initial_apis = FxHashSet::with_capacity(res.imports.len() + res.exports.len());
        for &api_id in res.imports.iter().chain(res.exports.iter()) {
            initial_apis.insert(PatternID::must(api_id));
        }

        let (basic_block_scope, function_scope, cfg_instructions) = match res.cfg.as_ref() {
            Some(cfg) => {
                let blocks = Self::extract_block_scopes(cfg, is_lib_block, &initial_apis);
                let functions = Self::extract_function_scopes(
                    cfg,
                    &blocks,
                    is_lib_block,
                    &res.library_functions,
                );
                (blocks, functions, Arc::clone(&cfg.instructions))
            }
            None => (Vec::new(), Vec::new(), Arc::from([])),
        };

        let file_scope =
            Self::extract_file_scope(res, &function_scope, basic_block_scope.len(), raw_buffer);
        let global_scope = Self::extract_global_scope(res);

        Self {
            file_scope,
            function_scope,
            basic_block_scope,
            global_scope,
            cfg_instructions,
        }
    }

    /// Discovers and merges overlapping FLIRT runtime library address ranges.
    pub(crate) fn extract_library_ranges(
        res: &AnalysisResult<'_>,
        arch_name: &str,
    ) -> Vec<(u64, u64)> {
        match res.cfg.as_ref() {
            Some(cfg) if !res.library_functions.is_empty() => {
                let all_entry_points: FxHashSet<u64> =
                    res.library_functions.keys().copied().collect();

                let arch_enum = match arch_name {
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

                Self::merge_ranges(ranges)
            }
            _ => Vec::new(),
        }
    }

    /// Extracts localized basic block scopes, instruction slices, and tight-loop indicators.
    pub(crate) fn extract_block_scopes(
        cfg: &'buf ControlFlowGraph,
        is_lib_block: impl Fn(u64) -> bool,
        api_ids: &FxHashSet<PatternID>,
    ) -> Vec<BlockScopeFeatures<'buf>> {
        let tight_loops: FxHashSet<u64> = cfg
            .edges
            .iter()
            .filter(|(src, dst, _)| src == dst)
            .map(|(src, _, _)| *src)
            .collect();

        let mut sorted_blocks: Vec<&'buf BasicBlock> = cfg
            .blocks
            .values()
            .filter(|block| !is_lib_block(block.start_address))
            .collect();
        sorted_blocks.sort_unstable_by_key(|b| b.start_address);

        let mut block_scopes = Vec::with_capacity(sorted_blocks.len());
        for block in sorted_blocks {
            let instructions = cfg.as_block_instr(block);
            let mut patterns = FxHashSet::default();
            let mut apis = FxHashSet::default();

            for insn in instructions {
                for &pat in &insn.matched {
                    patterns.insert(pat);
                    if api_ids.contains(&pat) {
                        apis.insert(pat);
                    }
                }
            }

            let is_tight_loop = tight_loops.contains(&block.start_address);

            block_scopes.push(BlockScopeFeatures {
                start_address: block.start_address,
                end_address: block.end_address,
                instructions,
                patterns,
                apis,
                is_tight_loop,
            });
        }

        block_scopes
    }

    /// Reconstructs function scopes, calculating local cycle presence, McCabe complexity, and recursion.
    fn extract_function_scopes(
        cfg: &'buf ControlFlowGraph,
        block_scopes: &[BlockScopeFeatures<'buf>],
        is_lib_block: impl Fn(u64) -> bool,
        library_functions: &FxHashMap<u64, String>,
    ) -> Vec<FunctionScopeFeatures<'buf>> {
        let addr_to_block_idx: FxHashMap<u64, usize> = block_scopes
            .iter()
            .enumerate()
            .map(|(idx, b)| (b.start_address, idx))
            .collect();

        let mut sorted_functions: Vec<&crate::core::cfg::Function> = cfg
            .functions
            .values()
            .filter(|func| !is_lib_block(func.start_address))
            .collect();
        sorted_functions.sort_unstable_by_key(|f| f.start_address);

        let mut function_scopes = Vec::with_capacity(sorted_functions.len());

        for func in sorted_functions {
            let mut block_indices: Vec<usize> = func
                .basic_blocks
                .iter()
                .filter_map(|addr| addr_to_block_idx.get(addr).copied())
                .collect();

            if block_indices.is_empty() {
                continue;
            }
            block_indices.sort_unstable();

            let mut patterns = FxHashSet::default();
            let mut apis = FxHashSet::default();
            for &idx in &block_indices {
                patterns.extend(&block_scopes[idx].patterns);
                apis.extend(&block_scopes[idx].apis);
            }

            // Local intra-procedural adjacency list for McCabe complexity & loop detection
            let mut local_addr_to_idx: FxHashMap<u64, usize> =
                FxHashMap::with_capacity(block_indices.len());
            for (local_idx, &global_block_idx) in block_indices.iter().enumerate() {
                local_addr_to_idx.insert(block_scopes[global_block_idx].start_address, local_idx);
            }

            let mut local_adj: Adj = vec![SmallVec::new(); block_indices.len()];
            let mut is_recursive = false;
            let mut external_calls = FxHashSet::default();

            for &(src, dst, edge_type) in &cfg.edges {
                if local_addr_to_idx.contains_key(&src) {
                    if edge_type == EdgeType::Call {
                        if dst == func.start_address {
                            is_recursive = true;
                        } else {
                            external_calls.insert(dst);
                        }
                    } else if let Some(&d) = local_addr_to_idx.get(&dst) {
                        let s = local_addr_to_idx[&src];
                        local_adj[s].push(d as u32);
                    }
                }
            }

            // Also check calls from instructions
            for &idx in &block_indices {
                for insn in block_scopes[idx].instructions {
                    if insn.inst_class == crate::core::cfg::InstructionClass::Call
                        && let Some(target) = ControlFlowGraph::parse_target_addr(&insn.op_str)
                    {
                        if target == func.start_address {
                            is_recursive = true;
                        } else {
                            external_calls.insert(target);
                        }
                    }
                }
            }

            for succs in local_adj.iter_mut() {
                succs.sort_unstable();
                succs.dedup();
            }

            let has_loop = Self::has_cycle(&local_adj);
            let cyclomatic_complexity = Self::max_cyclomatic_complexity(&local_adj);
            let calls_from = external_calls.len();
            let name = library_functions.get(&func.start_address).cloned();

            let end_address = block_indices
                .iter()
                .map(|&i| block_scopes[i].end_address)
                .max()
                .unwrap_or(func.end_address);

            function_scopes.push(FunctionScopeFeatures {
                start_address: func.start_address,
                end_address,
                block_indices,
                patterns,
                apis,
                basic_blocks_count: local_addr_to_idx.len(),
                has_loop,
                cyclomatic_complexity,
                is_recursive,
                calls_from,
                name,
                _marker: std::marker::PhantomData,
            });
        }

        function_scopes
    }

    /// Aggregates global file-level features across functions, imports, exports, and data sections.
    fn extract_file_scope(
        res: &'buf AnalysisResult<'buf>,
        function_scopes: &[FunctionScopeFeatures<'buf>],
        total_blocks: usize,
        raw_buffer: &'buf [u8],
    ) -> FileScopeFeatures<'buf> {
        let mut apis = FxHashSet::with_capacity(res.imports.len() + res.exports.len());
        for &api_id in res.imports.iter().chain(res.exports.iter()) {
            apis.insert(PatternID::must(api_id));
        }
        for func in function_scopes {
            apis.extend(&func.apis);
        }

        let string_capacity: usize = res.string_values.values().map(|v| v.len()).sum();
        let mut strings = AHashSet::with_capacity(string_capacity);
        for instances in res.string_values.values() {
            for inst in instances {
                strings.insert(inst.data.to_lowercase());
            }
        }

        let has_loop = function_scopes.iter().any(|f| f.has_loop);
        let max_cyclomatic_complexity = function_scopes
            .iter()
            .map(|f| f.cyclomatic_complexity)
            .max()
            .unwrap_or(0);

        FileScopeFeatures {
            apis,
            strings,
            section_entropies: &res.section_entropy,
            has_code_cave: !res.code_cave.is_empty(),
            has_packer_sig: !res.packer_signatures.is_empty(),
            basic_blocks_count: total_blocks,
            has_loop,
            max_cyclomatic_complexity,
            raw_buffer,
        }
    }

    /// Normalizes global binary format, architecture, and OS metadata.
    fn extract_global_scope(res: &AnalysisResult<'_>) -> GlobalScopeFeatures {
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

        GlobalScopeFeatures {
            os: binary_type,
            arch: res.metadata.architecture_name().to_lowercase(),
            binary_format: binary_format.to_string(),
        }
    }

    /// Returns the file-level scope features.
    #[inline]
    pub fn file_scope(&self) -> &FileScopeFeatures<'buf> {
        &self.file_scope
    }

    /// Returns the non-library functions extracted at function scope.
    #[inline]
    pub fn function_scope(&self) -> &[FunctionScopeFeatures<'buf>] {
        &self.function_scope
    }

    /// Returns the non-library basic blocks extracted at basic block scope.
    #[inline]
    pub fn basic_block_scope(&self) -> &[BlockScopeFeatures<'buf>] {
        &self.basic_block_scope
    }

    /// Returns the global environment and format features.
    #[inline]
    pub fn global_scope(&self) -> &GlobalScopeFeatures {
        &self.global_scope
    }

    /// Finds a function scope by its entry virtual address.
    pub fn function_at(&self, address: u64) -> Option<&FunctionScopeFeatures<'buf>> {
        self.function_scope
            .iter()
            .find(|f| f.start_address == address)
    }

    /// Finds a basic block scope by its start virtual address.
    pub fn block_at(&self, address: u64) -> Option<&BlockScopeFeatures<'buf>> {
        self.basic_block_scope
            .iter()
            .find(|b| b.start_address == address)
    }

    /// Returns a shared reference to the backing instruction slice.
    #[inline]
    pub fn instructions(&self) -> &[InstructionInfo] {
        &self.cfg_instructions
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

/// Global format, operating system, and architecture features valid across all rule scopes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GlobalScopeFeatures {
    /// Target operating system string (e.g. "windows", "linux", "macos").
    pub(crate) os: String,
    /// Target CPU architecture string (e.g. "x86_64", "x86", "arm", "arm64").
    pub(crate) arch: String,
    /// Canonical binary format identifier (`pe`, `elf`, or `macho`).
    pub(crate) binary_format: String,
}

impl GlobalScopeFeatures {
    /// Returns the target operating system string.
    #[inline]
    pub fn os(&self) -> &str {
        &self.os
    }

    /// Returns the target CPU architecture string.
    #[inline]
    pub fn arch(&self) -> &str {
        &self.arch
    }

    /// Returns the canonical binary format identifier (`pe`, `elf`, or `macho`).
    #[inline]
    pub fn binary_format(&self) -> &str {
        &self.binary_format
    }
}

/// Localized features, pattern matches, and instructions for a single basic block.
#[derive(Debug, Clone)]
pub struct BlockScopeFeatures<'buf> {
    /// Virtual start address of the basic block.
    pub(crate) start_address: u64,
    /// Virtual end address of the basic block.
    pub(crate) end_address: u64,
    /// Borrowed slice of instructions contained in this block.
    pub(crate) instructions: &'buf [InstructionInfo],
    /// All pattern IDs matched across this block's instructions (APIs, numbers, offsets, mnemonics, strings).
    pub(crate) patterns: FxHashSet<PatternID>,
    /// Resolved API pattern IDs invoked or referenced within this block.
    pub(crate) apis: FxHashSet<PatternID>,
    /// Whether this basic block branches directly to its own start address (tight loop).
    pub(crate) is_tight_loop: bool,
}

impl<'buf> BlockScopeFeatures<'buf> {
    /// Returns the virtual start address of the basic block.
    #[inline]
    pub fn start_address(&self) -> u64 {
        self.start_address
    }

    /// Returns the virtual end address of the basic block.
    #[inline]
    pub fn end_address(&self) -> u64 {
        self.end_address
    }

    /// Returns the borrowed slice of instructions contained in this block.
    #[inline]
    pub fn instructions(&self) -> &'buf [InstructionInfo] {
        self.instructions
    }

    /// Returns all pattern IDs matched across this block's instructions.
    #[inline]
    pub fn patterns(&self) -> &FxHashSet<PatternID> {
        &self.patterns
    }

    /// Returns resolved API pattern IDs invoked or referenced within this block.
    #[inline]
    pub fn apis(&self) -> &FxHashSet<PatternID> {
        &self.apis
    }

    /// Returns whether this basic block branches directly to its own start address (tight loop).
    #[inline]
    pub fn is_tight_loop(&self) -> bool {
        self.is_tight_loop
    }
}

/// Localized features, control-flow metrics, and constituent basic blocks for a single function.
#[derive(Debug, Clone)]
pub struct FunctionScopeFeatures<'buf> {
    /// Function entry virtual memory address.
    pub(crate) start_address: u64,
    /// Function end virtual memory address across constituent blocks.
    pub(crate) end_address: u64,
    /// Indices of constituent blocks within `FeatureSet::basic_block_scope`.
    pub(crate) block_indices: Vec<usize>,
    /// Union of all pattern IDs matched within this function's constituent blocks.
    pub(crate) patterns: FxHashSet<PatternID>,
    /// All APIs called or resolved within this function.
    pub(crate) apis: FxHashSet<PatternID>,
    /// Number of basic blocks in this function.
    pub(crate) basic_blocks_count: usize,
    /// Whether a loop was detected within this function's local control flow.
    pub(crate) has_loop: bool,
    /// McCabe cyclomatic complexity score computed over this function's local subgraph.
    pub(crate) cyclomatic_complexity: usize,
    /// Whether this function calls its own entry address directly (recursive call).
    pub(crate) is_recursive: bool,
    /// Number of unique external function call destinations called from this function.
    pub(crate) calls_from: usize,
    /// FLIRT or symbol-recovered function name, if identified.
    pub(crate) name: Option<String>,
    /// Phantom marker for lifetime `'buf`.
    pub(crate) _marker: std::marker::PhantomData<&'buf ()>,
}

impl<'buf> FunctionScopeFeatures<'buf> {
    /// Returns the function entry virtual memory address.
    #[inline]
    pub fn start_address(&self) -> u64 {
        self.start_address
    }

    /// Returns the function end virtual memory address across constituent blocks.
    #[inline]
    pub fn end_address(&self) -> u64 {
        self.end_address
    }

    /// Returns the indices of constituent blocks within `FeatureSet::basic_block_scope`.
    #[inline]
    pub fn block_indices(&self) -> &[usize] {
        &self.block_indices
    }

    /// Returns the union of all pattern IDs matched within this function's constituent blocks.
    #[inline]
    pub fn patterns(&self) -> &FxHashSet<PatternID> {
        &self.patterns
    }

    /// Returns all APIs called or resolved within this function.
    #[inline]
    pub fn apis(&self) -> &FxHashSet<PatternID> {
        &self.apis
    }

    /// Returns the number of basic blocks in this function.
    #[inline]
    pub fn basic_blocks_count(&self) -> usize {
        self.basic_blocks_count
    }

    /// Returns whether a loop was detected within this function's local control flow.
    #[inline]
    pub fn has_loop(&self) -> bool {
        self.has_loop
    }

    /// Returns McCabe cyclomatic complexity score computed over this function's local subgraph.
    #[inline]
    pub fn cyclomatic_complexity(&self) -> usize {
        self.cyclomatic_complexity
    }

    /// Returns whether this function calls its own entry address directly (recursive call).
    #[inline]
    pub fn is_recursive(&self) -> bool {
        self.is_recursive
    }

    /// Returns the number of unique external function call destinations called from this function.
    #[inline]
    pub fn calls_from(&self) -> usize {
        self.calls_from
    }

    /// Returns FLIRT or symbol-recovered function name, if identified.
    #[inline]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
}

/// Binary-wide structural and symbol features evaluated at file scope.
#[derive(Debug, Clone)]
pub struct FileScopeFeatures<'buf> {
    /// Union of all APIs across functions + dynamic imports + exports.
    pub(crate) apis: FxHashSet<PatternID>,
    /// Extracted string constants and YARA string matches.
    pub(crate) strings: AHashSet<String>,
    /// Section Shannon entropies.
    pub(crate) section_entropies: &'buf AHashMap<&'buf str, f64>,
    /// Whether code caves (NOP sleds / null padding) were detected.
    pub(crate) has_code_cave: bool,
    /// Whether packer or crypter signatures were matched.
    pub(crate) has_packer_sig: bool,
    /// Total count of non-library basic blocks in the binary.
    pub(crate) basic_blocks_count: usize,
    /// Whether any loop was detected across functions.
    pub(crate) has_loop: bool,
    /// Maximum McCabe cyclomatic complexity across all functions.
    pub(crate) max_cyclomatic_complexity: usize,
    /// Raw binary buffer for direct regex pattern verification.
    pub(crate) raw_buffer: &'buf [u8],
}

impl<'buf> FileScopeFeatures<'buf> {
    /// Returns the union of all APIs across functions + dynamic imports + exports.
    #[inline]
    pub fn apis(&self) -> &FxHashSet<PatternID> {
        &self.apis
    }

    /// Returns extracted string constants and YARA string matches.
    #[inline]
    pub fn strings(&self) -> &AHashSet<String> {
        &self.strings
    }

    /// Returns section Shannon entropies.
    #[inline]
    pub fn section_entropies(&self) -> &'buf AHashMap<&'buf str, f64> {
        self.section_entropies
    }

    /// Returns whether code caves were detected.
    #[inline]
    pub fn has_code_cave(&self) -> bool {
        self.has_code_cave
    }

    /// Returns whether packer or crypter signatures were matched.
    #[inline]
    pub fn has_packer_sig(&self) -> bool {
        self.has_packer_sig
    }

    /// Returns the total count of non-library basic blocks in the binary.
    #[inline]
    pub fn basic_blocks_count(&self) -> usize {
        self.basic_blocks_count
    }

    /// Returns whether any loop was detected across functions.
    #[inline]
    pub fn has_loop(&self) -> bool {
        self.has_loop
    }

    /// Returns the maximum McCabe cyclomatic complexity across all functions.
    #[inline]
    pub fn max_cyclomatic_complexity(&self) -> usize {
        self.max_cyclomatic_complexity
    }

    /// Returns the raw binary buffer for direct regex pattern verification.
    #[inline]
    pub fn raw_buffer(&self) -> &'buf [u8] {
        self.raw_buffer
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

        let fs = FeatureSet::new(&res, &[]);

        // Test APIs (both hooking and process injection should be merged)
        assert!(fs.file_scope.apis.contains(&PatternID::must(10)));
        assert!(fs.file_scope.apis.contains(&PatternID::must(20)));
        assert_eq!(fs.file_scope.apis.len(), 2);

        // Test Strings
        assert!(fs.file_scope.strings.contains("http://malicious.com"));
        assert_eq!(fs.file_scope.strings.len(), 1);

        // Test Section Entropies
        assert_eq!(fs.file_scope.section_entropies.get(".text"), Some(&6.8));

        // Test booleans
        assert!(fs.file_scope.has_code_cave);
        assert!(fs.file_scope.has_packer_sig);
    }

    #[test]
    fn test_feature_set_creation_empty() {
        let res = AnalysisResult::default();
        let fs = FeatureSet::new(&res, &[]);

        assert!(fs.file_scope.apis.is_empty());
        assert!(fs.file_scope.strings.is_empty());
        assert!(fs.file_scope.section_entropies.is_empty());
        assert!(!fs.file_scope.has_code_cave);
        assert!(!fs.file_scope.has_packer_sig);
        assert_eq!(fs.basic_block_scope.len(), 0);
        assert_eq!(fs.function_scope.len(), 0);
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

        let fs = FeatureSet::new(&res, &[]);

        // The user block at 0x1000 should be retained
        assert!(
            fs.basic_block_scope
                .iter()
                .any(|b| b.start_address == 0x1000)
        );

        // The library block at 0x2000 should be excluded
        assert!(
            !fs.basic_block_scope
                .iter()
                .any(|b| b.start_address == 0x2000)
        );
        assert_eq!(fs.file_scope.basic_blocks_count, 1);
        assert_eq!(fs.function_scope.len(), 1);
        assert_eq!(fs.function_scope[0].start_address, 0x1000);
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

        let fs = FeatureSet::new(&res, &[]);
        assert_eq!(fs.file_scope.max_cyclomatic_complexity, 2);
        assert_eq!(fs.function_scope.len(), 2);

        let f1 = fs.function_at(0x1000).expect("Function 1 must exist");
        assert_eq!(f1.cyclomatic_complexity, 1);
        assert!(!f1.has_loop);

        let f2 = fs.function_at(0x2000).expect("Function 2 must exist");
        assert_eq!(f2.cyclomatic_complexity, 2);
    }

    #[test]
    fn test_tight_loop_and_recursion_detection() {
        use crate::core::cfg::ControlFlowGraph;

        let mut res = AnalysisResult::default();
        res.metadata.architecture = 62;

        let insns = vec![
            // Function at 0x1000 with tight loop (jmp to self)
            InstructionInfo {
                address: 0x1000,
                mnemonic: "jmp".into(),
                op_str: "0x1000".into(),
                api_resolution: None,
                matched: smallvec::SmallVec::new(),
                inst_class: InstructionClass::UnconditionalJump,
            },
            // Function at 0x2000 that recursively calls itself
            InstructionInfo {
                address: 0x2000,
                mnemonic: "call".into(),
                op_str: "0x2000".into(),
                api_resolution: None,
                matched: smallvec::SmallVec::new(),
                inst_class: InstructionClass::Call,
            },
            InstructionInfo {
                address: 0x2005,
                mnemonic: "ret".into(),
                op_str: "".into(),
                api_resolution: None,
                matched: smallvec::SmallVec::new(),
                inst_class: InstructionClass::Return,
            },
        ];

        let cfg = ControlFlowGraph::new(insns.into(), &BinaryArch::X64);
        res.cfg = Some(cfg);

        let fs = FeatureSet::new(&res, &[]);

        let b1 = fs.block_at(0x1000).expect("Block 0x1000 must exist");
        assert!(b1.is_tight_loop);

        let f2 = fs.function_at(0x2000).expect("Function 0x2000 must exist");
        assert!(f2.is_recursive);
    }

    #[test]
    fn test_upward_feature_propagation() {
        use crate::core::cfg::ControlFlowGraph;

        let mut res = AnalysisResult::default();
        res.metadata.architecture = 62;
        res.imports.push(42);

        let insns = vec![
            InstructionInfo {
                address: 0x1000,
                mnemonic: "call".into(),
                op_str: "0x1005".into(),
                api_resolution: None,
                matched: smallvec::smallvec![PatternID::must(42), PatternID::must(99)],
                inst_class: InstructionClass::Call,
            },
            InstructionInfo {
                address: 0x1005,
                mnemonic: "ret".into(),
                op_str: "".into(),
                api_resolution: None,
                matched: smallvec::SmallVec::new(),
                inst_class: InstructionClass::Return,
            },
        ];

        let cfg = ControlFlowGraph::new(insns.into(), &BinaryArch::X64);
        res.cfg = Some(cfg);

        let fs = FeatureSet::new(&res, &[]);

        // Basic block contains matched pattern IDs
        let b = fs.block_at(0x1000).expect("Block at 0x1000 must exist");
        assert!(b.patterns.contains(&PatternID::must(42)));
        assert!(b.patterns.contains(&PatternID::must(99)));
        assert!(b.apis.contains(&PatternID::must(42)));
        assert!(!b.apis.contains(&PatternID::must(99)));

        // Function scope inherits pattern IDs from constituent blocks
        let f = fs
            .function_at(0x1000)
            .expect("Function at 0x1000 must exist");
        assert!(f.patterns.contains(&PatternID::must(42)));
        assert!(f.patterns.contains(&PatternID::must(99)));
        assert!(f.apis.contains(&PatternID::must(42)));

        // File scope contains the API
        assert!(fs.file_scope.apis.contains(&PatternID::must(42)));
    }
}
