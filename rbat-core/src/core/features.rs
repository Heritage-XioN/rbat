//! # Structural Feature Extraction
//!
//! This module implements the `FeatureSet` structure which extracts and flattens
//! binary analysis results into fast-lookup sets and maps for rule evaluation.

use crate::core::{
    AnalysisResult, BasicBlock, BinaryArch, EdgeType, InstructionClass, InstructionInfo,
};
use crate::utils::{cfg::classify_instruction, flirt::find_function_range};
use std::collections::{HashMap, HashSet};

/// Collected metrics and indicators extracted from the binary for rule evaluation.
#[derive(Debug, Clone)]
pub struct FeatureSet<'a> {
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
    /// Mapped target OS string.
    pub os: String,
    /// Mapped CPU architecture string.
    pub arch: String,
    // CFG structural fields
    pub basic_blocks_count: usize,
    pub has_loop: bool,
    pub max_cyclomatic_complexity: usize,
    // Captured basic blocks for scope evaluation
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

        for (api_name, &addr) in &res.api_hooking {
            if !is_lib_block(addr) {
                apis.insert(api_name.to_lowercase());
            }
        }
        for api_name in &res.process_injection {
            apis.insert(api_name.to_lowercase());
        }

        for instances in res.string_values.values() {
            for inst in instances {
                if !is_lib_block(inst.offset as u64) {
                    strings.insert(inst.data.to_lowercase());
                }
            }
        }

        let mut mnemonics = HashSet::new();
        for (m, addrs) in &res.blacklisted_mnemonics {
            let filtered_addrs: Vec<u64> = addrs
                .iter()
                .copied()
                .filter(|&addr| !is_lib_block(addr))
                .collect();
            if !filtered_addrs.is_empty() {
                mnemonics.insert(m.as_str().into());
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
        let mut apis = HashSet::new();
        let mut strings = HashSet::new();
        let mut mnemonics = HashSet::new();

        let mut buf_m = String::new();
        let mut buf_o = String::new();

        for insn in &block.instructions {
            insn.format_mnemonic_into(&mut buf_m);
            if !mnemonics.contains(&buf_m) {
                mnemonics.insert(buf_m.clone());
            }

            // Capture API names from call targets
            let class = classify_instruction(&buf_m, &BinaryArch::X64);

            insn.format_operands_into(&mut buf_o);
            if class == InstructionClass::Call && !apis.contains(&buf_o) {
                apis.insert(buf_o.to_lowercase());
            }

            // Capture any numeric/constants/strings used as instruction arguments
            if !strings.contains(&buf_o) {
                strings.insert(buf_o.to_lowercase());
            }
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
        let mut apis = HashSet::new();
        let mut strings = HashSet::new();
        let mut mnemonics = HashSet::new();

        let mut buf_m = String::new();
        let mut buf_o = String::new();

        insn.format_mnemonic_into(&mut buf_m);
        mnemonics.insert(buf_m.clone());

        insn.format_operands_into(&mut buf_o);
        strings.insert(buf_o.to_lowercase());
        if buf_m.to_lowercase() == "call" {
            apis.insert(buf_o.to_lowercase());
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
            basic_blocks_count: 0,
            has_loop: false,
            max_cyclomatic_complexity: 0,
            blocks: Vec::new(),
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
        assert!(fs.apis.contains("virtualalloc"));
        assert!(fs.apis.contains("writeprocessmemory"));
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
                matched: Vec::new(),
            },
            InstructionInfo {
                address: 0x2000,
                mnemonic: "ret".into(),
                op_str: "".into(),
                matched: Vec::new(),
            },
        ];

        let cfg = ControlFlowGraph::new(&insns, &crate::core::BinaryArch::X64);
        res.cfg = Some(cfg);

        // Add library function at 0x2000
        res.library_functions.insert(0x2000, "strlen".to_string());

        // Add blacklisted mnemonic and API call inside the library block (at 0x2000)
        res.blacklisted_mnemonics
            .insert("cpuid".to_string(), vec![0x2000]);
        res.api_hooking.insert("VirtualAlloc".to_string(), 0x2000);

        let fs = FeatureSet::from_analysis_result(&res);

        // The user block at 0x1000 should be retained
        assert!(fs.blocks.iter().any(|b| b.start_address == 0x1000));

        // The library block at 0x2000 should be excluded
        assert!(!fs.blocks.iter().any(|b| b.start_address == 0x2000));
        assert_eq!(fs.basic_blocks_count, 1);

        // The API call and blacklisted mnemonic from the library block should be excluded
        assert!(fs.apis.is_empty());
        assert!(fs.mnemonics.is_empty());
    }
}
