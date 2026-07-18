//! # Basic Block & Control Flow Graph Reconstruction
//!
//! This module analyzes linear disassembler output to reconstruct basic blocks and
//! model directed control flow transitions using graph topologies.

use petgraph::graph::DiGraph;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::{
    core::{
        BasicBlock, BinaryArch, EdgeType,
        types::{InstructionClass, InstructionInfo},
    },
    utils::cfg::{classify_instruction, parse_target_address},
};

/// A serialized and queryable model of a binary's Control Flow Graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFlowGraph {
    /// Mapped basic blocks by start virtual address.
    pub blocks: HashMap<u64, BasicBlock>,
    /// Directed links representing control flow jumps.
    pub edges: Vec<(u64, u64, EdgeType)>,
}

impl ControlFlowGraph {
    /// Analyzes an instruction list to partition basic blocks and map execution transitions.
    pub fn new(instructions: &[InstructionInfo], arch: &BinaryArch) -> Self {
        let mut leaders = HashSet::new();
        if !instructions.is_empty() {
            leaders.insert(instructions[0].address);
        }

        for (idx, insn) in instructions.iter().enumerate() {
            let mnemonic = insn.mnemonic.as_str();
            let class = classify_instruction(mnemonic, arch);

            match class {
                InstructionClass::ConditionalJump
                | InstructionClass::UnconditionalJump
                | InstructionClass::Call => {
                    if let Some(target) = parse_target_address(insn.op_str.as_str()) {
                        leaders.insert(target);
                    }
                    if idx + 1 < instructions.len() {
                        leaders.insert(instructions[idx + 1].address);
                    }
                }
                InstructionClass::Return if idx + 1 < instructions.len() => {
                    leaders.insert(instructions[idx + 1].address);
                }
                _ => {}
            }
        }

        let mut addr_to_idx = HashMap::new();
        for (idx, insn) in instructions.iter().enumerate() {
            addr_to_idx.insert(insn.address, idx);
        }

        let mut sorted_leaders: Vec<u64> = leaders.into_iter().collect();
        sorted_leaders.sort_unstable();

        let mut blocks = HashMap::new();
        let mut block_starts = vec![];

        for i in 0..sorted_leaders.len() {
            let start_addr = sorted_leaders[i];
            let start_idx = match addr_to_idx.get(&start_addr) {
                Some(&idx) => idx,
                None => continue,
            };

            let end_idx = if i + 1 < sorted_leaders.len() {
                let next_leader = sorted_leaders[i + 1];
                match addr_to_idx.get(&next_leader) {
                    Some(&idx) => idx,
                    None => instructions.len(),
                }
            } else {
                instructions.len()
            };

            if start_idx >= end_idx {
                continue;
            }

            let block_insns = &instructions[start_idx..end_idx];
            let inst_infos = block_insns.to_vec();

            let basic_block = BasicBlock {
                start_address: start_addr,
                end_address: block_insns.last().unwrap().address,
                instructions: inst_infos,
            };

            blocks.insert(start_addr, basic_block);
            block_starts.push(start_addr);
        }

        let mut edges = vec![];
        for (idx, &start_addr) in block_starts.iter().enumerate() {
            let block = &blocks[&start_addr];
            let last_insn = match block.instructions.last() {
                Some(insn) => insn,
                None => continue,
            };

            let class = classify_instruction(&last_insn.mnemonic, arch);
            let target = parse_target_address(&last_insn.op_str);
            let next_block_addr = if idx + 1 < block_starts.len() {
                Some(block_starts[idx + 1])
            } else {
                None
            };

            match class {
                InstructionClass::ConditionalJump => {
                    if let Some(t) = target
                        && blocks.contains_key(&t)
                    {
                        edges.push((start_addr, t, EdgeType::ConditionalTrue));
                    }
                    if let Some(next_addr) = next_block_addr {
                        edges.push((start_addr, next_addr, EdgeType::ConditionalFalse));
                    }
                }
                InstructionClass::UnconditionalJump => {
                    if let Some(t) = target
                        && blocks.contains_key(&t)
                    {
                        edges.push((start_addr, t, EdgeType::Unconditional));
                    }
                }
                InstructionClass::Call => {
                    if let Some(t) = target
                        && blocks.contains_key(&t)
                    {
                        edges.push((start_addr, t, EdgeType::Call));
                    }
                    if let Some(next_addr) = next_block_addr {
                        edges.push((start_addr, next_addr, EdgeType::FallThrough));
                    }
                }
                InstructionClass::Return => {}
                InstructionClass::Normal => {
                    if let Some(next_addr) = next_block_addr {
                        edges.push((start_addr, next_addr, EdgeType::FallThrough));
                    }
                }
            }
        }

        Self { blocks, edges }
    }

    /// Converts the control flow graph into a Graphviz DOT representation.
    pub fn to_dot(&self) -> String {
        let mut dot = String::new();
        dot.push_str("digraph CFG {\n");
        dot.push_str("  node [shape=box, fontname=\"Courier\", style=\"filled\", fillcolor=\"#1E1E1E\", color=\"#00FF00\", fontcolor=\"#00FF00\"];\n");
        dot.push_str("  edge [fontname=\"Courier\", fontsize=8];\n");
        dot.push_str("  bgcolor=\"#0C0C0C\";\n");

        // Sort blocks by start address for deterministic output
        let mut sorted_blocks: Vec<(&u64, &BasicBlock)> = self.blocks.iter().collect();
        sorted_blocks.sort_by_key(|&(&addr, _)| addr);

        for (addr, block) in sorted_blocks {
            let mut label = format!("Block 0x{:X}\\l", addr);
            label.push_str("-----------------\\l");
            for insn in &block.instructions {
                label.push_str(&format!(
                    "0x{:X}: {:<6} {}\\l",
                    insn.address, insn.mnemonic, insn.op_str
                ));
            }
            dot.push_str(&format!("  node_0x{:X} [label=\"{}\"];\n", addr, label));
        }

        for (src, dst, edge_type) in &self.edges {
            let (color, style) = match edge_type {
                EdgeType::ConditionalTrue => ("green", "solid"),
                EdgeType::ConditionalFalse => ("red", "solid"),
                EdgeType::Unconditional => ("blue", "solid"),
                EdgeType::Call => ("purple", "dashed"),
                EdgeType::FallThrough => ("gray", "solid"),
            };
            dot.push_str(&format!(
                "  node_0x{:X} -> node_0x{:X} [color=\"{}\", style=\"{}\", label=\"{:?}\"];\n",
                src, dst, color, style, edge_type
            ));
        }

        dot.push_str("}\n");
        dot
    }

    /// Builds a `petgraph::graph::DiGraph` representation of the control flow graph.
    pub fn to_petgraph(&self) -> DiGraph<BasicBlock, EdgeType> {
        let mut graph = DiGraph::new();
        let mut indices = HashMap::new();

        for (&addr, block) in &self.blocks {
            let idx = graph.add_node(block.clone());
            indices.insert(addr, idx);
        }

        for &(src, dst, edge_type) in &self.edges {
            if let (Some(&src_idx), Some(&dst_idx)) = (indices.get(&src), indices.get(&dst)) {
                graph.add_edge(src_idx, dst_idx, edge_type);
            }
        }

        graph
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{BinaryArch, EdgeType, types::InstructionInfo};

    /// Helper to build an `InstructionInfo` with minimal boilerplate.
    fn insn(address: u64, mnemonic: &str, op_str: &str) -> InstructionInfo {
        InstructionInfo {
            address,
            mnemonic: mnemonic.to_string(),
            op_str: op_str.to_string(),
        }
    }

    #[test]
    fn test_empty_instructions() {
        let cfg = ControlFlowGraph::new(&[], &BinaryArch::X64);
        assert!(cfg.blocks.is_empty());
        assert!(cfg.edges.is_empty());
    }

    #[test]
    fn test_single_basic_block_no_branches() {
        // A straight-line sequence with no control-flow changes forms one block.
        let instructions = vec![
            insn(0x1000, "push", "rbp"),
            insn(0x1001, "mov", "rbp, rsp"),
            insn(0x1004, "nop", ""),
        ];
        let cfg = ControlFlowGraph::new(&instructions, &BinaryArch::X64);

        assert_eq!(cfg.blocks.len(), 1);
        assert!(cfg.edges.is_empty());

        let block = &cfg.blocks[&0x1000];
        assert_eq!(block.start_address, 0x1000);
        assert_eq!(block.end_address, 0x1004);
        assert_eq!(block.instructions.len(), 3);
    }

    #[test]
    fn test_conditional_jump_splits_block() {
        // A conditional jump at 0x1002 targeting 0x2000 should:
        //  - Split into two blocks at 0x1000 and 0x1003.
        //  - Emit a ConditionalTrue edge to 0x2000 (if block exists) and
        //    a ConditionalFalse fallthrough edge to 0x1003.
        let instructions = vec![
            insn(0x1000, "cmp", "eax, 0"),
            insn(0x1002, "je", "0x1004"),
            insn(0x1003, "nop", ""),
            insn(0x1004, "mov", "eax, 1"),
        ];
        let cfg = ControlFlowGraph::new(&instructions, &BinaryArch::X64);

        // Three leaders: 0x1000 (entry), 0x1003 (fallthrough after je), 0x1004 (target of je)
        assert_eq!(cfg.blocks.len(), 3);
        assert!(cfg.blocks.contains_key(&0x1000));
        assert!(cfg.blocks.contains_key(&0x1003));
        assert!(cfg.blocks.contains_key(&0x1004));

        // Block 0x1000 should contain [cmp, je]
        assert_eq!(cfg.blocks[&0x1000].instructions.len(), 2);

        // Block 0x1003 should contain [nop]
        assert_eq!(cfg.blocks[&0x1003].instructions.len(), 1);

        // Block 0x1004 should contain [mov]
        assert_eq!(cfg.blocks[&0x1004].instructions.len(), 1);

        // Should have a ConditionalTrue edge from 0x1000 -> 0x1004
        assert!(
            cfg.edges
                .contains(&(0x1000, 0x1004, EdgeType::ConditionalTrue))
        );

        // Should have a ConditionalFalse edge from 0x1000 -> 0x1003
        assert!(
            cfg.edges
                .contains(&(0x1000, 0x1003, EdgeType::ConditionalFalse))
        );
    }

    #[test]
    fn test_unconditional_jump() {
        let instructions = vec![
            insn(0x1000, "mov", "eax, 0"),
            insn(0x1002, "jmp", "0x1004"),
            insn(0x1003, "nop", ""),
            insn(0x1004, "ret", ""),
        ];
        let cfg = ControlFlowGraph::new(&instructions, &BinaryArch::X64);

        // Should have an Unconditional edge from 0x1000 to the target block
        assert!(
            cfg.edges
                .contains(&(0x1000, 0x1004, EdgeType::Unconditional))
        );

        // Unconditional jumps should NOT produce a fallthrough edge
        let has_fallthrough = cfg
            .edges
            .iter()
            .any(|(src, _, et)| *src == 0x1000 && *et == EdgeType::FallThrough);
        assert!(!has_fallthrough);
    }

    #[test]
    fn test_call_instruction() {
        let instructions = vec![
            insn(0x1000, "mov", "rdi, 0"),
            insn(0x1003, "call", "0x2000"),
            insn(0x1008, "nop", ""),
            insn(0x2000, "push", "rbp"),
            insn(0x2001, "ret", ""),
        ];
        let cfg = ControlFlowGraph::new(&instructions, &BinaryArch::X64);

        // Call edge from 0x1000-block to 0x2000-block
        assert!(cfg.edges.contains(&(0x1000, 0x2000, EdgeType::Call)));

        // Fallthrough edge from 0x1000-block to 0x1008-block (return site)
        assert!(cfg.edges.contains(&(0x1000, 0x1008, EdgeType::FallThrough)));
    }

    #[test]
    fn test_return_terminates_block() {
        let instructions = vec![
            insn(0x1000, "mov", "eax, 0"),
            insn(0x1002, "ret", ""),
            insn(0x1003, "nop", ""),
        ];
        let cfg = ControlFlowGraph::new(&instructions, &BinaryArch::X64);

        // ret terminates the block — no outgoing edges from block 0x1000
        let block_0x1000_edges: Vec<_> = cfg
            .edges
            .iter()
            .filter(|(src, _, _)| *src == 0x1000)
            .collect();
        assert!(block_0x1000_edges.is_empty());
    }

    #[test]
    fn test_fallthrough_between_normal_blocks() {
        // When a leader is introduced by a branch target elsewhere, normal instructions
        // at the boundary should produce a FallThrough edge.
        let instructions = vec![
            insn(0x1000, "nop", ""),
            insn(0x1001, "jmp", "0x1003"),
            insn(0x1002, "nop", ""),
            insn(0x1003, "nop", ""),
            insn(0x1004, "nop", ""),
        ];
        let cfg = ControlFlowGraph::new(&instructions, &BinaryArch::X64);

        // Block starting at 0x1002 ends with "nop" (Normal) and should fallthrough to 0x1003
        assert!(cfg.edges.contains(&(0x1002, 0x1003, EdgeType::FallThrough)));
    }

    #[test]
    fn test_jump_to_nonexistent_target() {
        // If a jump targets an address not present in the instruction stream,
        // no edge should be emitted for that target.
        let instructions = vec![insn(0x1000, "jmp", "0x9999"), insn(0x1002, "nop", "")];
        let cfg = ControlFlowGraph::new(&instructions, &BinaryArch::X64);

        let edges_to_9999: Vec<_> = cfg
            .edges
            .iter()
            .filter(|(_, dst, _)| *dst == 0x9999)
            .collect();
        assert!(edges_to_9999.is_empty());
    }

    #[test]
    fn test_to_dot_output() {
        let instructions = vec![insn(0x1000, "nop", ""), insn(0x1001, "jmp", "0x1000")];
        let cfg = ControlFlowGraph::new(&instructions, &BinaryArch::X64);
        let dot = cfg.to_dot();

        assert!(dot.starts_with("digraph CFG {"));
        assert!(dot.contains("node_0x1000"));
        assert!(dot.contains("Unconditional"));
        assert!(dot.ends_with("}\n"));
    }

    #[test]
    fn test_to_petgraph_roundtrip() {
        let instructions = vec![
            insn(0x1000, "cmp", "eax, 0"),
            insn(0x1002, "je", "0x1004"),
            insn(0x1003, "nop", ""),
            insn(0x1004, "ret", ""),
        ];
        let cfg = ControlFlowGraph::new(&instructions, &BinaryArch::X64);
        let graph = cfg.to_petgraph();

        // The petgraph should have the same number of nodes as blocks
        assert_eq!(graph.node_count(), cfg.blocks.len());

        // The petgraph should have the same number of edges
        assert_eq!(graph.edge_count(), cfg.edges.len());
    }

    #[test]
    fn test_arm64_conditional_branch() {
        let instructions = vec![
            insn(0x400, "cmp", "w0, #0"),
            insn(0x404, "b.eq", "0x40c"),
            insn(0x408, "mov", "w0, #1"),
            insn(0x40c, "ret", ""),
        ];
        let cfg = ControlFlowGraph::new(&instructions, &BinaryArch::Arm64);

        assert!(
            cfg.edges
                .contains(&(0x400, 0x40c, EdgeType::ConditionalTrue))
        );
        assert!(
            cfg.edges
                .contains(&(0x400, 0x408, EdgeType::ConditionalFalse))
        );
    }

    #[test]
    fn test_single_instruction() {
        let instructions = vec![insn(0x1000, "ret", "")];
        let cfg = ControlFlowGraph::new(&instructions, &BinaryArch::X64);

        assert_eq!(cfg.blocks.len(), 1);
        assert!(cfg.edges.is_empty());

        let block = &cfg.blocks[&0x1000];
        assert_eq!(block.start_address, 0x1000);
        assert_eq!(block.end_address, 0x1000);
        assert_eq!(block.instructions.len(), 1);
    }

    #[test]
    fn test_multiple_conditional_jumps() {
        // Tests a chain of conditional jumps producing multiple blocks and edges.
        let instructions = vec![
            insn(0x1000, "cmp", "eax, 0"),
            insn(0x1002, "je", "0x1008"),
            insn(0x1004, "cmp", "eax, 1"),
            insn(0x1006, "je", "0x100a"),
            insn(0x1008, "nop", ""),
            insn(0x100a, "ret", ""),
        ];
        let cfg = ControlFlowGraph::new(&instructions, &BinaryArch::X64);

        // First je targets 0x1008
        assert!(
            cfg.edges
                .contains(&(0x1000, 0x1008, EdgeType::ConditionalTrue))
        );
        // First je falls through to 0x1004
        assert!(
            cfg.edges
                .contains(&(0x1000, 0x1004, EdgeType::ConditionalFalse))
        );
        // Second je targets 0x100a
        assert!(
            cfg.edges
                .contains(&(0x1004, 0x100a, EdgeType::ConditionalTrue))
        );
        // Second je falls through to 0x1008
        assert!(
            cfg.edges
                .contains(&(0x1004, 0x1008, EdgeType::ConditionalFalse))
        );
    }
}
