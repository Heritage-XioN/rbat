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
