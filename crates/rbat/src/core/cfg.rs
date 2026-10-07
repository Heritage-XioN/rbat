//! # Control Flow Graph & Basic Block Reconstruction
//!
//! Reconstructs basic blocks and models directed control flow graph (CFG) topologies
//! from linear disassembly instruction streams.
//!
//! ## Core Types
//!
//! - [`ControlFlowGraph`]: Directed graph of basic blocks and control-flow transition edges.
//! - [`BasicBlock`]: Straight-line instruction sequence with single-entry, single-exit execution.
//! - [`EdgeType`]: Semantic classification of control-flow branch transitions.
//! - [`InstructionClass`]: Control-flow classification of individual machine instructions.
//!
//! ## Overview
//!
//! CFG reconstruction maps linear machine code into a directed graph structure through
//! three coordinated analysis phases:
//!
//! 1. **Leader Identification**: Scans disassembled instructions to identify block entry addresses
//!    ("leaders"):
//!    - The first instruction of the disassembly stream.
//!    - Target addresses of conditional branches, unconditional jumps, and function calls.
//!    - Fallthrough instructions directly succeeding branches, calls, and function returns.
//! 2. **Basic Block Partitioning**: Partitions the instruction array into non-overlapping,
//!    contiguous [`BasicBlock`] ranges `[start_idx..end_idx)` sorted by virtual address.
//! 3. **Edge Resolution & Topology**: Resolves inter-block transitions by inspecting the terminator
//!    instruction of each basic block:
//!    - **Conditional Jumps**: Emits a [`EdgeType::ConditionalTrue`] edge to the branch target (if present)
//!      and a [`EdgeType::ConditionalFalse`] edge to the sequential fallthrough block.
//!    - **Unconditional Jumps**: Emits a [`EdgeType::Unconditional`] edge to the branch target.
//!    - **Function Calls**: Emits a [`EdgeType::Call`] edge to the callee target and a [`EdgeType::FallThrough`]
//!      edge to the return site.
//!    - **Sequential Instructions**: Emits a [`EdgeType::FallThrough`] edge to the next contiguous block.
//!    - **Returns**: Terminates the block with no outgoing edges.
//!
//! ## Examples
//!
//! Constructing a CFG from an instruction stream and exporting it to Graphviz DOT format:
//!
//! ```rust
//! use rbat::core::cfg::ControlFlowGraph;
//! use rbat::core::parser::BinaryArch;
//! use std::sync::Arc;
//!
//! let cfg = ControlFlowGraph::new(Arc::from([]), &BinaryArch::X64);
//! assert!(cfg.blocks.is_empty());
//! assert!(cfg.edges.is_empty());
//!
//! let dot = cfg.to_dot();
//! assert!(dot.starts_with("digraph CFG {"));
//! ```

use crate::core::{disassembler::InstructionInfo, parser::BinaryArch};
use ahash::{HashMapExt, HashSetExt};
use petgraph::graph::DiGraph;
use rustc_hash::{FxHashMap, FxHashSet};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Directed Control Flow Graph of an executable binary.
///
/// `ControlFlowGraph` models code execution paths by partitioning machine code into discrete,
/// single-entry single-exit [`BasicBlock`] nodes and connecting them with directed [`EdgeType`] edges.
/// It retains a shared handle to the backing instruction array to allow zero-copy slicing of
/// individual block instructions during heuristic analysis and rule matching.
///
/// # Invariants
///
/// - Every [`BasicBlock`] mapped in `blocks` references valid half-open slice bounds
///   `[start_idx..end_idx)` into `instructions`.
/// - Block start virtual addresses in `blocks` match their corresponding `BasicBlock::start_address`.
/// - Graph edges reference source and destination block start addresses.
///
/// # Serialization
///
/// `ControlFlowGraph` implements [`Serialize`] and [`Deserialize`]. The backing `instructions`
/// array is annotated with `#[serde(skip)]` to avoid serializing redundant instruction bytes;
/// serialized outputs contain the block mapping and edge topology.
///
/// # Examples
///
/// ```rust
/// use rbat::core::cfg::ControlFlowGraph;
/// use rbat::core::parser::BinaryArch;
/// use std::sync::Arc;
///
/// let cfg = ControlFlowGraph::new(Arc::from([]), &BinaryArch::X64);
/// assert_eq!(cfg.blocks.len(), 0);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFlowGraph {
    /// Shared backing instruction store.
    #[serde(skip)]
    pub instructions: Arc<[InstructionInfo]>,
    /// Mapped basic blocks by start virtual address.
    pub blocks: FxHashMap<u64, BasicBlock>,
    /// Directed links representing control flow jumps.
    pub edges: Vec<(u64, u64, EdgeType)>,
}

impl ControlFlowGraph {
    /// Analyzes an instruction list to partition basic blocks and map execution transitions.
    ///
    /// Identifies leader instructions based on branch targets and sequential boundaries,
    /// groups instructions into [`BasicBlock`] ranges, and resolves directed control-flow
    /// [`EdgeType`] transitions for the specified target CPU architecture.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rbat::core::cfg::ControlFlowGraph;
    /// use rbat::core::parser::BinaryArch;
    /// use std::sync::Arc;
    ///
    /// let instructions = Arc::from([]);
    /// let cfg = ControlFlowGraph::new(instructions, &BinaryArch::X64);
    /// assert!(cfg.blocks.is_empty());
    /// ```
    pub fn new(instructions: Arc<[InstructionInfo]>, arch: &BinaryArch) -> Self {
        let mut leaders = FxHashSet::with_capacity(instructions.len());
        if !instructions.is_empty() {
            leaders.insert(instructions[0].address());
        }

        for (idx, insn) in instructions.iter().enumerate() {
            let class = insn.class(arch);

            match class {
                InstructionClass::ConditionalJump
                | InstructionClass::UnconditionalJump
                | InstructionClass::Call => {
                    if let Some(target) = insn.branch_target() {
                        leaders.insert(target);
                    }
                    if idx + 1 < instructions.len() {
                        leaders.insert(instructions[idx + 1].address());
                    }
                }
                InstructionClass::Return if idx + 1 < instructions.len() => {
                    leaders.insert(instructions[idx + 1].address());
                }
                _ => {}
            }
        }

        let mut addr_to_idx = FxHashMap::with_capacity(instructions.len());
        for (idx, insn) in instructions.iter().enumerate() {
            addr_to_idx.insert(insn.address(), idx);
        }

        let mut sorted_leaders: Vec<u64> = leaders.into_iter().collect();
        sorted_leaders.retain(|addr| addr_to_idx.contains_key(addr));
        sorted_leaders.sort_unstable();

        let mut blocks = FxHashMap::with_capacity(sorted_leaders.len());
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

            let basic_block = BasicBlock {
                start_address: start_addr,
                end_address: instructions[end_idx - 1].address(),
                start_idx,
                end_idx,
            };

            blocks.insert(start_addr, basic_block);
            block_starts.push(start_addr);
        }

        let mut edges = vec![];
        for (idx, &start_addr) in block_starts.iter().enumerate() {
            let block = &blocks[&start_addr];
            let block_insns = &instructions[block.start_idx..block.end_idx];
            let last_insn = match block_insns.last() {
                Some(insn) => insn,
                None => continue,
            };

            let class = last_insn.class(arch);
            let target = last_insn.branch_target();
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

        Self {
            instructions,
            blocks,
            edges,
        }
    }

    /// Converts the control flow graph into a Graphviz DOT representation.
    ///
    /// Generates a styled Graphviz `digraph` with:
    /// - Dark-mode background (`#0C0C0C`) and Courier terminal monospace fonts.
    /// - Blocks labeled with their virtual address and disassembled instruction listing.
    /// - Color-coded edges: green for [`EdgeType::ConditionalTrue`], red for [`EdgeType::ConditionalFalse`],
    ///   blue for [`EdgeType::Unconditional`], purple for [`EdgeType::Call`], and gray for [`EdgeType::FallThrough`].
    /// - Deterministic node ordering sorted by ascending block virtual memory address.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rbat::core::cfg::ControlFlowGraph;
    /// use rbat::core::parser::BinaryArch;
    /// use std::sync::Arc;
    ///
    /// let cfg = ControlFlowGraph::new(Arc::from([]), &BinaryArch::X64);
    /// let dot = cfg.to_dot();
    /// assert!(dot.contains("digraph CFG"));
    /// ```
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
            for insn in self.as_block_instr(block) {
                label.push_str(&format!(
                    "0x{:X}: {:<6} {}\\l",
                    insn.address(),
                    insn.format_mnemonic(),
                    insn.format_operands()
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
    ///
    /// Constructs an owned [`DiGraph`] where each node contains a cloned [`BasicBlock`]
    /// and each directed edge is annotated with its corresponding [`EdgeType`].
    /// Useful for running external graph algorithms such as dominator trees, reachability,
    /// and topological traversals.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rbat::core::cfg::ControlFlowGraph;
    /// use rbat::core::parser::BinaryArch;
    /// use std::sync::Arc;
    ///
    /// let cfg = ControlFlowGraph::new(Arc::from([]), &BinaryArch::X64);
    /// let graph = cfg.to_petgraph();
    /// assert_eq!(graph.node_count(), 0);
    /// ```
    pub fn to_petgraph(&self) -> DiGraph<BasicBlock, EdgeType> {
        let mut graph = DiGraph::new();
        let mut indices = FxHashMap::default();

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

    /// Returns the instruction slice for a given basic block.
    ///
    /// Borrows the block's instruction range directly from the
    /// [`Shared backing instruction store`] using the block's
    /// `[start_idx..end_idx)` indices.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rbat::core::cfg::{BasicBlock, ControlFlowGraph};
    /// use rbat::core::parser::BinaryArch;
    /// use std::sync::Arc;
    ///
    /// let cfg = ControlFlowGraph::new(Arc::from([]), &BinaryArch::X64);
    /// let block = BasicBlock {
    ///     start_address: 0x1000,
    ///     end_address: 0x1000,
    ///     start_idx: 0,
    ///     end_idx: 0,
    /// };
    /// assert_eq!(cfg.as_block_instr(&block).len(), 0);
    /// ```
    ///
    /// [`Shared backing instruction store`]: ControlFlowGraph::instructions
    #[inline]
    pub fn as_block_instr(&self, block: &BasicBlock) -> &[InstructionInfo] {
        &self.instructions[block.start_idx..block.end_idx]
    }

    /// Parses a branch target virtual address from an instruction operand string.
    ///
    /// Extracts hexadecimal (`0x...`) or decimal target offsets from operand strings,
    /// stripping punctuation and comment decorators common in disassembler outputs
    /// (e.g. `"#0x1004"` -> `Some(0x1004)`).
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use rbat::core::cfg::ControlFlowGraph;
    ///
    /// assert_eq!(ControlFlowGraph::parse_target_addr("0x401000"), Some(0x401000));
    /// assert_eq!(ControlFlowGraph::parse_target_addr("#0x2000"), Some(0x2000));
    /// assert_eq!(ControlFlowGraph::parse_target_addr("rax"), None);
    /// ```
    pub(crate) fn parse_target_addr(op_str: &str) -> Option<u64> {
        let trimmed = op_str.trim();
        if trimmed.is_empty() {
            return None;
        }

        let cleaned: String = trimmed
            .chars()
            .filter(|&c| c.is_alphanumeric() || c == 'x' || c == 'X' || c == '-' || c == '+')
            .collect();

        if cleaned.starts_with("0x") || cleaned.starts_with("0X") {
            u64::from_str_radix(&cleaned[2..], 16).ok()
        } else {
            cleaned.parse::<u64>().ok()
        }
    }

    /// Classifies a disassembled instruction mnemonic into its control-flow role.
    ///
    /// Convenience forwarding function for [`InstructionClass::classify`].
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use rbat::core::cfg::{ControlFlowGraph, InstructionClass};
    /// use rbat::core::parser::BinaryArch;
    ///
    /// assert_eq!(
    ///     ControlFlowGraph::classify_instr("jmp", &BinaryArch::X64),
    ///     InstructionClass::UnconditionalJump
    /// );
    /// assert_eq!(
    ///     ControlFlowGraph::classify_instr("ret", &BinaryArch::X64),
    ///     InstructionClass::Return
    /// );
    /// ```
    #[cfg_attr(not(feature = "backend-capstone"), allow(dead_code))]
    pub(crate) fn classify_instr(mnemonic: &str, arch: &BinaryArch) -> InstructionClass {
        InstructionClass::classify(mnemonic, arch)
    }
}

/// Represents a basic block: a straight-line sequence of execution with a single entry and exit.
///
/// A basic block is a fundamental unit of control-flow analysis. Execution enters only at the
/// first instruction (`start_address`) and leaves only at the final instruction (`end_address`)
/// without halting or branching except at the end.
///
/// Instructions within the block are indexed into the parent instruction array using the half-open
/// range `[start_idx..end_idx)`.
///
/// # Examples
///
/// ```rust
/// use rbat::core::cfg::BasicBlock;
///
/// let block = BasicBlock {
///     start_address: 0x1000,
///     end_address: 0x1008,
///     start_idx: 0,
///     end_idx: 3,
/// };
/// assert_eq!(block.instr_count(), 3);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BasicBlock {
    /// The start virtual memory address of the block.
    pub start_address: u64,
    /// The end virtual memory address of the block.
    pub end_address: u64,
    /// Start index (inclusive) into the parent instruction array.
    pub start_idx: usize,
    /// End index (exclusive) into the parent instruction array.
    pub end_idx: usize,
}

impl BasicBlock {
    /// Returns this block's instruction slice from the given backing store.
    ///
    /// Slices `source[self.start_idx..self.end_idx]`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rbat::core::cfg::BasicBlock;
    ///
    /// let block = BasicBlock {
    ///     start_address: 0x1000,
    ///     end_address: 0x1000,
    ///     start_idx: 0,
    ///     end_idx: 0,
    /// };
    /// assert!(block.as_instr(&[]).is_empty());
    /// ```
    #[inline]
    pub fn as_instr<'inon>(&self, source: &'inon [InstructionInfo]) -> &'inon [InstructionInfo] {
        &source[self.start_idx..self.end_idx]
    }

    /// Number of instructions in this block (`end_idx - start_idx`).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rbat::core::cfg::BasicBlock;
    ///
    /// let block = BasicBlock {
    ///     start_address: 0x1000,
    ///     end_address: 0x1004,
    ///     start_idx: 2,
    ///     end_idx: 5,
    /// };
    /// assert_eq!(block.instr_count(), 3);
    /// ```
    #[inline]
    pub fn instr_count(&self) -> usize {
        self.end_idx - self.start_idx
    }
}

/// Types of control flow edges connecting basic blocks in a [`ControlFlowGraph`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EdgeType {
    /// Sequential execution continuation to the next contiguous block.
    FallThrough,
    /// Taken branch path of a conditional jump instruction.
    ConditionalTrue,
    /// Not-taken fallthrough path of a conditional jump instruction.
    ConditionalFalse,
    /// Unconditional jump target path.
    Unconditional,
    /// Subroutine call target path.
    Call,
}

/// Categorizes machine instructions into functional control-flow roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum InstructionClass {
    /// Normal sequential instruction with no control-flow redirection.
    #[default]
    Normal,
    /// Conditional branching instruction (e.g. `je`, `jne`, `b.eq`).
    ConditionalJump,
    /// Unconditional branching instruction (e.g. `jmp`, `b`).
    UnconditionalJump,
    /// Subroutine call instruction (e.g. `call`, `bl`).
    Call,
    /// Subroutine return instruction (e.g. `ret`, `sysret`).
    Return,
}

impl InstructionClass {
    /// Classifies a disassembled instruction mnemonic into its control-flow role.
    ///
    /// Recognizes architecture-specific mnemonics for:
    /// - **x86 / x86-64**: `jmp`, `call`, `ret`/`sysret`/`iret`, and `j*` conditional branches.
    /// - **ARM / ARM64**: `b`, `bl`/`blx`, `ret`/`br`/`bx`, and `b.*`/`cbz`/`cbnz`/`tbz`/`tbnz` branches.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rbat::core::{
    ///   cfg::InstructionClass,
    ///   parser::BinaryArch,
    /// };
    ///
    /// assert_eq!(
    ///     InstructionClass::classify("je", &BinaryArch::X64),
    ///     InstructionClass::ConditionalJump
    /// );
    /// assert_eq!(
    ///     InstructionClass::classify("b.ne", &BinaryArch::Arm64),
    ///     InstructionClass::ConditionalJump
    /// );
    /// assert_eq!(
    ///     InstructionClass::classify("mov", &BinaryArch::X64),
    ///     InstructionClass::Normal
    /// );
    /// ```
    pub fn classify(mnemonic: &str, arch: &BinaryArch) -> Self {
        match arch {
            BinaryArch::X86 | BinaryArch::X64 => match mnemonic {
                "jmp" => Self::UnconditionalJump,
                "ret" | "retf" | "retn" | "iret" | "iretd" | "sysret" => Self::Return,
                "call" => Self::Call,
                m if m.starts_with('j') => Self::ConditionalJump,
                _ => Self::Normal,
            },
            BinaryArch::Arm | BinaryArch::Arm64 => match mnemonic {
                "b" => Self::UnconditionalJump,
                "br" | "bx" | "ret" => Self::Return,
                "bl" | "blx" => Self::Call,
                m if m.starts_with("b.")
                    || m.starts_with("cbz")
                    || m.starts_with("cbnz")
                    || m.starts_with("tbz")
                    || m.starts_with("tbnz") =>
                {
                    Self::ConditionalJump
                }
                _ => Self::Normal,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::disassembler::InstructionInfo;

    /// Helper to build an `InstructionInfo` with minimal boilerplate.
    fn insn_arch(address: u64, mnemonic: &str, op_str: &str, arch: &BinaryArch) -> InstructionInfo {
        let inst_class = InstructionClass::classify(mnemonic, arch);
        InstructionInfo {
            address,
            mnemonic: mnemonic.into(),
            op_str: op_str.into(),
            api_resolution: None,
            matched: smallvec::SmallVec::new(),
            inst_class,
        }
    }

    fn insn(address: u64, mnemonic: &str, op_str: &str) -> InstructionInfo {
        insn_arch(address, mnemonic, op_str, &BinaryArch::X64)
    }

    #[test]
    fn test_empty_instructions() {
        let cfg = ControlFlowGraph::new(Arc::from([]), &BinaryArch::X64);
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
        let cfg = ControlFlowGraph::new(instructions.into(), &BinaryArch::X64);

        assert_eq!(cfg.blocks.len(), 1);
        assert!(cfg.edges.is_empty());

        let block = &cfg.blocks[&0x1000];
        assert_eq!(block.start_address, 0x1000);
        assert_eq!(block.end_address, 0x1004);
        assert_eq!(block.instr_count(), 3);
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
        let cfg = ControlFlowGraph::new(instructions.into(), &BinaryArch::X64);

        // Three leaders: 0x1000 (entry), 0x1003 (fallthrough after je), 0x1004 (target of je)
        assert_eq!(cfg.blocks.len(), 3);
        assert!(cfg.blocks.contains_key(&0x1000));
        assert!(cfg.blocks.contains_key(&0x1003));
        assert!(cfg.blocks.contains_key(&0x1004));

        // Block 0x1000 should contain [cmp, je]
        assert_eq!(cfg.blocks[&0x1000].instr_count(), 2);

        // Block 0x1003 should contain [nop]
        assert_eq!(cfg.blocks[&0x1003].instr_count(), 1);

        // Block 0x1004 should contain [mov]
        assert_eq!(cfg.blocks[&0x1004].instr_count(), 1);

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
        let cfg = ControlFlowGraph::new(instructions.into(), &BinaryArch::X64);

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
        let cfg = ControlFlowGraph::new(instructions.into(), &BinaryArch::X64);

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
        let cfg = ControlFlowGraph::new(instructions.into(), &BinaryArch::X64);

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
        let cfg = ControlFlowGraph::new(instructions.into(), &BinaryArch::X64);

        // Block starting at 0x1002 ends with "nop" (Normal) and should fallthrough to 0x1003
        assert!(cfg.edges.contains(&(0x1002, 0x1003, EdgeType::FallThrough)));
    }

    #[test]
    fn test_jump_to_nonexistent_target() {
        // If a jump targets an address not present in the instruction stream,
        // no edge should be emitted for that target.
        let instructions = vec![insn(0x1000, "jmp", "0x9999"), insn(0x1002, "nop", "")];
        let cfg = ControlFlowGraph::new(instructions.into(), &BinaryArch::X64);

        let edges_to_9999: Vec<_> = cfg
            .edges
            .iter()
            .filter(|(_, dst, _)| *dst == 0x9999)
            .collect();
        assert!(edges_to_9999.is_empty());
    }

    #[test]
    fn test_invalid_jump_target_between_valid_leaders() {
        // Jump targets 0x1001 which is not an instruction boundary between 0x1000 and 0x1002.
        // It must NOT swallow the block at 0x1002.
        let instructions = vec![
            insn(0x1000, "jmp", "0x1001"),
            insn(0x1002, "nop", ""),
            insn(0x1003, "ret", ""),
        ];
        let cfg = ControlFlowGraph::new(instructions.into(), &BinaryArch::X64);

        // Leaders must be 0x1000 and 0x1002 (0x1001 is filtered out)
        assert_eq!(cfg.blocks.len(), 2);
        assert!(cfg.blocks.contains_key(&0x1000));
        assert!(cfg.blocks.contains_key(&0x1002));
        assert_eq!(cfg.blocks[&0x1000].instr_count(), 1);
        assert_eq!(cfg.blocks[&0x1002].instr_count(), 2);
    }

    #[test]
    fn test_to_dot_output() {
        let instructions = vec![insn(0x1000, "nop", ""), insn(0x1001, "jmp", "0x1000")];
        let cfg = ControlFlowGraph::new(instructions.into(), &BinaryArch::X64);
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
        let cfg = ControlFlowGraph::new(instructions.into(), &BinaryArch::X64);
        let graph = cfg.to_petgraph();

        // The petgraph should have the same number of nodes as blocks
        assert_eq!(graph.node_count(), cfg.blocks.len());

        // The petgraph should have the same number of edges
        assert_eq!(graph.edge_count(), cfg.edges.len());
    }

    #[test]
    fn test_arm64_conditional_branch() {
        let arch = BinaryArch::Arm64;
        let instructions = vec![
            insn_arch(0x400, "cmp", "w0, #0", &arch),
            insn_arch(0x404, "b.eq", "0x40c", &arch),
            insn_arch(0x408, "mov", "w0, #1", &arch),
            insn_arch(0x40c, "ret", "", &arch),
        ];
        let cfg = ControlFlowGraph::new(instructions.into(), &arch);

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
        let cfg = ControlFlowGraph::new(instructions.into(), &BinaryArch::X64);

        assert_eq!(cfg.blocks.len(), 1);
        assert!(cfg.edges.is_empty());

        let block = &cfg.blocks[&0x1000];
        assert_eq!(block.start_address, 0x1000);
        assert_eq!(block.end_address, 0x1000);
        assert_eq!(block.instr_count(), 1);
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
        let cfg = ControlFlowGraph::new(instructions.into(), &BinaryArch::X64);

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
