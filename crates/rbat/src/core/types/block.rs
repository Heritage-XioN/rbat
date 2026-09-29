//! Control-flow graph primitive types.

use crate::core::disassembler::InstructionInfo;
use serde::{Deserialize, Serialize};

/// Represents a basic block: a straight-line sequence of execution with a single entry and exit.
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
    #[inline]
    pub fn instructions<'inon>(
        &self,
        source: &'inon [InstructionInfo],
    ) -> &'inon [InstructionInfo] {
        &source[self.start_idx..self.end_idx]
    }

    /// Number of instructions in this block.
    #[inline]
    pub fn instruction_count(&self) -> usize {
        self.end_idx - self.start_idx
    }
}

/// Types of control flow edges connecting basic blocks.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EdgeType {
    /// Sequential execution continuation.
    FallThrough,
    /// Taken branch of a conditional jump.
    ConditionalTrue,
    /// Not-taken branch of a conditional jump.
    ConditionalFalse,
    /// Unconditional jump target.
    Unconditional,
    /// Subroutine call target.
    Call,
}

/// Categorizes an instruction into control flow classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum InstructionClass {
    /// Normal sequential instruction.
    #[default]
    Normal,
    /// Conditional branching instruction.
    ConditionalJump,
    /// Unconditional branching instruction.
    UnconditionalJump,
    /// Subroutine call instruction.
    Call,
    /// Subroutine return instruction.
    Return,
}
