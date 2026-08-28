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
    /// The set of instructions belonging to this block.
    pub instructions: Vec<InstructionInfo>,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstructionClass {
    /// Normal sequential instruction.
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
