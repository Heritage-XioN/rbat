//! # Common Abstractions and Traits
//!
//! This module defines the common interfaces used for disassembling binaries
//! and executing heuristic plugins.

use crate::core::{
    disassembler::InstructionInfo,
    parser::IatMap,
    types::{
        analysis::{AnalysisContext, AnalysisProgress},
        result::RbatResult,
    },
};

/// Interface for disassembling raw machine code into structured instruction sequences.
///
/// Implementations translate architecture-specific bytes into [`InstructionInfo`] vectors,
/// resolving IAT thunk addresses to their imported API names along the way.
pub(crate) trait Disassembler {
    /// Decodes the provided text bytes starting at `entry_addr` and returns parsed instructions.
    fn disassemble(
        &self,
        text_bytes: &[u8],
        entry_addr: u64,
        iat_map: &IatMap,
    ) -> RbatResult<Vec<InstructionInfo>>;
}

/// Interface for implementing custom static binary analysis heuristics plugins.
/// All plugins run concurrently across the binary context in a background thread pool.
pub(crate) trait HeuristicPlugin: Send + Sync {
    /// Runs the heuristic logic using the provided analysis context.
    fn run<'buf, 'ctx>(
        &self,
        ctx: &AnalysisContext<'buf, 'ctx>,
    ) -> RbatResult<AnalysisProgress<'buf>>;
}
