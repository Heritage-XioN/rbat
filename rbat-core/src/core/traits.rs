//! # Common Abstractions and Traits
//!
//! This module defines the common interfaces used for disassembling binaries
//! and executing heuristic plugins.

use crate::core::disassembler::InstructionInfo;
use crate::core::types::IatMap;
use crate::core::{AnalysisContext, AnalysisProgress};

use super::Result;

/// Interface for configuring and instantiating the Capstone disassembly engine.
pub trait Disassembler {
    /// Configures, builds the disassembler, and returns parsed instructions.
    fn disassemble(
        &self,
        text_bytes: &[u8],
        entry_addr: u64,
        iat_map: &IatMap,
    ) -> Result<Vec<InstructionInfo>>;
}

/// Interface for implementing custom static binary analysis heuristics plugins.
/// All plugins run concurrently across the binary context in a background thread pool.
pub trait HeuristicPlugin: Send + Sync {
    /// Returns the static, unique string identifier of the plugin.
    fn name(&self) -> &'static str;

    /// Runs the heuristic logic using the provided analysis context.
    fn run<'buf, 'ctx>(&self, ctx: &AnalysisContext<'buf, 'ctx>) -> Result<AnalysisProgress<'buf>>;
}
