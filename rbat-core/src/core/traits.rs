//! # Common Abstractions and Traits
//!
//! This module defines the common interfaces used for disassembling binaries
//! and executing heuristic plugins.

use crate::core::{AnalysisContext, AnalysisProgress};

use super::Result;
pub use capstone::prelude::*;

/// Interface for configuring and instantiating the Capstone disassembly engine.
pub trait Disassembler {
    /// Configures and builds a Capstone disassembler instance based on the binary's CPU architecture and target OS.
    fn disassemble(&self) -> Result<Capstone>;
}

/// Interface for implementing custom static binary analysis heuristics plugins.
/// All plugins run concurrently across the binary context in a background thread pool.
pub trait HeuristicPlugin: Send + Sync {
    /// Returns the static, unique string identifier of the plugin.
    fn name(&self) -> &'static str;

    /// Runs the static analysis heuristic on the provided [`AnalysisContext`] and returns the analysis progress.
    fn run(&self, ctx: &AnalysisContext) -> Result<AnalysisProgress>;
}
