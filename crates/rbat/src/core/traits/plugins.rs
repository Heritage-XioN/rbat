//! This module defines the common interfaces used for executing heuristic plugins.

use crate::core::types::{
    analysis::{AnalysisContext, AnalysisProgress},
    result::RbatResult,
};

/// Interface for implementing custom static binary analysis heuristics plugins.
/// All plugins run concurrently across the binary context in a background thread pool.
pub(crate) trait HeuristicPlugin: Send + Sync {
    /// Runs the heuristic logic using the provided analysis context.
    fn run<'buf, 'ctx>(
        &self,
        ctx: &AnalysisContext<'buf, 'ctx>,
    ) -> RbatResult<AnalysisProgress<'buf>>;
}
