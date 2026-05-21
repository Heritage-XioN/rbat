use crate::core::{AnalysisContext, AnalysisProgress};

use super::Result;
pub use capstone::prelude::*;

pub trait Disassembler {
    /// capstone disassembly function.
    /// returns a Capstone instance based on the binary's OS type.
    fn disassemble(&self) -> Result<Capstone>;
}

pub trait HeuristicPlugin: Send + Sync {
    fn name(&self) -> &'static str;
    fn run(&self, ctx: &AnalysisContext) -> Result<AnalysisProgress>;
}
