//! # RBAT Prelude
//!
//! Convenient re-exports of common types and traits for binary analysis.

pub use crate::core::{
    analyzer::Analyzer,
    cfg::{BasicBlock, ControlFlowGraph, Function},
    disassembler::{DisassemblerBackend, InstructionInfo},
    eval::{CapaCharacteristic, Rule, RuleScope},
    features::{BlockScopeFeatures, FeatureSet, FileScopeFeatures, FunctionScopeFeatures},
    flirt::FlirtMatcher,
    needle::NeedleIndex,
    scoring::{
        classifier::{SeverityClass, SeverityClassifier},
        risk::{FindingCounts, RiskAssessment},
    },
    traits::Disassembler,
    types::{
        analysis::{AnalysisProgress, AnalysisResult, BinaryHashes, BinaryMetadata, SectionRange},
        result::{RbatError, RbatResult},
    },
};
