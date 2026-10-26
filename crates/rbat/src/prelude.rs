//! # RBAT Prelude
//!
//! Convenient re-exports of common types and traits for binary analysis.

pub use crate::core::{
    analyzer::Analyzer,
    cfg::{BasicBlock, ControlFlowGraph, Function},
    disassembler::{DisassemblerBackend, InstructionInfo},
    features::{BlockScopeFeatures, FeatureSet, FunctionScopeFeatures, GlobalScopeFeatures},
    flirt::FlirtMatcher,
    needle::NeedleIndex,
    rule::{CapaCharacteristic, Rule, RuleScope},
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
