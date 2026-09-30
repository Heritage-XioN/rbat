//! # RBAT Prelude
//!
//! Convenient re-exports of common types and traits for binary analysis.

pub use crate::core::{
    analyzer::Analyzer,
    cfg::ControlFlowGraph,
    features::FeatureSet,
    flirt::FlirtMatcher,
    rule::Rule,
    scoring::SeverityClassifier,
    types::{
        AnalysisProgress, AnalysisResult, BinaryHashes, BinaryMetadata, RbatError, RbatResult,
        SectionRange,
    },
};
