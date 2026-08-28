//! # RBAT Core Module
//!
//! This module aggregates and re-exports all submodules, configurations,
//! error definitions, plugins, traits, and types forming the static analysis library.

pub mod analyzer;
pub mod cfg;
pub mod cli;
pub mod disassembler;
pub mod error;
pub mod features;
pub mod flirt;
pub mod heuristics;
pub mod parser;
pub mod plugins;
pub mod rule;
pub mod traits;
pub mod tui;
pub mod types;
pub mod yarahandler;

pub use crate::core::{
    cfg::ControlFlowGraph,
    error::RbatError,
    features::FeatureSet,
    flirt::FlirtMatcher,
    heuristics::{disassemble_section, packer_sig_check, string_check},
    rule::Rule,
    types::{
        AnalysisContext, AnalysisProgress, AnalysisResult, Asset, BasicBlock, BinaryArch,
        BinaryHashes, BinaryMetadata, BinaryOS, CategoryScore, EdgeType, Finding, FindingCounts,
        IatMap, InstructionClass, NeedleIndex, ParsedBinaryContext, RiskAssessment, RuleCondition,
        RuleInner, RuleMeta, RuleTag, SectionRange, SeverityClass, YaraMatches,
    },
};

/// A specialized Result type for rbat core operations.
pub type Result<T> = core::result::Result<T, RbatError>;
