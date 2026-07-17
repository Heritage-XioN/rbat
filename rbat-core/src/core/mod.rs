//! # RBAT Core Module
//!
//! This module aggregates and re-exports all submodules, configurations,
//! error definitions, plugins, traits, and types forming the static analysis library.

pub mod analyzer;
pub mod cfg;
pub mod cli;
mod disassembler;
pub mod error;
pub mod features;
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
    disassembler::{BinaryArch, BinaryOS, Factory},
    error::RbatError,
    features::FeatureSet,
    heuristics::{disassemble_section, packer_sig_check, string_check},
    rule::{Rule, RuleCondition},
    types::{
        AnalysisContext, AnalysisProgress, AnalysisResult, Asset, BasicBlock, BinaryMetadata,
        Confidence, EdgeType, FeatureCondition, Finding, InstructionInfo, MapValue, RiskAssessment,
        RuleMeta, SectionRange, YaraMatches,
    },
};

pub type Result<T> = core::result::Result<T, RbatError>;
