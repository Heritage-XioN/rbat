pub mod analyzer;
pub mod cli;
mod disassembler;
pub mod error;
pub mod heuristics;
pub mod parser;
pub mod plugins;
pub mod traits;
pub mod tui;
pub mod types;
pub mod yarahandler;

pub use crate::core::{
    disassembler::{BinaryArch, BinaryOS, Factory},
    error::RbatError,
    heuristics::{disassemble_section, packer_sig_check, string_check},
    types::{
        AnalysisContext, AnalysisProgress, AnalysisResult, Asset, BinaryMetadata, Confidence,
        Finding, MapValue, RiskAssessment, SectionRange, YaraMatches,
    },
};

pub type Result<T> = core::result::Result<T, RbatError>;
