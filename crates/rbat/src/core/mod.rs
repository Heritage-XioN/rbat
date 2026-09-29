//! # RBAT Core Module
//!
//! This module aggregates and re-exports all submodules, configurations,
//! error definitions, plugins, traits, and types forming the static analysis library.

pub mod analyzer;
pub mod cfg;
pub mod disassembler;
pub mod features;
pub mod flirt;
pub mod heuristics;
pub mod parser;
pub mod plugins;
pub mod rule;
pub mod scoring;
pub mod traits;
pub mod types;
pub mod yarahandler;
