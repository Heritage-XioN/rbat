//! # RBAT Core Module
//!
//! This module aggregates and re-exports all submodules, configurations,
//! error definitions, plugins, traits, and types forming the static analysis library.

pub mod analyzer;
pub mod cfg;
pub mod disassembler;
pub mod features;
pub mod flirt;
pub(crate) mod heuristics;
pub mod needle;
pub mod parser;
pub(crate) mod plugins;
pub mod rule;
pub mod scoring;
pub(crate) mod traits;
pub mod types;
pub mod yarahandler;
