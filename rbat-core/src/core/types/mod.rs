//! # Analysis Data Types
//!
//! This module defines the core data structures, enums, and utility structures
//! used throughout the binary analysis pipeline, reporting, and scoring engines.
//!
//! The module is split into focused submodules (each re-exported here)

pub mod analysis;
pub mod binary;
pub mod block;
pub mod needle;
pub mod risk;
pub mod rule;
pub mod rule_condition;

pub use analysis::*;
pub use binary::*;
pub use block::*;
pub use needle::*;
pub use risk::*;
pub use rule::*;
pub use rule_condition::*;
