//! # Analysis Data Types
//!
//! This module defines the core data structures, enums, and utility structures
//! used throughout the binary analysis pipeline, reporting, and scoring engines.
//!
//! The module is split into focused submodules (each re-exported here)

pub mod analysis;
pub mod needle;
pub mod result;

pub use analysis::*;
pub use needle::*;
pub use result::*;
