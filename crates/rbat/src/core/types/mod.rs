//! # Analysis Data Types and Error Primitives
//!
//! Foundational data transfer objects, progress streaming events, section boundary
//! descriptors, and error types forming the core communication layer of RBAT.
//!
//! ## Submodules
//!
//! - [`analysis`]: Binary metadata, cryptographic digests, section maps, code caves, and accumulated results.
//! - [`result`]: Strongly-typed error handling ([`RbatError`]) and specialized results ([`RbatResult`]).
//!
//! ## Core Types Summary
//!
//! - [`AnalysisProgress`]: Streaming event emitted when a heuristic plugin finishes.
//! - [`AnalysisResult`]: Aggregated findings from all concurrent analysis plugins.
//! - [`BinaryMetadata`]: Normalized binary architecture, format, and entry point.
//! - [`BinaryHashes`]: Cryptographic (MD5, SHA-1, SHA-256) and triage fuzzy hashes.
//! - [`SectionRange`]: Fast file-offset interval mapper for binary sections.
//! - [`CodeCaves`]: Strongly-typed findings for NOP sleds, NULL padding, INT3 traps.
//! - [`RbatError`]: Unified `verbObjectError` error enum covering all pipeline failures.
//! - [`RbatResult`]: Standard `Result<T, RbatError>` alias.
//!
//! ## Examples
//!
//! Constructing basic analysis data types:
//!
//! ```rust
//! use rbat::core::types::{BinaryHashes, CodeCaves, RbatResult};
//!
//! fn check_binary_health(caves: &CodeCaves, hashes: &BinaryHashes) -> RbatResult<bool> {
//!     let is_clean = caves.is_empty() && !hashes.sha256.is_empty();
//!     Ok(is_clean)
//! }
//!
//! let caves = CodeCaves::default();
//! let hashes = BinaryHashes::default();
//! assert_eq!(check_binary_health(&caves, &hashes).unwrap(), false);
//! ```

pub mod analysis;
pub mod result;

pub use analysis::{
    AnalysisProgress, AnalysisResult, BinaryHashes, BinaryMetadata, CodeCaves, SectionRange,
};
pub use result::{RbatError, RbatResult};
