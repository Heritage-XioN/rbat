//! # RBAT
//!
//! `rbat` is the core library for the Rust Binary Analysis Tool (RBAT).
//! It provides platform-independent interfaces and high-performance heuristics for static
//! binary analysis of ELF, PE, and Mach-O files.
//!
//! ## Key Features
//! - **Multi-Format Parsing**: Transparently parses ELF, PE, and Mach-O formats utilizing the `object` crate.
//! - **Parallel Heuristic Evaluation**: Runs static analysis modules concurrently using `rayon` thread pools.
//! - **High-Performance Memory Scanning**: Uses compiled YARA rules for memory scans, cached section mappings, and zero disk I/O.
//! - **Static Disassembly & Instruction Analysis**: Disassembly via `capstone` or `iced` to detect NOP sleds, zero-entropy padding, and anti-analysis instructions without early exit evasions.
//! - **Scoring & Classification**: Automated risk-score classification (Safe, Suspicious, Malicious) using noisy-OR probabilistic combination.
//!
//! ## Architectural Overview
//! The analysis pipeline consists of three main stages:
//! 1. **Parsing and Range Caching**: The binary buffer is read and parsed into a `object::File`. Section boundaries are precomputed and cached in `SectionRange` elements for $O(1)$ virtual memory offset mapping.
//! 2. **Context and Plugin Dispatch**: An `AnalysisContext` borrows all read-only binary structures. A registry of `HeuristicPlugin` trait objects executes concurrently via a Rayon thread scope.
//! 3. **Aggregation and Assessment**: Results are aggregated into an `AnalysisResult` and evaluated by a scoring engine to produce a `RiskAssessment` containing findings and recommendations.
//!
//! ## Code Example
//!
//! The following example demonstrates how to perform a batch static analysis on a binary using the crate's entry points:
//!
//! ```rust,no_run
//! use std::path::Path;
//! use rbat::core::analyzer::Analyzer;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let binary_path = Path::new("path/to/my_binary");
//!     let buffer = std::fs::read(binary_path)?;
//!
//!     // Build an analyzer with default embedded rules and classifier
//!     let analyzer = Analyzer::builder().build()?;
//!
//!     // Perform batch analysis to retrieve findings and risk score
//!     let (result, assessment) = analyzer.batch(&buffer)?;
//!
//!     println!("Binary Type: {}", result.metadata.binary_type);
//!     println!("Calculated Risk Score: {}", assessment.score);
//!     println!("Threat Severity: {}", assessment.severity);
//!
//!     for finding in &assessment.findings {
//!         println!("[-] Indicator: {} - {}", finding.indicator, finding.description);
//!     }
//!
//!     Ok(())
//! }
//! ```

pub mod core;
pub mod prelude;
pub mod utils;
