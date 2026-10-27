//! # Static Analysis and Threat Scoring Core Engine
//!
//! Provides the end-to-end static binary analysis, instruction disassembly,
//! behavioral capability matching, and threat scoring pipeline for RBAT.
//!
//! ## Architectural Overview
//!
//! The static analysis engine operates in five sequential and concurrent phases:
//!
//! 1. **Binary Ingestion & Header Parsing** ([`parser`]):
//!    Parses executable headers (ELF, PE, Mach-O), validates binary format, identifies the target
//!    CPU architecture, extracts text section bytes, and resolves Import Address Table (IAT) symbols.
//!
//! 2. **Instruction Disassembly & CFG Reconstruction** ([`disassembler`], [`mod@cfg`]):
//!    Performs linear instruction disassembly across executable text sections using runtime-selected
//!    engines ([`disassembler::DisassemblerBackend`]: Capstone, `iced-x86`, or custom implementations).
//!    Reconstructs basic blocks, control flow edges, branch targets, call sites, and recovered function
//!    subgraphs into a directed [`ControlFlowGraph`].
//!
//! 3. **Concurrent Heuristic Execution** (`plugins`, `heuristics`, [`flirt`], [`yarahandler`]):
//!    Executes modular analysis plugins in parallel over a Rayon work-stealing thread pool:
//!    - Cryptographic and fuzzy hashes (MD5, SHA-1, SHA-256, SSDEEP, TLSH) via [`plugins::MetadataPlugin`].
//!    - Section-level Shannon entropy calculations via `plugins::EntropyPlugin`.
//!    - Embedded YARA suspicious string and packer signature scans via [`yarahandler`].
//!    - Fast library function identification via [`flirt::FlirtMatcher`].
//!    - Code cave discovery (NOP sleds, NULL blocks, INT3 padding) via `heuristics`.
//!
//! 4. **Capability Rule Matching** ([`rule`], [`needle`], [`features`]):
//!    Extracts behavioral and structural features partitioned by scope (file, function, basic block,
//!    instruction) into a unified [`FeatureSet`].
//!    Queries rule trees against pre-built Aho-Corasick automata in [`needle::NeedleIndex`] to evaluate
//!    capa-compatible YAML and JSON capability rules according to their declared static scopes.
//!
//! 5. **Risk Assessment & Scoring** ([`scoring`]):
//!    Maps matched capabilities into MITRE ATT&CK and MBC tactics. Uses a Bayesian noisy-OR
//!    probabilistic model in [`scoring::risk::RiskAssessment`] calibrated by [`scoring::classifier::SeverityClassifier`]
//!    to generate a 0–100 threat score and finding severity breakdown.
//!
//! ## Concurrency and Thread Safety
//!
//! The pipeline is optimized for concurrent execution:
//! - All long-lived indices ([`needle::NeedleIndex`], [`flirt::FlirtMatcher`], rule vectors) are compiled once
//!   and wrapped in thread-safe [`Arc`] handles.
//! - Parallel heuristic execution borrows from read-only buffers without data copying or mutex contention.
//! - Errors in background worker threads trigger atomic cancellation flags and safely preserve the root cause error.
//!
//! ## Disassembler Backends & Feature Flags
//!
//! Rather than forcing compile-time mutual exclusivity, `rbat` supports compiling multiple disassembler backends
//! simultaneously and selecting the active engine at runtime via [`disassembler::DisassemblerBackend`]:
//! - `backend-capstone`: Uses the native Capstone C library disassembler. Supports
//!   x86, x64, ARM (32-bit), and ARM64 (AArch64) architectures.
//! - `backend-iced`: Uses the pure-Rust `iced-x86` disassembler. Provides high throughput and zero
//!   C-dependency builds for x86 and x64 binaries.
//!
//! ## Examples
//!
//! ```rust,no_run
//! use rbat::core::analyzer::Analyzer;
//!
//! # fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let buffer = std::fs::read("path/to/binary")?;
//! let analyzer = Analyzer::builder().build();
//!
//! let (analysis, assessment) = analyzer.batch(&buffer)?;
//! println!("Binary type: {}", analysis.metadata.binary_type);
//! println!("Threat score: {}/100 ({})", assessment.score, assessment.severity);
//! # Ok(())
//! # }
//! ```
//!
//! [`FeatureSet`]: features::FeatureSet
//! [`ControlFlowGraph`]: cfg::ControlFlowGraph
//! [`Arc`]: std::sync::Arc

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
pub mod traits;
pub mod types;
pub mod yarahandler;
