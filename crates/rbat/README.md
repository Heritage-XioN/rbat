# rbat

[![Crates.io Version](https://img.shields.io/crates/v/rbat?style=for-the-badge&logo=rust&color=orange&label=version)](https://crates.io/crates/rbat)
[![Crates.io Downloads](https://img.shields.io/crates/d/rbat?style=for-the-badge&color=blue&label=downloads)](https://crates.io/crates/rbat)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=for-the-badge)](https://opensource.org/licenses/Apache-2.0)
[![Build Status](https://img.shields.io/github/actions/workflow/status/Heritage-XioN/rbat/ci-rust.yml?style=for-the-badge&label=build)](https://github.com/Heritage-XioN/rbat/actions)
[![Rust MSRV](https://img.shields.io/badge/rustc-1.85+-orange.svg?style=for-the-badge&logo=rust)](https://blog.rust-lang.org/)

**rbat** is a high-performance, modular static binary analysis and threat detection engine written in pure Rust. It provides programmatic APIs to parse executable headers across multiple operating systems, reconstruct Control Flow Graphs (CFG), perform multi-backend machine code disassembly, match Fast Library Identification and Recognition Technology (FLIRT) compiler signatures, evaluate Mandiant Capa behavioral rules across four execution scopes, and aggregate findings into calibrated Bayesian threat scores mapped to MITRE ATT&CK and MBC.

This crate serves as the foundational analysis library For the CLI/TUI binary crate `rbat-cli`.

---

## Capabilities

* **Multi-Format Executable Ingestion**: Native parsing for ELF (Linux), PE/COFF (Windows), and Mach-O (macOS) binaries in both 32-bit and 64-bit architectures using the `object` crate.
* **Pluggable Multi-Backend Disassembly**:
  * **Iced Backend**: High-throughput pure-Rust disassembly and instruction decoding for x86 and x86_64 architectures using `iced-x86`.
  * **Capstone Backend**: Multi-architecture disassembly supporting x86, x64, ARM, AArch64 (ARM64), MIPS, and PowerPC via `capstone-rs`.
  * **Custom Backends**: Trait-based architecture extension via the `Disassembler` trait and `DisassemblerBackend::custom`.
* **Control Flow Graph (CFG) & Function Recovery**:
  * Linear sweep and recursive descent basic block discovery.
  * Explicit edge classification (`BranchTrue`, `BranchFalse`, `Jump`, `Call`).
  * Intra-procedural function clustering, McCabe cyclomatic complexity calculation, and loop/recursion detection.
  * Graph export to Graphviz DOT format (`ControlFlowGraph::to_dot`) and Petgraph representations (`ControlFlowGraph::to_petgraph`).
* **Extensible Rayon-Scoped Heuristic Plugin Engine**:
  * Thread-safe plugin architecture governed by the `HeuristicPlugin` trait abstraction (`Send + Sync`).
  * Concurrent plugin dispatch executed within a Rayon work-stealing thread scope (`rayon::scope`) over a zero-copy shared `AnalysisContext`.
  * Fully extensible: any custom struct implementing the heuristic plugin trait can be introduced to execute specialized static analysis logic.
  * Built-in concurrent plugins include:
    * Multi-algorithm cryptographic hashing (MD5, SHA-1, SHA-256) and similarity hashing (SSDEEP fuzzy hash, TLSH trend locality hash).
    * Shannon entropy calculation per section with automated packed/encrypted payload detection.
    * Static string extraction with ASCII and UTF-16LE decoding alongside embedded YARA pattern matching.
    * Dynamic Import Address Table (IAT) and Export Address Table (EAT) extraction with MSVC and Itanium C++ symbol demangling.
    * Compiler runtime identification via Fast Library Identification and Recognition Technology (FLIRT) signatures (`.sig` / `.pat`).
    * Code cave discovery (NOP sleds, null padding, and trap padding analysis).
  * Atomic cancellation (`cancel_flag`) and thread-safe error capture for instantaneous fail-fast error handling.
* **Declarative Behavioral Rule Engine (Capa Compatible)**:
  * Full support for Mandiant Capa YAML rules and strict JSON schemas.
  * Boolean condition trees supporting `and`, `or`, `not`, threshold counts, range matches, and regular expressions.
  * Scope-aware matching across four distinct execution scopes: `File`, `Function`, `BasicBlock`, and `Instruction`.
* **Probabilistic Bayesian Risk Scoring**:
  * Findings combined using a Bayesian Noisy-OR formulation to prevent linear score inflation while compounding corroborating hostile indicators.
  * Dynamic severity tiering (`Informational`, `Capability`, `Low`, `Medium`, `High`, `Critical`).
  * Tunable TOML override support (`capa-overrides.toml`) to recalibrate dual-use indicators (e.g., anti-debugging or timing checks).
  * Direct taxonomy alignment with MITRE ATT&CK Enterprise Tactics & Techniques and Malware Behavior Catalog (MBC) Objectives.
* **Dual Execution Modes**:
  * **Batch Analysis**: Synchronous analysis returning comprehensive structured results and risk scores.
  * **Streaming Analysis**: Non-blocking analysis delivering real-time `AnalysisProgress` callbacks across pipeline phases.

---

## Analysis Workflow & Architecture

The static analysis pipeline coordinates parsing, decoding, graph reconstruction, concurrent heuristic scanning, scope-based feature extraction, rule evaluation, and probabilistic scoring:

```text
Raw Binary Buffer &[u8]
      │
      ├───► Parser & Validation (object)
      │        ├── Format Identification (ELF / PE / Mach-O)
      │        ├── Architecture Detection (x86 / x64 / ARM / ARM64)
      │        └── Section Ranges & Entry Point Resolution
      │
      ├───► Disassembler Backend (Iced / Capstone / Custom)
      │        └── InstructionInfo Stream (Normalized Intel Syntax)
      │                 │
      │                 ├───► Control Flow Graph (CFG) Reconstruction
      │                 │        ├── Basic Block Segmentation
      │                 │        ├── Edge Categorization (Branch / Jump / Call)
      │                 │        └── Intra-Procedural Function Recovery
      │                 │
      │                 └───► FLIRT Compiler Signature Matcher
      │                          └── Library Range Compaction (O(log K) Filtering)
      │
      ├───► Rayon-Scoped Heuristic Plugin Engine (Concurrent Execution)
      │        ├── HashingPlugin (MD5, SHA-1, SHA-256, SSDEEP, TLSH)
      │        ├── EntropyPlugin (Shannon Entropy per Section)
      │        ├── StringCheckPlugin & PackerSigCheckPlugin (YARA Signatures)
      │        ├── ImportsPlugin & ExportsPlugin (MSVC / Itanium Demangling)
      │        ├── MetadataPlugin (Header & Timestamp Analysis)
      │        ├── CfgPlugin & LibraryFunctionsPlugin
      │        └── Custom HeuristicPlugin Implementations
      │
      ├───► FeatureSet Partitioning by Scope
      │        ├── FileScopeFeatures (Whole-binary hashes, format, imports, strings)
      │        ├── FunctionScopeFeatures (Subgraphs, cyclomatic complexity, loops)
      │        ├── BlockScopeFeatures (Basic block instruction slices, tight loops)
      │        └── InstructionScope (Mnemonics, operands, immediates, API calls)
      │
      ├───► NeedleIndex Literal Anchor Pruning (Aho-Corasick Multi-Pattern Automaton)
      │        └── Fast streaming sweep sets presence bitmasks, pruning non-matching rule ASTs
      │
      ├───► Rule Evaluation Engine (Capa YAML & JSON)
      │        ├── Pass 1: Parallel Independent Rules (Rayon Workers)
      │        └── Pass 2..N: Fixpoint Iteration for Dependent Rules (match:)
      │
      └───► Risk Assessment & Severity Classification
               ├── SeverityClassifier & capa-overrides.toml
               ├── Bayesian Noisy-OR Threat Score (0 - 100)
               └── MITRE ATT&CK & MBC Taxonomy Mapping
```

### Pipeline Stages

1. **Ingestion & Validation**: The input buffer is validated using the `object` crate. Executable sections, header flags, entry point virtual addresses, and segment mappings are extracted into a `SectionRange` table.
2. **Disassembly**: Machine code bytes from executable sections are fed to the active `DisassemblerBackend`, generating an `InstructionInfo` stream with normalized Intel-syntax mnemonics and resolved operand targets.
3. **Control Flow Analysis**: The instruction sequence is segmented into basic blocks. Branch targets and fallthrough edges are resolved, and basic blocks are grouped into intra-procedural `Function` subgraphs.
4. **Concurrent Heuristic Scanning (Rayon Scoped Plugins)**: Modular analysis plugins run concurrently inside a scoped Rayon pool (`rayon::scope`) against a shared, zero-copy `AnalysisContext`. Any struct implementing the `HeuristicPlugin` trait can be executed to emit real-time progress events. An atomic cancellation flag halts remaining tasks immediately if any fatal error occurs.
5. **Scope-Tiered Feature Extraction**: Raw plugin findings and CFG topologies are organized into a `FeatureSet`. FLIRT-identified runtime library ranges are compacted into sorted non-overlapping intervals, allowing $O(\log K)$ exclusion of compiler boilerplate from capability matches.
6. **Literal Anchor Pruning & Multi-Tier Rule Evaluation**: The `NeedleIndex` multi-pattern automaton performs a fast streaming scan of the binary to record literal string and API anchor occurrences. Rules whose literal anchors are absent are pruned immediately without traversing ASTs. Surviving independent rules are evaluated concurrently in Pass 1 via Rayon, while dependent rules (`match:` conditions) are resolved in Pass 2..N via fixpoint iteration.
7. **Threat Scoring & Taxonomy Mapping**: Matched rules are categorized by `SeverityClassifier`, and a probabilistic Noisy-OR calculation produces a normalized 0-100 threat score alongside MITRE ATT&CK and MBC annotations.

### Extensible Rayon Scoped Plugin Architecture

The heuristic engine is designed for zero-copy concurrency and modular extensibility:

* **Scoped Concurrency (`rayon::scope`)**: All registered plugins are spawned within a Rayon scope, allowing them to borrow non-static references directly from the binary buffer and analysis context (`AnalysisContext<'buf, 'ctx>`) without heap cloning or lifetime extension.
* **Trait Abstraction (`HeuristicPlugin`)**: The engine defines the `HeuristicPlugin` trait (`Send + Sync`). Any custom struct implementing this interface can be passed into the engine to execute arbitrary specialized static analysis logic.
* **Non-Blocking Progress Streaming**: As each plugin completes, it publishes its findings as an `AnalysisProgress` variant (`BinaryMetadata`, `Hashes`, `Entropy`, `Disassembly`, `CFG`, `Strings`, `Imports`, `Exports`, `LibraryFunctions`).
* **Short-Circuit Error Propagation**: If a plugin encounters an unrecoverable failure (such as corrupt executable headers or malformed instruction streams), the engine records the initial root-cause error and flips an atomic cancellation flag (`cancel_flag`), causing active sibling threads to abort cleanly without completing redundant work.

---

## Feature Flags & Build Configurations

The crate exposes feature flags to control disassembler backends:

| Feature Flag | Default | Description |
| :--- | :--- | :--- |
| `backend-iced` | Yes | High-throughput pure-Rust x86 and x86_64 disassembler via `iced-x86`. |
| `backend-capstone` | Yes | Multi-architecture disassembler (x86, x64, ARM, ARM64, MIPS, PPC) via Capstone C-FFI. |

Both backends can be enabled simultaneously. Disassembly selection is handled at runtime via enum dispatch through `DisassemblerBackend`:

* `DisassemblerBackend::default()`: Automatically selects the fastest available backend (prefers `Iced` for x86/x64, falls back to `Capstone`).
* `DisassemblerBackend::iced()`: Forces pure-Rust x86/x64 decoding.
* `DisassemblerBackend::capstone()`: Forces Capstone multi-architecture decoding.
* `DisassemblerBackend::custom(Arc::new(MyDisassembler))`: Injects a third-party disassembler implementing the `Disassembler` trait.

### Build Commands

```bash
# Default build: enables both iced and capstone backends
cargo build --release

# Pure-Rust lightweight build (x86/x64 only, zero C-FFI dependencies)
cargo build --release --no-default-features --features backend-iced

# Multi-architecture only build
cargo build --release --no-default-features --features backend-capstone

# Headless / custom-backend build
cargo build --release --no-default-features
```

---

## Rule Evaluation & FeatureSet Extraction Model

The feature extraction and rule evaluation subsystems bridge raw disassembly and behavioral signatures.

### Scope Hierarchy

Rules declare a `scope` defining the structural context in which assertions are evaluated:

* **File Scope (Whole-Binary & Environmental Attributes)**:
  * `FileScopeFeatures`: Whole-binary physical and structural metrics, universal platform metadata (`os`, `arch`, `binary_format`), dynamic imports, exported symbols, section headers, entropy, and YARA string hits.
* **Function Scope (Intra-Procedural Context)**:
  * `FunctionScopeFeatures`: Intra-procedural subgraphs, McCabe cyclomatic complexity, loop discovery, and direct recursion detection.
* **Basic Block Scope (Localized Control-Flow Slices)**:
  * `BlockScopeFeatures`: Contiguous instruction blocks ending with a branch/ret terminator, tight self-referencing loops, and localized pattern matches.
* **Instruction Scope (Fine-Grained Instruction Semantics)**:
  * Granular instruction attributes evaluated within basic blocks: mnemonics, operands, immediate constants, register access patterns, and specific Windows API or libc invocations.

### Architectural Differences from Python Capa

While `rbat` adheres to the Mandiant Capa rule specification and condition semantics, its internal execution model is re-engineered for compiled, parallel performance in Rust:

1. **Multi-Tier Parallel Evaluation Engine**:
   * *Mandiant Capa (Python)*: Evaluates rules sequentially or through interpreted dictionary lookups in a single-threaded runtime.
   * *rbat*: Partitions rules into independent and dependent rules. Independent rules are evaluated concurrently across all available CPU cores in **Pass 1** via Rayon. Dependent rules (rules containing `match:` predicates) are processed in **Pass 2..N** using fixpoint iteration until convergence.
2. **Literal Anchor Pruning via `NeedleIndex`**:
   * *Mandiant Capa (Python)*: Often traverses rule ASTs and runs regular expression evaluations against extracted features.
   * *rbat*: During rule index compilation, mandatory literal string substrings, API names, and regex anchors are indexed into an Aho-Corasick automaton. A single streaming sweep sets presence bitmasks. If a rule's literal anchor bitmask is not set, the entire rule condition tree is pruned before feature lookup or regex compilation.
3. **Compact Allocation & Zero-Heap Buffers**:
   * *Mandiant Capa (Python)*: Instantiates Python objects for every instruction, feature, and statement, incurring GC overhead.
   * *rbat*: Utilizes cache-conscious stack allocations via `CompactString` (stack-inlined up to 24 bytes without heap allocation), `SmallVec` for operand collections, and slice-backed basic blocks.
4. **FLIRT Interval Compaction**:
   * *Mandiant Capa (Python)*: Evaluates rules against identified library code unless manually filtered.
   * *rbat*: Compiler runtime functions detected via FLIRT signatures are compacted into sorted non-overlapping intervals (`merge_ranges`). Basic blocks falling within library ranges are excluded via binary search in $O(\log K)$ time, eliminating false-positive capability matches on standard library code.
5. **Native Compiled Disassembly**:
   * *Mandiant Capa (Python)*: Relies on Python framework wrappers (Vivisect, SMDA, or IDA Pro).
   * *rbat*: Directly links native Rust `iced-x86` for decoding throughput and C-backed `capstone` for broad architecture support, without external Python interpreters or runtime environments.

---

## Bayesian Risk Scoring System

Traditional static threat scanners sum weights linearly, leading to unbounded score inflation on large binaries with multiple dual-use APIs. `rbat` models finding severity probabilistically.

### Mathematical Formulation

Given a set of matched rules $\{R_1, R_2, \dots, R_n\}$, each rule is assigned an independent threat probability $p_i \in [0, 1)$ based on its severity class:

$$P(\text{Malicious}) = 1 - \prod_{i=1}^n (1 - p_i)$$

The aggregate threat score $S \in [0, 100]$ is computed as:

$$S = \min\left(100, \left\lfloor 100 \times P(\text{Malicious}) \right\rfloor\right)$$

Under this model:
* Independent capabilities compound asymptotically toward 100 without overflowing.
* Pure cryptographic primitives or standard networking features carry low weight and cannot trigger high severity on their own.
* Corroborating hostile indicators (e.g., process hollowing + direct syscalls + anti-debugging) rapidly escalate the aggregate score.

### Severity Classification Tiers

| Severity Class | Base Probability ($p_i$) | Typical Capabilities |
| :--- | :--- | :--- |
| `Informational` | $0.00$ | PE metadata, compiler runtime markers, section headers. |
| `Capability` | $0.05$ | Standard file I/O, socket networking, threading primitives. |
| `Low` | $0.15$ | Dual-use APIs (crypto, registry access, process enumeration). |
| `Medium` | $0.40$ | Evasive heuristics, memory allocation in remote processes. |
| `High` | $0.75$ | Anti-debugging, timing checks (`rdtsc`), code injection, persistence. |
| `Critical` | $0.95$ | Active ransomware encryption loops, kernel driver exploits, wipers. |

### Severity Overrides

Classification weights are tuned via the embedded `capa-overrides.toml` table and can be reconfigured at runtime or via `AnalyzerBuilder::with_classifier`. For example, dual-use rules like `rdtsc`-based timing checks can be demoted when analyzing performance-profiling utilities.

---

## Performance Benchmarks

Empirical performance measurements collected using the Criterion benchmark suite (`benches/`):

| Pipeline Stage / Component | Target / Sample | Engine / Backend | Measured Throughput / Latency |
| :--- | :--- | :--- | :--- |
| **Disassembly** | `al-khaser_x86.exe_` (438 KB text) | `IcedBackend` (pure Rust) | ~195 MB/s (~2.2 ms) |
| **Disassembly** | `al-khaser_x86.exe_` (438 KB text) | `CapstoneBackend` (C-FFI) | ~38 MB/s (~11.5 ms) |
| **Disassembly** | Large PE sample (9.19 MB text) | `IcedBackend` (pure Rust) | ~210 MB/s (~43.7 ms) |
| **Disassembly** | Large PE sample (9.19 MB text) | `CapstoneBackend` (C-FFI) | ~42 MB/s (~218.8 ms) |
| **CFG Construction** | `al-khaser_x86.exe_` (438 KB text) | Block splitting & edge classification | ~2.6 ms |
| **FLIRT Signature Load** | Embedded DB (`.sig` / `.pat`) | In-memory signature parsing | ~1.1 ms (one-off) |
| **FLIRT Matching** | `al-khaser_x86.exe_` | Function prologue matching | ~0.7 ms |
| **Literal Anchor Scan** | `al-khaser_x86.exe_` (438 KB) | `NeedleIndex` (Aho-Corasick) | ~0.35 ms (~1.25 GB/s) |
| **Rule Evaluation** | Full Capa ruleset (~800+ rules) | Pass 1 parallel + Pass 2 fixpoint | ~46.7 ms median |
| **End-to-End Pipeline** | `al-khaser_x86.exe_` (438 KB) | Batch mode (`IcedBackend`) | ~92 ms |
| **End-to-End Pipeline** | `al-khaser_x86.exe_` (438 KB) | Batch mode (`CapstoneBackend`) | ~118 ms |
| **End-to-End Pipeline** | `al-khaser_x86.exe_` (438 KB) | Streaming mode (event callbacks) | ~95 ms |

### Running Benchmarks

```bash
# Run all engine benchmarks
cargo bench -p rbat-bench --bench engine

# Run specific benchmark groups
cargo bench -p rbat-bench --bench engine -- bench_disassembly
cargo bench -p rbat-bench --bench engine -- bench_rules
cargo bench -p rbat-bench --bench engine -- bench_pipeline
```

---

## Fuzzing & Automation Tooling

### LibFuzzer Fuzz Suite (`fuzz/`)

Four libFuzzer targets ensure stability and memory safety when parsing corrupted, malformed, or adversarial inputs:

* `fuzz_analyze`: End-to-end analyzer batching on arbitrary byte slices.
* `fuzz_cfg`: CFG reconstruction resilience against circular branches and malformed jump targets.
* `fuzz_flirt`: Resilience against corrupted `.sig` and `.pat` signature formats.
* `fuzz_rules`: Fuzzing YAML/JSON rule parsing, syntax validation, and match tree evaluation.

```bash
# Generate seed corpus from existing test files
bash scripts/generate_fuzz_corpus.sh

# Run end-to-end analysis fuzzer
cargo fuzz run fuzz_analyze

# Run CFG reconstruction fuzzer
cargo fuzz run fuzz_cfg
```

### Rule Pre-Compilation (`xtask`)

To eliminate rule-parsing overhead at startup, the repository provides an `xtask` command to scan YAML Capa rules and compile them into a compact, deterministic MessagePack bundle (`embedded_rules.mp`):

```bash
cargo run -p xtask -- bundle-rules
```

---

## Quick Start & Code Examples

### 1. Basic Batch Analysis

Run static binary analysis on a buffer and inspect metadata, matched rules, and the Bayesian threat score:

```rust,no_run
use rbat::core::analyzer::Analyzer;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let buffer = std::fs::read("sample.exe")?;
    let analyzer = Analyzer::builder().build();
    let (analysis_result, risk_assessment) = analyzer.batch(&buffer)?;

    println!("Target platform: {}", analysis_result.metadata.binary_type);
    println!("Architecture: {}", analysis_result.metadata.architecture_name());
    println!("Threat score: {}/100", risk_assessment.score);
    println!("Severity: {}", risk_assessment.severity);

    for finding in &risk_assessment.findings {
        println!("Rule: {} [{:?}]", finding.indicator, finding.severity_class);
    }

    Ok(())
}
```

### 2. Real-Time Streaming Analysis

Consume analysis events as each pipeline stage finishes:

```rust,no_run
use rbat::core::analyzer::Analyzer;
use rbat::core::types::analysis::AnalysisProgress;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let buffer = std::fs::read("sample.bin")?;
    let analyzer = Analyzer::builder().build();

    analyzer.streaming(&buffer, |event| match event {
        AnalysisProgress::BinaryMetadata(meta) => {
            println!("Target platform: {} ({})", meta.binary_type, meta.architecture_name());
        }
        AnalysisProgress::Entropy(sections) => {
            println!("Calculated entropy for {} sections", sections.len());
        }
        AnalysisProgress::Strings(matches) => {
            println!("Matched {} suspicious strings", matches.len());
        }
        AnalysisProgress::Disassembly(instructions) => {
            println!("Disassembled {} instructions", instructions.len());
        }
        _ => {}
    })?;

    Ok(())
}
```

### 3. Custom Rules and Classifier Configuration

Load custom YAML rules and a custom severity overrides table:

```rust,no_run
use rbat::core::analyzer::AnalyzerBuilder;
use rbat::core::disassembler::DisassemblerBackend;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let analyzer = AnalyzerBuilder::new()
        .with_backend(DisassemblerBackend::default())
        .with_rules("path/to/custom_rules")?
        .with_flirt("path/to/flirt_signatures")?
        .with_classifier("path/to/capa-overrides.toml")?
        .build();

    let buffer = std::fs::read("sample.exe")?;
    let (_, assessment) = analyzer.batch(&buffer)?;
    println!("Custom analysis score: {}", assessment.score);

    Ok(())
}
```

### 4. Control Flow Graph Traversal & Function Inspection

Inspect reconstructed basic blocks, cyclomatic complexity, and intra-procedural functions:

```rust,no_run
use rbat::core::analyzer::Analyzer;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let buffer = std::fs::read("sample.exe")?;
    let analyzer = Analyzer::builder().build();
    let (analysis_result, _) = analyzer.batch(&buffer)?;

    if let Some(cfg) = analysis_result.cfg {
        println!("Reconstructed {} basic blocks", cfg.blocks.len());
        for (addr, func) in &cfg.functions {
            println!(
                "Function at 0x{:x}: {} blocks, {} instructions",
                addr,
                func.block_count(),
                func.instr_count(&cfg)
            );
        }

        // Export graph to Graphviz DOT syntax
        let dot_graph = cfg.to_dot();
        std::fs::write("graph.dot", dot_graph)?;
    }

    Ok(())
}
```

### 5. Custom Disassembler Implementation

Inject a custom disassembler engine using `DisassemblerBackend::custom`:

```rust,no_run
use std::sync::Arc;
use rbat::core::analyzer::AnalyzerBuilder;
use rbat::core::disassembler::{DisassemblerBackend, InstructionInfo};
use rbat::core::parser::{BinaryArch, IatMap};
use rbat::core::traits::Disassembler;
use rbat::core::types::result::RbatResult;

#[derive(Debug)]
struct CustomDisassembler;

impl Disassembler for CustomDisassembler {
    fn disassemble(
        &self,
        _bytes: &[u8],
        _base_addr: u64,
        _arch: BinaryArch,
        _iat_map: &IatMap,
    ) -> RbatResult<Arc<[InstructionInfo]>> {
        // External decoding logic goes here
        Ok(Arc::new([]))
    }

    fn name(&self) -> &'static str {
        "custom-engine"
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let custom_backend = DisassemblerBackend::custom(Arc::new(CustomDisassembler));
    let analyzer = AnalyzerBuilder::new()
        .with_backend(custom_backend)
        .build();

    let buffer = std::fs::read("sample.bin")?;
    let (result, _) = analyzer.batch(&buffer)?;
    println!("Analyzed {} sections", result.section_entropy.len());

    Ok(())
}
```

For complete executable examples, explore the `examples/` directory:
* `examples/batch_analysis.rs`: Command-line batch analysis demonstrating metadata and risk reporting.
* `examples/streaming_analysis.rs`: Asynchronous analysis with decoupled mpsc progress reporting.
* `examples/custom_disassembler.rs`: End-to-end custom disassembler implementation.
* `examples/cfg_and_functions.rs`: Basic block navigation, cyclomatic complexity, and DOT graph export.

---

## Attribution & Major Dependencies

`rbat` builds upon foundational open-source crates and research from the reverse-engineering and security analysis communities:

| Component / Crate | Maintainer / Project | Role in RBAT |
| :--- | :--- | :--- |
| **`iced-x86`** | 0xd4d | High-throughput, memory-efficient x86 and x86_64 instruction decoder and Intel-syntax formatter in pure Rust. |
| **`capstone-rs`** | Capstone Engine & Nguyen Anh Quynh | Multi-architecture disassembly engine providing support for ARM, ARM64, MIPS, and PowerPC. |
| **`object`** | Gimpmaster & Contributors | Unified parsing and header extraction for ELF, PE/COFF, and Mach-O binary formats. |
| **`fast-flirt`** | Fast-FLIRT Project | Fast Library Identification and Recognition Technology (.sig/.pat) pattern matcher for compiler runtime identification. |
| **`aho-corasick`** | Andrew Gallant (BurntSushi) | Multi-pattern finite automaton used in `NeedleIndex` for instantaneous literal anchor pre-filtering. |
| **`rayon`** | Rayon Project | Work-stealing data-parallel thread pool for concurrent plugin execution and parallel rule evaluation. |
| **`yara`** | VirusTotal & YARA Contributors | Embedded signature scanning and payload pattern matching. |
| **`petgraph`** | Petgraph Contributors | Graph data structures and algorithms powering Control Flow Graph (CFG) analysis and DOT serialization. |
| **`compact_str`** | ParkMyCar | Memory-compact strings inlined on the stack (up to 24 bytes) to eliminate heap allocations during feature extraction. |
| **`smallvec`** | Servo Project | Stack-allocated inline vectors used for instruction operands, jump targets, and CFG adjacency lists. |
| **`capa`** | Mandiant / Google Cloud | Rule syntax specifications, condition semantics, and threat capability taxonomy that inspired the behavioral rule engine. |

---

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](../../LICENSE) file for details.
