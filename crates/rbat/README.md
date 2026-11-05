# rbat

[![Crates.io Version](https://img.shields.io/crates/v/rbat?style=for-the-badge&logo=rust&color=orange&label=version)](https://crates.io/crates/rbat)
[![Crates.io Downloads](https://img.shields.io/crates/d/rbat?style=for-the-badge&color=blue&label=downloads)](https://crates.io/crates/rbat)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=for-the-badge)](https://opensource.org/licenses/Apache-2.0)
[![Build Status](https://img.shields.io/github/actions/workflow/status/Heritage-XioN/rbat/ci-rust.yml?style=for-the-badge&label=build)](https://github.com/Heritage-XioN/rbat/actions)
[![Rust MSRV](https://img.shields.io/badge/rustc-1.85+-orange.svg?style=for-the-badge&logo=rust)](https://blog.rust-lang.org/)

**rbat** is a high-performance, modular static binary analysis and threat detection engine. It provides programmatic APIs to parse executable formats, reconstruct control flow graphs, perform multi-backend disassembly, match FLIRT compiler signatures, evaluate Mandiant Capa behavioral rules across four execution scopes, and aggregate findings into calibrated Bayesian threat scores mapped to MITRE ATT&CK and MBC.

This crate serves as the foundational analysis library for the CLI/TUI binary crate [`rbat-cli`](../rbat-cli/README.md).

---

## Quick Start

### Batch Analysis

Run static analysis on a binary buffer and inspect metadata, matched rules, and the Bayesian threat score:

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

### Streaming Analysis

Consume analysis events as each pipeline stage completes:

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

For additional usage patterns, see [Code Examples](#code-examples) below.

---

## Capabilities

* **Multi-Format Binary Parsing** -- ELF (Linux), PE/COFF (Windows), and Mach-O (macOS) in both 32-bit and 64-bit variants.
* **Pluggable Multi-Backend Disassembly** -- Pure-Rust Iced (x86/x64), Capstone C-FFI (x86, x64, ARM, ARM64, MIPS, PowerPC), and custom trait-based backends.
* **Control Flow Graph Reconstruction** -- Basic block segmentation, edge classification, intra-procedural function recovery, McCabe cyclomatic complexity, loop/recursion detection, and Graphviz DOT / Petgraph export.
* **Extensible Concurrent Plugin Engine** -- Rayon-scoped heuristic plugins governed by the `HeuristicPlugin` trait, enabling custom static analysis logic with zero-copy shared state and atomic cancellation.
* **Cryptographic and Similarity Hashing** -- MD5, SHA-1, SHA-256, SSDEEP (fuzzy), and TLSH (locality-sensitive).
* **Shannon Entropy Analysis** -- Per-section entropy with automated packed/encrypted payload detection.
* **Static String Extraction** -- ASCII and UTF-16LE decoding with embedded YARA pattern matching.
* **Import/Export Table Analysis** -- IAT and EAT extraction with MSVC and Itanium C++ symbol demangling.
* **FLIRT Compiler Runtime Identification** -- `.sig` / `.pat` signature matching with sorted interval compaction for $O(\log K)$ library range exclusion.
* **Code Cave Discovery** -- NOP sled, null padding, and trap padding detection across executable sections.
* **Declarative Behavioral Rule Engine** -- Full Mandiant Capa YAML/JSON rule evaluation with boolean condition trees, threshold counts, range matches, and regex support.
* **Bayesian Probabilistic Threat Scoring** -- Noisy-OR formulation with MITRE ATT&CK and MBC taxonomy alignment, tunable via TOML severity overrides.
* **Dual Execution Modes** -- Synchronous batch analysis returning structured results, or non-blocking streaming with real-time `AnalysisProgress` callbacks.

---

## Analysis Pipeline

The pipeline coordinates parsing, decoding, concurrent heuristic scanning, feature extraction, rule evaluation, and probabilistic scoring:

```text
Raw Binary Buffer &[u8]
      │
      ├───► Parse & Validate (object crate)
      │        ├── Format Detection (ELF / PE / Mach-O)
      │        ├── Architecture Detection (x86 / x64 / ARM / ARM64)
      │        └── Section Table & Entry Point Resolution
      │
      ├───► Disassemble (Iced / Capstone / Custom)
      │        ├── InstructionInfo Stream (Normalized Intel Syntax)
      │        └── FLIRT Entry Point Collection (Candidate Prologues)
      │
      ├───► Concurrent Heuristic Plugin Engine (rayon::scope)
      │        ├── HashingPlugin          (MD5, SHA-1, SHA-256, SSDEEP, TLSH)
      │        ├── EntropyPlugin          (Shannon Entropy per Section)
      │        ├── StringCheckPlugin      (Extraction + YARA + NeedleIndex Scan)
      │        ├── PackerSigCheckPlugin   (Packer / Cryptor YARA Signatures)
      │        ├── ImportsPlugin          (IAT Extraction + Demangling + NeedleIndex)
      │        ├── ExportsPlugin          (EAT Extraction + Demangling + NeedleIndex)
      │        ├── MetadataPlugin         (Header & Timestamp Analysis)
      │        ├── CfgPlugin              (CFG Reconstruction & Function Recovery)
      │        ├── LibraryFunctionsPlugin (FLIRT Signature Matching)
      │        ├── DisassemblyPlugin      (Code Cave & NOP Sled Detection)
      │        └── Custom HeuristicPlugin Implementations
      │
      ├───► NeedleIndex Finalization
      │        ├── Instruction Mnemonic & Operand Anchor Scanning
      │        └── Literal Presence Bitmask Population
      │
      ├───► FeatureSet Partitioning by Scope
      │        ├── File        (Hashes, Format, Imports, Exports, Strings)
      │        ├── Function    (Subgraphs, Cyclomatic Complexity, Loops)
      │        ├── BasicBlock  (Instruction Slices, Tight Loops)
      │        └── Instruction (Mnemonics, Operands, API Calls)
      │
      ├───► Rule Evaluation Engine (Capa YAML & JSON)
      │        ├── Pass 1: Parallel Independent Rules (Rayon Workers)
      │        └── Pass 2..N: Fixpoint Iteration for Dependent Rules (match:)
      │
      └───► Risk Assessment & Severity Classification
               ├── Bayesian Noisy-OR Threat Score (0 - 100)
               ├── SeverityClassifier & capa-overrides.toml
               └── MITRE ATT&CK & MBC Taxonomy Mapping
```

1. **Parse & Validate**: The input buffer is validated via the `object` crate. Executable sections, header flags, entry point addresses, and segment mappings are extracted into a `SectionRange` table.
2. **Disassemble**: Machine code from executable sections is decoded by the active `DisassemblerBackend`, producing a normalized `InstructionInfo` stream. FLIRT candidate function prologues are collected for downstream signature matching.
3. **Concurrent Plugin Engine**: All registered `HeuristicPlugin` implementations execute concurrently inside a Rayon scope (`rayon::scope`), sharing a zero-copy `AnalysisContext`. CFG reconstruction, FLIRT signature matching, NeedleIndex buffer scanning, and all other heuristic analyses run as plugins in this phase. An atomic cancellation flag halts sibling threads immediately if any plugin encounters a fatal error.
4. **NeedleIndex Finalization**: After plugins complete, the `NeedleIndex` automaton performs a final pass over instruction mnemonics and operands in the reconstructed CFG, populating literal anchor presence bitmasks used to prune non-matching rules.
5. **FeatureSet Partitioning**: Plugin findings and CFG topologies are organized into scope-tiered feature sets. FLIRT-identified library ranges are compacted into sorted non-overlapping intervals, enabling $O(\log K)$ exclusion of compiler boilerplate from capability matches.
6. **Rule Evaluation**: Independent rules are evaluated concurrently in Pass 1 via Rayon. Dependent rules (those containing `match:` predicates referencing other rules) are resolved in Pass 2..N via fixpoint iteration until convergence. Rules whose literal anchor bitmasks are absent are pruned without AST traversal.
7. **Risk Assessment**: Matched rules are categorized by the `SeverityClassifier`, and a Noisy-OR calculation produces a normalized 0-100 threat score alongside MITRE ATT&CK and MBC annotations.

---

## Extensible Plugin Architecture

The heuristic engine is designed for zero-copy concurrency and modular extensibility:

* **Scoped Concurrency (`rayon::scope`)**: All registered plugins are spawned within a Rayon scope, borrowing non-static references directly from the binary buffer and analysis context (`AnalysisContext<'buf, 'ctx>`) without heap cloning or lifetime extension.
* **Trait Abstraction (`HeuristicPlugin`)**: The engine defines the `HeuristicPlugin` trait (`Send + Sync`). Any custom struct implementing this interface can be passed into the engine to execute specialized static analysis logic alongside the built-in plugins.
* **Non-Blocking Progress Streaming**: As each plugin completes, it publishes findings as an `AnalysisProgress` variant (`Hashes`, `Entropy`, `CFG`, `Strings`, `Imports`, `Exports`, `BinaryMetadata`, `LibraryFunctions`, `Disassembly`, `PackerSigs`).
* **Short-Circuit Error Propagation**: If a plugin encounters an unrecoverable failure, the engine records the root-cause error and flips an atomic cancellation flag (`cancel_flag`), causing active sibling threads to abort without completing redundant work.

---

## Feature Flags

| Feature Flag | Default | Description |
| :--- | :--- | :--- |
| `backend-iced` | Yes | Pure-Rust x86/x64 disassembler via `iced-x86`. |
| `backend-capstone` | Yes | Multi-architecture disassembler (x86, x64, ARM, ARM64, MIPS, PPC) via Capstone C-FFI. |

Both backends can be enabled simultaneously. Runtime selection is handled via enum dispatch through `DisassemblerBackend`:

* `DisassemblerBackend::default()`: Selects the fastest available backend (prefers Iced for x86/x64, falls back to Capstone).
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

## Code Examples

### Custom Rules and Classifier Configuration

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

### Control Flow Graph Traversal

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

### Custom Disassembler Implementation

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

For complete executable examples, explore the [`examples/`](examples/) directory:
* [`examples/batch_analysis.rs`](examples/batch_analysis.rs): Programmatic batch analysis with metadata and risk reporting.
* [`examples/streaming_analysis.rs`](examples/streaming_analysis.rs): Real-time streaming analysis with progress event callbacks.
* [`examples/custom_disassembler.rs`](examples/custom_disassembler.rs): End-to-end custom `Disassembler` trait implementation.
* [`examples/cfg_and_functions.rs`](examples/cfg_and_functions.rs): Basic block navigation, cyclomatic complexity, and DOT graph export.

---

## Rule Evaluation & FeatureSet Model

### Scope Hierarchy

Rules declare a `scope` defining the structural context in which assertions are evaluated:

* **File Scope** -- Whole-binary physical and structural metrics: platform metadata (`os`, `arch`, `binary_format`), dynamic imports, exported symbols, section headers, entropy, and YARA string hits.
* **Function Scope** -- Intra-procedural subgraphs: McCabe cyclomatic complexity, loop discovery, and direct recursion detection.
* **Basic Block Scope** -- Contiguous instruction blocks ending at a branch or return terminator: tight self-referencing loops and localized pattern matches.
* **Instruction Scope** -- Granular instruction attributes: mnemonics, operands, immediate constants, register access patterns, and specific API invocations.

### Differences from Python Capa

While `rbat` adheres to the Mandiant Capa rule specification and condition semantics, its execution model is re-engineered for compiled, parallel performance:

1. **Multi-Tier Parallel Evaluation**: Python Capa evaluates rules sequentially through interpreted dictionary lookups. `rbat` partitions rules into independent and dependent sets -- independent rules run concurrently across all CPU cores in Pass 1 via Rayon, while dependent rules (`match:` predicates) resolve in Pass 2..N via fixpoint iteration.
2. **Literal Anchor Pruning via `NeedleIndex`**: Python Capa traverses rule ASTs and runs regex evaluations against extracted features. `rbat` indexes mandatory literal substrings and API names into an Aho-Corasick automaton during rule compilation. A single streaming sweep sets presence bitmasks, pruning entire rule trees whose anchors are absent.
3. **Compact Allocations**: Python Capa instantiates objects for every instruction and feature, incurring GC overhead. `rbat` uses `CompactString` (stack-inlined up to 24 bytes), `SmallVec` for operand collections, and slice-backed basic blocks.
4. **FLIRT Interval Compaction**: Python Capa evaluates rules against identified library code unless manually filtered. `rbat` compacts FLIRT-detected ranges into sorted non-overlapping intervals (`merge_ranges`), excluding library basic blocks via binary search in $O(\log K)$ time.
5. **Native Disassembly**: Python Capa relies on Python framework wrappers (Vivisect, SMDA, or IDA Pro). `rbat` links `iced-x86` directly for decoding throughput and `capstone` for broad architecture support, without external interpreters.

---

## Bayesian Risk Scoring

Traditional static threat scanners sum weights linearly, leading to unbounded score inflation on large binaries with multiple dual-use APIs. `rbat` models finding severity probabilistically.

### Mathematical Formulation

Given matched rules $\{R_1, R_2, \dots, R_n\}$, each assigned an independent threat probability $p_i \in [0, 1)$ based on its severity class:

$$P(\text{Malicious}) = 1 - \prod_{i=1}^n (1 - p_i)$$

The aggregate threat score $S \in [0, 100]$ is computed as:

$$S = \min\left(100, \left\lfloor 100 \times P(\text{Malicious}) \right\rfloor\right)$$

Under this model:
* Independent capabilities compound asymptotically toward 100 without overflowing.
* Standard networking or cryptographic primitives carry low weight and cannot trigger high severity alone.
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

Empirical measurements collected using the Criterion benchmark suite (`benches/`):

| Pipeline Stage | Target / Sample | Engine | Measured Throughput / Latency |
| :--- | :--- | :--- | :--- |
| Disassembly | `al-khaser_x86.exe_` (438 KB text) | IcedBackend | ~195 MB/s (~2.2 ms) |
| Disassembly | `al-khaser_x86.exe_` (438 KB text) | CapstoneBackend | ~38 MB/s (~11.5 ms) |
| Disassembly | Large PE sample (9.19 MB text) | IcedBackend | ~210 MB/s (~43.7 ms) |
| Disassembly | Large PE sample (9.19 MB text) | CapstoneBackend | ~42 MB/s (~218.8 ms) |
| CFG Construction | `al-khaser_x86.exe_` (438 KB text) | Block split + edge classification | ~2.6 ms |
| FLIRT Signature Load | Embedded DB (`.sig` / `.pat`) | In-memory parsing | ~1.1 ms (one-off) |
| FLIRT Matching | `al-khaser_x86.exe_` | Function prologue matching | ~0.7 ms |
| Literal Anchor Scan | `al-khaser_x86.exe_` (438 KB) | NeedleIndex (Aho-Corasick) | ~0.35 ms (~1.25 GB/s) |
| Rule Evaluation | Full Capa ruleset (~800+ rules) | Pass 1 parallel + Pass 2 fixpoint | ~46.7 ms median |
| End-to-End Pipeline | `al-khaser_x86.exe_` (438 KB) | Batch (IcedBackend) | ~92 ms |
| End-to-End Pipeline | `al-khaser_x86.exe_` (438 KB) | Batch (CapstoneBackend) | ~118 ms |
| End-to-End Pipeline | `al-khaser_x86.exe_` (438 KB) | Streaming (event callbacks) | ~95 ms |

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

## Fuzzing & Tooling

### LibFuzzer Fuzz Suite ([`fuzz/`](../../fuzz/))

Four libFuzzer targets ensure stability and memory safety against corrupted, malformed, or adversarial inputs:

* [`fuzz_analyze`](../../fuzz/fuzz_targets/fuzz_analyze.rs): End-to-end analyzer batching on arbitrary byte slices (`Analyzer::streaming`).
* [`fuzz_cfg`](../../fuzz/fuzz_targets/fuzz_cfg.rs): CFG reconstruction resilience against circular branches and malformed jump targets (`ControlFlowGraph::new`).
* [`fuzz_flirt`](../../fuzz/fuzz_targets/fuzz_flirt.rs): Resilience against corrupted `.sig` and `.pat` signature formats (`FlirtMatcher::identify_library_functions`).
* [`fuzz_rules`](../../fuzz/fuzz_targets/fuzz_rules.rs): YAML/JSON rule parsing, syntax validation, and match tree evaluation (`Rule::evaluate`).

```bash
# Generate seed corpus from existing test files
bash scripts/generate_fuzz_corpus.sh

# Run end-to-end analysis fuzzer
cargo fuzz run fuzz_analyze

# Run CFG reconstruction fuzzer
cargo fuzz run fuzz_cfg
```

### Rule Pre-Compilation (`xtask`)

To eliminate rule-parsing overhead at startup, the repository provides an `xtask` command to compile YAML Capa rules into a compact MessagePack bundle (`embedded_rules.mp`):

```bash
cargo run -p xtask -- bundle-rules
```

---

## Attribution & Dependencies

This project builds on the incredible work of the following projects:

* [**iced-x86**](https://github.com/icedland/iced) -- High-throughput x86/x64 instruction decoder and Intel-syntax formatter.
* [**capstone-rs**](https://github.com/capstone-rust/capstone-rs) -- Multi-architecture disassembly engine (ARM, ARM64, MIPS, PowerPC) via Capstone C-FFI.
* [**object**](https://github.com/gimli-rs/object) -- Unified parsing and header extraction for ELF, PE/COFF, and Mach-O binary formats.
* [**fast-flirt**](https://crates.io/crates/fast-flirt) -- Fast Library Identification and Recognition Technology pattern matcher for compiler runtime identification.
* [**aho-corasick**](https://github.com/BurntSushi/aho-corasick) -- Multi-pattern finite automaton powering `NeedleIndex` literal anchor pre-filtering.
* [**rayon**](https://github.com/rayon-rs/rayon) -- Work-stealing data-parallel thread pool for concurrent plugin execution and parallel rule evaluation.
* [**yara**](https://github.com/VirusTotal/yara) -- Embedded signature scanning and payload pattern matching.
* [**petgraph**](https://github.com/petgraph/petgraph) -- Graph data structures and algorithms for CFG analysis and DOT serialization.
* [**compact_str**](https://github.com/ParkMyCar/compact_str) -- Stack-inlined strings (up to 24 bytes) eliminating heap allocations during feature extraction.
* [**smallvec**](https://github.com/servo/rust-smallvec) -- Stack-allocated inline vectors for instruction operands and CFG adjacency lists.
* [**capa**](https://github.com/mandiant/capa) -- Rule syntax specifications, condition semantics, and threat capability taxonomy by Mandiant / Google Cloud.

---

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](../../LICENSE) file for details.
