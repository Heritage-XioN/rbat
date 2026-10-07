# rbat

[![Crates.io Version](https://img.shields.io/crates/v/rbat?style=for-the-badge&logo=rust&color=orange&label=version)](https://crates.io/crates/rbat)
[![Crates.io Downloads](https://img.shields.io/crates/d/rbat?style=for-the-badge&color=blue&label=downloads)](https://crates.io/crates/rbat)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=for-the-badge)](https://opensource.org/licenses/Apache-2.0)
[![Build Status](https://img.shields.io/github/actions/workflow/status/Heritage-XioN/rbat/ci-rust.yml?style=for-the-badge&label=build)](https://github.com/Heritage-XioN/rbat/actions)
[![Rust MSRV](https://img.shields.io/badge/rustc-1.75+-orange.svg?style=for-the-badge&logo=rust)](https://blog.rust-lang.org/2023/12/28/Rust-1.75.0.html)

**rbat** is a high-performance, terminal-native binary analysis tool designed for security researchers, malware analysts, and reverse engineers. It provides a comprehensive suite of static analysis tools to identify potential threats, analyze binary structures, and evaluate risk levels across multiple executable formats.

---

## Features

* **Multi-Format Support**: Native parsing for ELF, PE, and Mach-O binaries.
* **Control Flow Graph (CFG) Reconstruction**: Basic block disassembly and edge tracking outputting Graphviz DOT format (`--cfg`) and interactive TUI block navigation.
* **Declarative JSON & YAML Rule Engine (CAPA Compatible)**: Native support for parsing Mandiant's CAPA YAML rules alongside strict JSON rule schemas. Supports nested `and`/`or`/`not` condition trees and MITRE ATT&CK technique tagging.
* **Fast Library Identification and Recognition Technology (FLIRT)**: Automatically apply `.sig` and `.pat` FLIRT signatures to identify known compiler library functions and eliminate analysis noise.
* **Backend Feature Flags**: Pluggable disassembly engines, **mutually exclusive** — compile with `backend-capstone` (default, multi-architecture) or `backend-iced` (blazing fast, x86/x64 only):
  - `cargo build --release` → capstone backend
  - `cargo build --release --no-default-features --features backend-iced` → iced backend
  - Enabling both fails the build with a guidance error.
* **Dynamic Risk Scoring (MITRE ATT&CK)**: Noisy-OR probabilistic aggregation over classified findings — rules are mapped to severity classes (`Informational`, `Capability`, `Low`, `Medium`, `High`, `Critical`) via an embedded TOML override table (`capa-overrides.toml`, tunable at runtime with `--severity-overrides`) combined with ATT&CK tactic / MBC objective inference. Ordinary capabilities and pure cryptographic primitives carry zero-to-negligible weight; corroborating hostile indicators compound toward the ceiling. Dual-use rules (e.g. `rdtsc`-based anti-debugging detection) ship High by default — when analyzing perf-instrumented software, demote them per-target via `--severity-overrides`.
* **Rich TUI Dashboard**: An interactive terminal interface (`--tui`) for navigating disassembly blocks, entropy heatmaps, findings, and security recommendations.
* **Multi-Format Reporting**: Export analysis results to Light-Mode Executive PDF reports (with heatmaps), SIEM-ready CSV logs, or JSON dumps for automated pipelines.
* **Shell Auto-Completions**: Generator subcommand (`rbat completions`) for Bash, Zsh, Fish, PowerShell, and Elvish.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
rbat = "1.0.1"
```

### Capa Rules Submodule

To use the embedded Mandiant Capa ruleset, ensure the rules submodule is initialized and cloned:

```bash
git submodule update --init --recursive
```

If the submodule is not checked out at compile-time, `rbat` will build with the minimal json rules present in the codebase and or fallback to loading custom rules from user-specified directories.

---

## Quick Start

The following minimal example demonstrates how to run a programmatic static analysis on a target binary and retrieve its risk assessment score:

```rust,no_run
use std::path::Path;
use rbat::core::analyzer::Analyzer;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new("path/to/binary");
    let buffer = std::fs::read(path)?;
    let analyzer = Analyzer::builder().build();
    let (analysis_result, risk_assessment) = analyzer.batch(&buffer)?;

    println!("Analysis complete for: {}", analysis_result.metadata.binary_type);
    println!("Architecture: {}", analysis_result.metadata.architecture_name());
    println!("Threat Score: {}/100", risk_assessment.score);
    println!("Severity: {}", risk_assessment.severity);

    Ok(())
}
```

---

## Usage Examples

### Programmatic Streaming Analysis

Consume analysis updates as they occur using streaming mode:

```rust,no_run
use std::path::Path;
use rbat::core::analyzer::Analyzer;
use rbat::core::types::analysis::AnalysisProgress;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new("path/to/binary");
    let buffer = std::fs::read(path)?;
    let analyzer = Analyzer::builder().build();

    analyzer.streaming(&buffer, |event| match event {
        AnalysisProgress::BinaryMetadata(meta) => {
            println!("Target platform: {} ({})", meta.binary_type, meta.architecture_name());
        }
        AnalysisProgress::Entropy(sections) => {
            println!("Calculated entropy for {} sections", sections.len());
        }
        AnalysisProgress::Strings(matches) => {
            println!("YARA matched {} suspicious strings", matches.len());
        }
        _ => {}
    })?;

    Ok(())
}
```

### Report Generation

Generate formatted PDF, CSV, or JSON analysis reports via the CLI:

```bash
# Executive Light-Mode PDF Report
rbat analyze sample.exe --pdf report.pdf

# SIEM-Ready CSV Report
rbat analyze sample.exe --csv report.csv

# Structured JSON Dump
rbat analyze sample.exe --json report.json
```

---

## CLI Mode Commands & Subcommands

Run `rbat` as a command-line application using its explicit subcommand interface.

### 1. `rbat analyze <PATH>`

Analyze a binary executable and display terminal summary reports or generate artifacts:

```bash
# Display interactive TUI dashboard
rbat analyze /path/to/binary --tui

# Generate PDF, CSV, and JSON reports into a target directory
rbat analyze /path/to/binary --pdf --csv --json --out-dir ./reports

# Include custom JSON threat detection rules
rbat analyze /path/to/binary --rules ./custom_rules

# Output Control Flow Graph (CFG) in Graphviz DOT format to stdout
rbat analyze /path/to/binary --cfg
```

#### `rbat analyze` Flags:
* `-t, --tui`: Launch the interactive Ratatui terminal UI dashboard.
* `-p, --pdf`: Generate a Light-Mode Executive PDF report.
* `-c, --csv`: Generate a SIEM-ready CSV report.
* `-j, --json`: Generate a structured JSON analysis report.
* `-g, --cfg`: Output the Control Flow Graph (CFG) in Graphviz DOT format to `stdout`.
* `-o, --out-dir <DIR>`: Output directory for generated report files (default: `.`).
* `-r, --rules <RULES>`: Load custom JSON threat rules from a directory.
* `-s, --signatures <SIGNATURES>`: Optional directory containing custom FLIRT signatures (.sig or .pat files).
* `-b, --backend <BACKEND>`: Disassembler backend engine to use [default: dynamic] [possible values: capstone, iced, dynamic].
* `-d, --dry-run`: Run static analysis pipeline without emitting output files or launching the UI.

### 2. `rbat rules`

Inspect, validate, or generate custom JSON threat detection rules:

```bash
# Print an annotated example JSON and yaml rule template
rbat rules example

# Output the Draft-07 JSON Schema definition
rbat rules schema

# Validate all custom JSON and yaml rules in a directory against the schema
rbat rules validate --dir ./my_rules
```

### 3. `rbat completions <SHELL>`

Generate shell completion scripts for auto-completing commands:

```bash
# Bash
rbat completions bash > ~/.local/share/bash-completion/completions/rbat

# Zsh
rbat completions zsh > ~/.zfunc/_rbat

# Fish
rbat completions fish > ~/.config/fish/completions/rbat.fish
```

---

## Links

* [Documentation (docs.rs)](https://docs.rs/rbat)
* [Repository (GitHub)](https://github.com/Heritage-XioN/rbat)
* [Contributing Guide](../CONTRIBUTING.md)

---

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](https://www.apache.org/licenses/LICENSE-2.0) file for details.
