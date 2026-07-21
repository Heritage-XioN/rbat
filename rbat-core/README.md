# rbat

[![Crates.io Version](https://img.shields.io/crates/v/rbat?style=for-the-badge&logo=rust&color=orange&label=version)](https://crates.io/crates/rbat)
[![Crates.io Downloads](https://img.shields.io/crates/d/rbat?style=for-the-badge&color=blue&label=downloads)](https://crates.io/crates/rbat)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/github/actions/workflow/status/Heritage-XioN/rbat/ci-rust.yml?style=for-the-badge&label=build)](https://github.com/Heritage-XioN/rbat/actions)
[![Rust MSRV](https://img.shields.io/badge/rustc-1.75+-orange.svg?style=for-the-badge&logo=rust)](https://blog.rust-lang.org/2023/12/28/Rust-1.75.0.html)

**rbat** is a high-performance, terminal-native binary analysis tool designed for security researchers, malware analysts, and reverse engineers. It provides a comprehensive suite of static analysis tools to identify potential threats, analyze binary structures, and evaluate risk levels across multiple executable formats.

---

## Features

* **Multi-Format Support**: Native parsing for ELF, PE, and Mach-O binaries.
* **Control Flow Graph (CFG) Reconstruction**: Basic block disassembly and edge tracking outputting Graphviz DOT format (`--cfg`) and interactive TUI block navigation.
* **Declarative Custom Rule Engine**: Strict JSON rule schemas (`rbat rules`) supporting `and`/`or`/`not` condition trees, MITRE ATT&CK technique tags, and strict field validation.
* **Dynamic Risk Scoring**: Heuristic-based risk assessment calculating threat levels based on section entropy, suspicious imports, code caves, and behavior patterns.
* **Rich TUI Dashboard**: An interactive terminal interface (`--tui`) for navigating disassembly blocks, entropy heatmaps, findings, and security recommendations.
* **Multi-Format Reporting**: Export analysis results to Light-Mode Executive PDF reports (with heatmaps), SIEM-ready CSV logs, or JSON dumps for automated pipelines.
* **Shell Auto-Completions**: Generator subcommand (`rbat completions`) for Bash, Zsh, Fish, PowerShell, and Elvish.

---

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
rbat = "1.0.1"
```

---

## Quick Start

The following minimal example demonstrates how to run a programmatic static analysis on a target binary and retrieve its risk assessment score:

```rust
use std::path::Path;
use rbat::core::analyzer::analyze_batch;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new("path/to/binary");
    let (analysis_result, risk_assessment) = analyze_batch(path)?;

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

Consume analysis updates as they occur using `analyze_streaming`:

```rust
use std::path::Path;
use rbat::core::analyzer::analyze_streaming;
use rbat::core::types::AnalysisProgress;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new("path/to/binary");

    analyze_streaming(path, |event| match event {
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

Generate formatted PDF, CSV, or JSON analysis reports:

```rust
use std::path::Path;
use rbat::core::analyzer::analyze_batch;
use rbat::utils::{
    csv::generate_csv_report,
    json::generate_json_report,
    pdf::generate_pdf_report,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let binary_path = Path::new("path/to/binary");
    let out_dir = Path::new("./reports");
    std::fs::create_dir_all(out_dir)?;

    let (result, score) = analyze_batch(binary_path)?;

    // Executive Light-Mode PDF Report
    generate_pdf_report(binary_path, &score, &result, &out_dir.join("report.pdf"))?;

    // SIEM-Ready CSV Report
    generate_csv_report(binary_path, &score, &out_dir.join("report.csv"))?;

    // Structured JSON Dump
    generate_json_report(binary_path, &score, &result, &out_dir.join("report.json"))?;

    Ok(())
}
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
* `-d, --dry-run`: Run static analysis pipeline without emitting output files or launching the UI.

### 2. `rbat rules`

Inspect, validate, or generate custom JSON threat detection rules:

```bash
# Print an annotated example JSON rule template
rbat rules example

# Output the Draft-07 JSON Schema definition
rbat rules schema

# Validate all custom JSON rules in a directory against the schema
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

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
