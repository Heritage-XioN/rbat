# rbat

[![Crates.io Version](https://img.shields.io/crates/v/rbat?style=for-the-badge&logo=rust&color=orange&label=version)](https://crates.io/crates/rbat)
[![Crates.io Downloads](https://img.shields.io/crates/d/rbat?style=for-the-badge&color=blue&label=downloads)](https://crates.io/crates/rbat)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/github/actions/workflow/status/Heritage-XioN/rbat/ci.yml?style=for-the-badge&label=build)](https://github.com/Heritage-XioN/rbat/actions)
[![Rust MSRV](https://img.shields.io/badge/rustc-1.75+-orange.svg?style=for-the-badge&logo=rust)](https://blog.rust-lang.org/2023/12/28/Rust-1.75.0.html)

**rbat** is a high-performance, terminal-native binary analysis tool designed for security researchers, malware analysts, and reverse engineers. It provides a comprehensive suite of static analysis tools to identify potential threats, analyze binary structures, and evaluate risk levels across multiple executable formats.

---

## Features

* Multi-Format Support: Native parsing for ELF, PE, and Mach-O binaries.
* Dynamic Risk Scoring: Heuristic-based risk assessment that calculates a threat level based on entropy, suspicious imports, and behavior patterns.
* Rich TUI Dashboard: An interactive terminal interface for navigating findings, metadata, and security recommendations.
* Entropy Heatmaps: Visualizes section-level entropy to detect packed code, encrypted payloads, or hidden data.
* YARA Integration: Built-in scanning for packer signatures and suspicious patterns using customized, embedded YARA rules.
* Multi-Format Reporting: Export analysis results to PDF reports (with heatmaps), CSV logs, or JSON for automated pipelines.

---

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
rbat = "0.2.0"
```

---

## Quick Start

The following is a minimal example demonstrating how to run a programmatic static analysis on a target binary and retrieve its risk assessment score:

```rust
use std::path::Path;
use rbat::core::analyzer::analyze_batch;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new("path/to/binary");
    let (analysis_result, risk_assessment) = analyze_batch(path)?;

    println!("Analysis complete for: {}", analysis_result.metadata.binary_type);
    println!("Threat Score: {}/100", risk_assessment.score);
    println!("Severity: {}", risk_assessment.severity);

    Ok(())
}
```

---

## Usage Examples

### Programmatic Streaming Analysis

You can consume analysis updates as they occur (e.g., to feed a progress bar or custom logger) using `analyze_streaming`:

```rust
use std::path::Path;
use rbat::core::analyzer::analyze_streaming;
use rbat::core::types::AnalysisProgress;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new("path/to/binary");

    analyze_streaming(path, |event| match event {
        AnalysisProgress::BinaryMetadata(meta) => {
            println!("Target platform: {}", meta.binary_type);
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

    // PDF Report
    generate_pdf_report(binary_path, &score, &result, &out_dir.join("report.pdf"))?;

    // CSV Report
    generate_csv_report(binary_path, &score, &out_dir.join("report.csv"))?;

    // JSON Report
    generate_json_report(binary_path, &score, &result, &out_dir.join("report.json"))?;

    Ok(())
}
```

### CLI Mode

Alternatively, run `rbat` as a command-line application.

Analyze a binary and display the interactive dashboard:
```bash
rbat <path_to_binary> --tui
```

Generate reports and save them to a directory:
```bash
rbat <path_to_binary> --pdf --csv --json --out-dir ./reports
```
---
## Links

* [Documentation (docs.rs)](https://docs.rs/rbat)
* [Repository (GitHub)](https://github.com/Heritage-XioN/rbat)
* [Contributing Guide](../CONTRIBUTING.md)

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
