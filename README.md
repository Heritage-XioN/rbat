# RBAT: Rust Binary Analysis Tool

![RBAT Logo](https://img.shields.io/badge/RBAT-Rust%20Binary%20Analysis%20Tool-orange?style=for-the-badge&logo=rust)
![Build Status](https://img.shields.io/badge/status-stable-green?style=for-the-badge)

**RBAT** is a high-performance, terminal-native binary analysis tool designed for security researchers, malware analysts, and reverse engineers. It provides a comprehensive suite of static analysis tools to identify potential threats, analyze binary structures, and evaluate risk levels across multiple executable formats.

---

## 🚀 Features

- **Multi-Format Support**: Native parsing for **ELF**, **PE**, and **Mach-O** binaries using `goblin`.
- **Dynamic Risk Scoring**: Heuristic-based risk assessment that calculates a threat level (0-100) based on entropy, suspicious imports, and behavior patterns.
- **Rich TUI Dashboard**: An interactive terminal interface built with `ratatui` for navigating findings, metadata, and security recommendations.
- **Entropy Heatmaps**: Visualizes section-level entropy to detect packed code, encrypted payloads, or hidden data.
- **YARA Integration**: Built-in scanning for packer signatures and suspicious patterns using customized, embedded YARA rules.
- **Multi-Format Reporting**: Export analysis results to professional **PDF** reports (with heatmaps), SOC-ready **CSV** logs, or **JSON** for automated pipelines.

## 🎓 Educational Value

RBAT is designed not just as a tool, but as a reference for learning binary internals:
- **Binary Internals**: Learn how headers, section tables, and symbol tables differ between ELF, PE, and Mach-O.
- **Static Analysis Techniques**: Understand how to identify "code caves," analyze import function associations, and detect API hooking signatures.
- **Information Theory**: Explore how Shannon Entropy is applied in security to differentiate between compressed, encrypted, and plaintext data.
- **Heuristic Modeling**: See how multiple low-confidence indicators can be combined into a high-confidence risk score.

## 📋 Prerequisites

- **Rust**: Version 1.75 or higher is recommended.
- **C Libraries**: 
  - `capstone` (for disassembly)
  - `libyara` (for pattern matching)
  - *Note: On most systems, these are handled automatically by Cargo or bundled via "vendored" features.*

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/Heritage-XioN/rbat.git
cd rbat

# Build the project
cargo build --release

# Run tests to verify setup
cargo test
```

## 📖 Usage

Analyze a binary directly in the interactive **TUI**:
```bash
./target/release/rbat <path_to_binary> --tui
```

Generate a professional **PDF report**:
```bash
./target/release/rbat <path_to_binary> --pdf
```

Export results to **CSV** or **JSON**:
```bash
./target/release/rbat <path_to_binary> --csv
./target/release/rbat <path_to_binary> --json
```

## ⚙️ Configuration

RBAT is designed to be a "zero-config" standalone tool:
- **Embedded Assets**: All YARA rules, blacklists, and CSS templates are embedded into the binary at compile-time using `rust-embed`.
- **CLI Flags**: Behavior is controlled entirely through command-line arguments (run `rbat --help` for details).

## 🏗️ Architecture

RBAT follows a modular pipeline architecture:
1. **Parser Layer**: Uses `goblin` to abstract away the differences between binary formats and extract raw bytes, entry points, and symbol data.
2. **Analysis Engine**: Orchestrates the analysis flow, feeding executable bytes to the **Disassembler (Capstone)** and the file buffer to the **YARA Scanner**.
3. **Scoring Engine**: Consumes all findings (entropy, suspicious APIs, packer matches) and applies a weighted heuristic to produce a `RiskAssessment`.
4. **Presentation Layer**: 
    - **TUI**: Provides a stateful, interactive dashboard.
    - **Reporters**: Uses `askama` templates and `fullbleed` to generate design-compliant documents.

## 📂 Project Structure

```text
rbat/
├── assets/             # Embedded YARA rules and suspicious pattern blacklists
├── src/
│   ├── main.rs         # Entry point and CLI orchestration
│   ├── rbat/           # Core library components
│   │   ├── parser.rs   # Binary format parsing (ELF/PE/Mach-O)
│   │   ├── tui.rs      # Ratatui-based interactive dashboard
│   │   └── ...
│   └── utils/          # Analysis and reporting utilities
│       ├── analyzer.rs # Analysis pipeline orchestration
│       ├── scoring.rs  # Risk assessment heuristic engine
│       ├── pdf.rs      # Askama/Fullbleed PDF reporting
│       └── ...
├── templates/          # HTML/CSS templates for generated reports
└── tests/              # Integration tests and binary generation helpers
```

## 🛡️ Security Considerations

- **Static Only**: RBAT performs static analysis. It does **not** execute the target binary, making it safe to use on unknown or potentially malicious files.
- **Local Privacy**: All analysis is performed locally on your machine. No data is sent to external servers or cloud services.
- **Heuristic Limits**: Risk scoring is based on common malware patterns. A high score indicates a need for manual review, while a low score does not guarantee the file is harmless.

## ⚖️ License

This project is licensed under the **MIT License**. See the `LICENSE` file for details.
