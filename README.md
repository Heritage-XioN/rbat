# RBAT: Rust Binary Analysis Tool

![RBAT Logo](https://img.shields.io/badge/RBAT-Rust%20Binary%20Analysis%20Tool-orange?style=for-the-badge&logo=rust)
![Build Status](https://img.shields.io/badge/status-stable-green?style=for-the-badge)

**RBAT** is a high-performance, terminal-native binary analysis tool designed for security researchers and reverse engineers. It provides a comprehensive suite of static analysis tools to identify potential threats, analyze binary structure, and evaluate risk levels across multiple executable formats.

---

## 🚀 Key Features

- **Multi-Format Support**: Native parsing for **ELF**, **PE**, and **Mach-O** binaries.
- **Dynamic Risk Scoring**: Heuristic-based risk assessment that calculates a threat level based on entropy, imports, and suspicious patterns.
- **TUI Dashboard**: A rich, interactive Terminal User Interface (TUI) for navigating findings, metadata, and security recommendations.
- **Entropy Heatmaps**: Visualizes section-level entropy to detect packed code, encrypted payloads, or hidden data.
- **YARA Integration**: Built-in scanning for packer signatures and suspicious string patterns using customized YARA rules.
- **Automated Reporting**: Export analysis results to professional **PDF** reports (with heatmaps) or SOC-ready **CSV** logs.

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/Heritage-XioN/rbat.git
cd rbat

# Build the project
cargo build --release

# Run tests
cargo test
```

## 📖 Usage

Analyze a binary directly in the TUI:
```bash
rbat <path_to_binary> --tui
```

Generate a PDF report:
```bash
rbat <path_to_binary> --pdf
```

Export results to CSV:
```bash
rbat <path_to_binary> --csv
```

## 💪 Strengths

- **Performance**: Built with Rust, RBAT is extremely fast and has a minimal memory footprint.
- **Visual Clarity**: Uses a pixel-perfect TUI and SVG-based heatmaps to make complex data readable.
- **Portability**: Standalone binary with no complex dependencies (uses `fullbleed` for PDF generation without Chromium).
- **Automation Ready**: CLI flags make it easy to integrate into CI/CD pipelines or automated malware analysis sandboxes.

## ⚠️ Limitations & Scope

- **Static Analysis Only**: RBAT does not execute the binary. It cannot detect runtime behavior, anti-debugging tricks that trigger only during execution, or late-stage payload downloads.
- **Deobfuscation**: While RBAT detects packers, it does not currently provide automated unpacking or deobfuscation capabilities.
- **Heuristics**: Risk scoring is based on common malware indicators. High scores do not always mean a file is malicious (False Positives), and low scores do not guarantee safety (False Negatives).

## 🛡️ Security & Privacy

RBAT performs all analysis locally on your machine. No data is sent to external servers or cloud services.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit Pull Requests or open issues for feature requests and bug reports.

## ⚖️ License

[Specify License, e.g., MIT or Apache 2.0]
