# rbat-cli

[![Crates.io Version](https://img.shields.io/crates/v/rbat-cli?style=for-the-badge&logo=rust&color=orange&label=version)](https://crates.io/crates/rbat-cli)
[![Crates.io Downloads](https://img.shields.io/crates/d/rbat-cli?style=for-the-badge&color=blue&label=downloads)](https://crates.io/crates/rbat-cli)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=for-the-badge)](https://opensource.org/licenses/Apache-2.0)
[![Build Status](https://img.shields.io/github/actions/workflow/status/Heritage-XioN/rbat/ci-rust.yml?style=for-the-badge&label=build)](https://github.com/Heritage-XioN/rbat/actions)
[![Rust MSRV](https://img.shields.io/badge/rustc-1.85+-orange.svg?style=for-the-badge&logo=rust)](https://blog.rust-lang.org/)

**rbat-cli** is the terminal-native binary analysis executable (`rbat`) and interactive Terminal User Interface (TUI) dashboard powered by the [`rbat`](../rbat/README.md) static analysis engine. Designed for security researchers, malware analysts, and reverse engineers, it provides automated executable triage, multi-backend disassembly, Control Flow Graph (CFG) extraction, Mandiant Capa rule evaluation, and calibrated Bayesian threat scoring directly in your terminal.

---

## Terminal Analysis Report

Running `rbat analyze` against a binary delivers an immediate cyber-noir summary report featuring format metadata, multi-algorithm cryptographic digests, locality-sensitive hashes (SSDEEP, TLSH), Bayesian threat severity meters, and categorized capability matches mapped to MITRE ATT&CK and Malware Behavior Catalog (MBC):

```text
$ rbat analyze al-khaser_x86.exe

 ██████╗  ██████╗   █████╗  ████████╗
██╔══██╗ ██╔══██╗ ██╔══██╗ ╚══██╔══╝
██████╔╝ ██████╔╝ ███████║    ██║   
██╔══██╗ ██╔══██╗ ██╔══██║    ██║   
██║  ██║ ██████╔╝ ██║  ██║    ██║   
╚═╝  ╚═╝ ╚═════╝  ╚═╝  ╚═╝    ╚═╝   

┌─────────────────────────────┬────────────────────────────────────────────────┐
│ RBAT STATIC ANALYSIS REPORT ┆ VALUE                                          │
╞═════════════════════════════╪════════════════════════════════════════════════╡
│ Target File                 ┆ al-khaser_x86.exe                              │
│ Binary Type                 ┆ Windows PE                                     │
│ Architecture                ┆ x86                                            │
│ Entry Point                 ┆ 0x41B252                                       │
│ MD5                         ┆ db648cd247281954344f1d810c6fd590               │
│ SHA-1                       ┆ a457931874ba395917da2ab060c02159f2c418ec       │
│ SHA-256                     ┆ faf351db4072395ca1e2855a379b120cdbccdb09131c48 │
│                             ┆ 463e30dccf4245f4bb                             │
│ SSDEEP                      ┆ 3072:9KyAkoHZmderbwS3cWrffxk4s5QZndPKfZTHS4wGB │
│                             ┆ SveSlK2mJXtk6ZxOspwIGO5:9xm5vXjN6rlqKcNyxNX2NP │
│                             ┆ zIxv                                           │
│ TLSH                        ┆ T106943C21AA84C475F5E302B7AEF494B548A4BC604BBD │
│                             ┆ 00F760C897DE8A6F3D11B36B57                     │
└─────────────────────────────┴────────────────────────────────────────────────┘

┌─────────────────┬────────────────────────┬───────────┬───────────────────────┐
│ RISK ASSESSMENT ┆ SCORE                  ┆ VERDICT   ┆ SUMMARY               │
╞═════════════════╪════════════════════════╪═══════════╪═══════════════════════╡
│ Threat Level    ┆ ██████████████░░░░░░   ┆ MALICIOUS ┆ 4 high · 3 low · 3    │
│                 ┆ (70%)                  ┆           ┆ capabilities          │
└─────────────────┴────────────────────────┴───────────┴───────────────────────┘

┌────────────┬────────────────────┬───────────┬───────────┬────────────────────┐
│ CLASS      ┆ CAPABILITY         ┆ ATT&CK    ┆ MBC       ┆ NAMESPACE          │
╞════════════╪════════════════════╪═══════════╪═══════════╪════════════════════╡
│ HIGH       ┆ reference analysis ┆ —         ┆ B0013.001 ┆ anti-analysis      │
│            ┆ tools strings      ┆           ┆           ┆                    │
│ HIGH       ┆ reference anti-VM  ┆ T1497.001 ┆ B0009     ┆ anti-analysis/anti │
│            ┆ strings targeting  ┆           ┆           ┆ -vm/vm-detection   │
│            ┆ Qemu               ┆           ┆           ┆                    │
│ HIGH       ┆ reference anti-VM  ┆ T1497.001 ┆ B0009     ┆ anti-analysis/anti │
│            ┆ strings targeting  ┆           ┆           ┆ -vm/vm-detection   │
│            ┆ VMWare             ┆           ┆           ┆                    │
│ HIGH       ┆ reference anti-VM  ┆ T1497.001 ┆ B0009     ┆ anti-analysis/anti │
│            ┆ strings targeting  ┆           ┆           ┆ -vm/vm-detection   │
│            ┆ VirtualBox         ┆           ┆           ┆                    │
│ LOW        ┆ contains PDB path  ┆ —         ┆ —         ┆ executable/pe/pdb  │
│ LOW        ┆ interact with      ┆ —         ┆ —         ┆ host-interaction/d │
│            ┆ driver via IOCTL   ┆           ┆           ┆ river              │
│ LOW        ┆ read raw disk data ┆ —         ┆ —         ┆ host-interaction/f │
│            ┆                    ┆           ┆           ┆ ile-system         │
│ CAPABILITY ┆ contain a thread   ┆ —         ┆ —         ┆ executable/pe/sect │
│            ┆ local storage      ┆           ┆           ┆ ion/tls            │
│            ┆ (.tls) section     ┆           ┆           ┆                    │
│ CAPABILITY ┆ execute command    ┆ —         ┆ C0017     ┆ host-interaction/p │
│            ┆                    ┆           ┆           ┆ rocess/create      │
│ CAPABILITY ┆ get file           ┆ —         ┆ C0049     ┆ host-interaction/f │
│            ┆ attributes         ┆           ┆           ┆ ile-system/meta    │
└────────────┴────────────────────┴───────────┴───────────┴────────────────────┘
  Analyzed 2026-11-05 13:48:32 · override classes via --severity-overrides

  [-] Total Analysis Time: 1.13s
  [*] Tip: Run with --tui for an interactive dashboard view or --cfg for Graphviz DOT format.
```

---

## Installation

### From Crates.io

```bash
cargo install rbat-cli
```

### From Source

Clone the repository and build the release binary:

```bash
git clone https://github.com/Heritage-XioN/rbat.git
cd rbat
cargo build --release -p rbat-cli

# The compiled binary is located at target/release/rbat
./target/release/rbat --version
```

---

## Key Features

* **Multi-Format Executable Ingestion**: Parses ELF (Linux), PE/COFF (Windows), and Mach-O (macOS) binaries in 32-bit and 64-bit architectures using `object`.
* **Pluggable Multi-Backend Disassembly**:
  * `iced` (pure Rust, default): High-throughput instruction decoding for x86 and x86_64.
  * `capstone` (default): Broad multi-architecture disassembly for x86, x64, ARM, AArch64 (ARM64), MIPS, and PowerPC.
  * Select backend at runtime using `--backend iced` or `--backend capstone`.
* **Control Flow Graph (CFG) Reconstruction**: Recovers basic blocks, classifies edges (`BranchTrue`, `BranchFalse`, `Jump`, `Call`), and calculates McCabe cyclomatic complexity. Emits Graphviz DOT format via `--cfg`.
* **Mandiant Capa Behavioral Rules**: Evaluates boolean condition trees (`and`, `or`, `not`, threshold counts, range matches, regex) across four execution scopes (`File`, `Function`, `BasicBlock`, `Instruction`).
* **FLIRT Compiler Identification**: Automatically identifies compiler runtime and standard library functions via `.sig` and `.pat` signatures to eliminate false-positive capability noise.
* **Calibrated Bayesian Threat Scoring**: Aggregates findings probabilistically via a Bayesian Noisy-OR formulation ($P = 1 - \prod(1 - p_i)$). Hostile corroborating indicators escalate threat scores asymptotically to 100 without artificial linear inflation.
* **Tunable Severity Overrides**: Demote or promote rule severities at runtime using `--severity-overrides <path.toml>`.
* **Interactive Terminal UI (TUI)**: Launch an interactive Ratatui dashboard (`--tui`) to explore disassembly streams, basic block graphs, entropy heatmaps, and finding trees.
* **Multi-Format Artifact Export**: Output structured reports in JSON (`--json`), CSV (`--csv`), or executive PDF (`--pdf`) formats.
* **Shell Auto-Completions**: Generate completion scripts for Bash, Zsh, Fish, PowerShell, and Elvish via `rbat completions`.

---

## CLI Reference

### 1. `rbat analyze <PATH>`

Analyze an executable binary file and display reports or launch the TUI:

```bash
# Standard terminal report
rbat analyze sample.exe

# Interactive TUI dashboard
rbat analyze sample.exe --tui

# Export Control Flow Graph to Graphviz DOT
rbat analyze sample.exe --cfg > sample_cfg.dot

# Generate JSON analysis report
rbat analyze sample.exe --json --out-dir ./reports

# Run with custom JSON rules and FLIRT signatures
rbat analyze sample.exe --rules ./custom_rules --signatures ./flirt_sigs

# Run with custom severity overrides table
rbat analyze sample.exe --severity-overrides ./custom-overrides.toml

# Specify disassembler backend engine
rbat analyze sample.exe --backend iced
rbat analyze firmware.bin --backend capstone

# Headless / Dry-run validation (no files written, exit code indicates success)
rbat analyze sample.exe --dry-run
```

#### Options:

| Flag / Option | Description |
| :--- | :--- |
| `<PATH>` | Path to the binary file to analyze (required). |
| `-t, --tui` | Launch the interactive Terminal User Interface (TUI) dashboard. |
| `-j, --json` | Generate a JSON dump of the raw analysis findings (requires `report-json`). |
| `-p, --pdf` | Generate an Executive Light-Mode PDF report (requires `report-pdf`). |
| `-c, --csv` | Generate a SIEM-ready CSV report (requires `report-csv`). |
| `-o, --out-dir <DIR>` | Output directory for report files (default: current directory). |
| `-d, --dry-run` | Run analysis pipeline without writing output files or launching the UI. |
| `-r, --rules <RULES>` | Directory containing custom JSON rules to load alongside embedded rules. |
| `-s, --signatures <DIR>` | Directory containing custom FLIRT signatures (`.sig` or `.pat` files). |
| `--severity-overrides <FILE>` | TOML file overriding severity classifications for rule names or namespaces. |
| `-b, --backend <BACKEND>` | Disassembly engine to use (`capstone`, `iced`) [aliases: `--disassembler`]. |
| `--cfg` | Output the Control Flow Graph (CFG) in Graphviz DOT format to `stdout`. |
| `-h, --help` | Print help information. |

---

### 2. `rbat rules`

Inspect, validate, or generate custom JSON security rules:

```bash
# Print an annotated example JSON rule template to stdout
rbat rules example

# Output the formal JSON Schema definition (Draft-07) to stdout
rbat rules schema

# Validate custom JSON rules in a directory against the formal schema
rbat rules validate --dir ./my_rules
```

#### Subcommands:

| Subcommand | Description |
| :--- | :--- |
| `example` | Print an annotated example JSON rule template to `stdout`. |
| `schema` | Output the formal JSON schema definition for RBAT rules to `stdout`. |
| `validate --dir <DIR>` | Validate custom JSON rule files in the specified directory. |

---

### 3. `rbat completions <SHELL>`

Generate shell completion scripts:

```bash
# Bash
rbat completions bash > ~/.local/share/bash-completion/completions/rbat

# Zsh
rbat completions zsh > ~/.zfunc/_rbat

# Fish
rbat completions fish > ~/.config/fish/completions/rbat.fish

# PowerShell
rbat completions powershell >> $PROFILE
```

---

## Feature Flags & Build Profiles

Feature flags in `Cargo.toml` control included disassembler backends and report generation engines:

| Feature Flag | Default | Description |
| :--- | :--- | :--- |
| `backend-iced` | Yes | Pure-Rust x86/x64 disassembler via `iced-x86`. |
| `backend-capstone` | Yes | Multi-architecture disassembler via Capstone C-FFI. |
| `report-json` | Yes | Structured JSON analysis report exporter. |
| `report-csv` | No | SIEM-ready CSV summary exporter via `csv`. |
| `report-pdf` | No | Executive PDF report generator via `fullbleed`, `askama`, and `lightningcss`. |
| `reports` | No | Convenience bundle enabling JSON, CSV, and PDF reporting. |
| `dhat-heap` | No | Heap profiling integration via `dhat`. |

### Custom Compilation Examples

```bash
# Pure-Rust lightweight build (x86/x64 only, zero C-FFI dependencies)
cargo build --release --no-default-features --features backend-iced,report-json

# Full reporting build (JSON, CSV, and PDF generation)
cargo build --release --features reports

# Minimal headless triage binary
cargo build --release --no-default-features --features backend-iced
```

---

## Related Projects

* [`rbat`](../rbat/README.md) -- Core static binary analysis and threat detection library.

---

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](../../LICENSE) file for details.
