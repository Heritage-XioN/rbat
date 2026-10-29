```bash
        ██████╗ ██████╗  █████╗ ████████╗
        ██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝
        ██████╔╝██████╔╝███████║   ██║   
        ██╔══██╗██╔══██╗██╔══██║   ██║   
        ██║  ██║██████╔╝██║  ██║   ██║   
        ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝   ╚═╝   
```

[![Crates.io Version](https://img.shields.io/crates/v/rbat?style=for-the-badge&logo=rust&color=orange&label=core%20version)](https://crates.io/crates/rbat)
[![Crates.io Downloads](https://img.shields.io/crates/d/rbat?style=for-the-badge&color=blue&label=downloads)](https://crates.io/crates/rbat)
[![Rust CI Status](https://img.shields.io/github/actions/workflow/status/Heritage-XioN/rbat/ci-rust.yml?style=for-the-badge&label=rust%20ci)](https://github.com/Heritage-XioN/rbat/actions)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=for-the-badge)](https://opensource.org/licenses/Apache-2.0)
[![Rust MSRV](https://img.shields.io/badge/rustc-1.75+-orange.svg?style=for-the-badge&logo=rust)](https://blog.rust-lang.org/2023/12/28/Rust-1.75.0.html)

RBAT (Rust Binary Analysis Tool) is a modern, high-performance static analysis and security auditing framework for compiled binaries.

## Workspace Structure

The project is organized as a Cargo workspace:

* **[crates/rbat](crates/rbat)**: The core static analysis engine library. Written in Rust, it performs binary parsing (ELF, PE, Mach-O), entropy calculation, YARA rule matching, FLIRT signature matching, disassembling (via `backend-capstone` and `backend-iced` feature flags), CFG graph reconstruction, and threat scoring against MITRE ATT&CK categories using a native JSON & YAML CAPA-compatible rule engine.
* **[crates/rbat-cli](crates/rbat-cli)**: The terminal-native CLI binary executable (`rbat`) and Ratatui interactive TUI dashboard (`analyze`, `rules`, `completions`, `--tui`).
* **[crates/xtask](crates/xtask)**: Developer automation CLI for pre-compiling Capa rules and repository maintenance (`cargo xtask bundle-rules`).

```text
rbat/
├── crates/
│   ├── rbat/               # Core static analysis library engine
│   ├── rbat-cli/           # Terminal binary & TUI dashboard
│   └── xtask/              # Developer automation & rule precompilation
└── fuzz/                   # Fuzz targets & seed corpora
```

## Roadmap & Future Enhancements

To further advance **RBAT**, the following capabilities are planned for future major releases:

1. **Static Emulation / Auto-Unpacking Sandbox:** Integrate a lightweight emulation layer (such as Unicorn/Qiling engine bindings) to execute packed entry loops in a safe sandbox and capture unpacked memory payloads automatically.
2. **Symbolic Execution Assistance(not sure how to go about it yet):** Provide lightweight path constraint solver integration to evaluate complex obfuscated jump targets.

## Contributing & Community

We welcome contributions of all forms. Please check the following resources to get started:

* **[Contributing Guidelines](CONTRIBUTING.md)**: Build instructions, PR workflow, and code style.
* **[Code of Conduct](CODE_OF_CONDUCT.md)**: Community standards and pledge of behavior.

## License

This project is licensed under the [Apache License 2.0](LICENSE).
