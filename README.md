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
[![Client CI Status](https://img.shields.io/github/actions/workflow/status/Heritage-XioN/rbat/ci-client.yml?style=for-the-badge&label=client%20ci)](https://github.com/Heritage-XioN/rbat/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Rust MSRV](https://img.shields.io/badge/rustc-1.75+-orange.svg?style=for-the-badge&logo=rust)](https://blog.rust-lang.org/2023/12/28/Rust-1.75.0.html)
[![Node Version](https://img.shields.io/badge/node-%3E%3D20.0.0-green.svg?style=for-the-badge&logo=node.js)](https://nodejs.org)


RBAT (Rust Binary Analysis Tool) is a modern, high-performance static analysis and security auditing framework for compiled binaries.

## Workspace Structure

The project is organized as a Cargo workspace consisting of three primary components:

* **[rbat-core](rbat-core/README.md)**: The core static analysis engine. Written in Rust, it performs binary parsing (ELF, PE, Mach-O), entropy calculation, YARA rule matching, disassembling, and scoring. It also exposes the command-line interface (CLI) to run local audits.
* **[rbat-server](rbat-server/README.md)**: A high-performance gRPC server daemon wrapping the core engine to enable remote static analysis auditing services.
* **[rbat-client](rbat-client/README.md)**: A modern Next.js web application frontend dashboard providing interactive visualizations of binary analysis findings, entropy maps, and reports.

```text
rbat/
├── proto/               # gRPC Service Definition
├── rbat-core/           # Core Rust static analysis engine & CLI
├── rbat-server/         # gRPC server wrapper around the core engine
└── rbat-client/         # Next.js web application dashboard
```

## Roadmap

To advance **RBAT** toward an industry-standard binary static analysis platform, the following capabilities are planned for future releases:

1. **API Hashing Resolver:** Implement detection and parsing for common API hashing algorithms (e.g., CRC32, ROR13) and PEB walking patterns (like `fs:[0x30]` or `gs:[0x60]` on Windows/x86) to uncover dynamically resolved APIs.
2. **Control Flow Graph (CFG) Reconstruction:** Walk disassembled instructions to trace basic blocks, identify loops/jumps, and detect obfuscation techniques like control flow flattening.
3. **Static Emulation / Auto-Unpacking:** Integrate a lightweight emulation engine (such as Unicorn/Qiling) to run packed entry loops inside a safe sandbox to capture unpacked memory states automatically.
4. **MITRE ATT&CK Framework Mapping:** Link heuristic findings, blacklisted APIs, and YARA match rules to standardized MITRE ATT&CK technique IDs (e.g., *T1055 - Process Injection*) to generate standardized security reports.

## Contributing & Community

We welcome contributions of all forms. Please check the following resources to get started:

* **[Contributing Guidelines](CONTRIBUTING.md)**: Build instructions, PR workflow, and code style.
* **[Code of Conduct](CODE_OF_CONDUCT.md)**: Community standards and pledge of behavior.

## License

This project is licensed under the [MIT License](LICENSE).