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

* **[rbat-core](rbat-core/README.md)**: The core static analysis engine. Written in Rust, it performs binary parsing (ELF, PE, Mach-O), entropy calculation, YARA rule matching, disassembling, CFG graph reconstruction, and threat scoring. Exposes the subcommand CLI (`analyze`, `rules`, `completions`).
* **[rbat-server](rbat-server/README.md)**: A high-performance gRPC server daemon wrapping the core engine to enable remote static analysis auditing services.
* **[rbat-client](rbat-client/README.md)**: A modern Next.js web application frontend dashboard providing interactive visualizations of binary analysis findings, entropy maps, and reports.

```text
rbat/
├── proto/               # gRPC Service Definition
├── rbat-core/           # Core Rust static analysis engine & CLI
├── rbat-server/         # gRPC server wrapper around the core engine
└── rbat-client/         # Next.js web application dashboard
```

## Roadmap & Future Enhancements

To further advance **RBAT**, the following capabilities are planned for future major releases:

1. **Static Emulation / Auto-Unpacking Sandbox:** Integrate a lightweight emulation layer (such as Unicorn/Qiling engine bindings) to execute packed entry loops in a safe sandbox and capture unpacked memory payloads automatically.
2. **Symbolic Execution Assistance:** Provide lightweight path constraint solver integration to evaluate complex obfuscated jump targets.

## Contributing & Community

We welcome contributions of all forms. Please check the following resources to get started:

* **[Contributing Guidelines](CONTRIBUTING.md)**: Build instructions, PR workflow, and code style.
* **[Code of Conduct](CODE_OF_CONDUCT.md)**: Community standards and pledge of behavior.

## License

This project is licensed under the [MIT License](LICENSE).
