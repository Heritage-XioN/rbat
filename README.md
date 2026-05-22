```bash
██████╗ ██████╗  █████╗ ████████╗
██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝
██████╔╝██████╔╝███████║   ██║   
██╔══██╗██╔══██╗██╔══██║   ██║   
██║  ██║██████╔╝██║  ██║   ██║   
╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝   ╚═╝   
```

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

## Contributing & Community

We welcome contributions of all forms. Please check the following resources to get started:

* **[Contributing Guidelines](CONTRIBUTING.md)**: Build instructions, PR workflow, and code style.
* **[Code of Conduct](CODE_OF_CONDUCT.md)**: Community standards and pledge of behavior.

## License

This project is licensed under the [MIT License](LICENSE).