# Contributing to RBAT

First off, thank you for taking the time to contribute to RBAT! We welcome contributions from everyone.

To ensure a productive and welcoming community, please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## How Can I Contribute?

### Reporting Bugs
* Check the existing issues to see if the bug has already been reported.
* If not, open a new issue. Include a clear title, detailed description, steps to reproduce, and the expected vs. actual behavior.

### Suggesting Enhancements
* Open an issue describing the proposed feature, why it is useful, and how it should work.

### Submitting Pull Requests (PRs)
1. **Fork the Repository**: Create a fork of the project on GitHub.
2. **Clone Locally**: Clone your fork to your development machine.
3. **Create a Branch**: Use a descriptive branch name (e.g., `feature/add-yara-rules` or `bugfix/issue-123`).
4. **Implement & Test**: Write clean, commented code and add tests verifying your changes.
5. **Format & Lint**:
   * Run `cargo fmt` to format Rust code.
   * Run `cargo clippy` to check for common lints and errors.
6. **Run Tests**: Ensure all tests pass with `cargo test`.
7. **Commit Changes**: Use clear, concise commit messages.
8. **Run Pre-Release Validation**: Run `./scripts/validate-release.sh` locally to ensure all integration and unit tests pass.
9. **Push & Open PR**: Push to your fork and submit a PR to the `master` branch.

## Development Setup

The workspace is structured as a Cargo workspace containing:
- `crates/rbat`: Core static analysis engine library.
- `crates/rbat-cli`: Terminal binary executable (`rbat`) with CLI subcommands and Ratatui TUI dashboard.
- `crates/xtask`: Developer automation CLI for rule bundling (`cargo xtask bundle-rules`).
- `fuzz`: LibFuzzer targets and seed generation scripts.

### Prerequisites
- [Rust](https://rustup.rs/) (Stable 1.75+)
- System packages: `libcapstone-dev`, `libyara-dev`, `pkg-config`

### Useful Commands
- Check compilation: `cargo check`
- Run tests: `cargo test`
- Check specific backend: `cargo check -p rbat --no-default-features --features backend-iced`
- Build release targets: `cargo build --release -p rbat-cli --bin rbat`
- Bundle capa rules: `cargo xtask bundle-rules`
- Run full pre-release validation: `./scripts/validate-release.sh`

## Code Style

- **Rust**: Follow the standard Rust style guides enforced by `rustfmt`.
- **Documentation**: Provide comments for public interfaces and functions where appropriate.
- **Commits**: Follow conventional commits where possible (e.g., `feat: ...`, `fix: ...`, `docs: ...`).
