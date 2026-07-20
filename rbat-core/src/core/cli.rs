//! # Command Line Interface Definitions
//!
//! This module defines the subcommand hierarchy and options for the RBAT CLI
//! using `clap`, styled with custom ANSI colors matching the RBAT design system.

pub use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Custom ANSI styles for clap CLI help menus
pub fn cli_styles() -> clap::builder::styling::Styles {
    use clap::builder::styling::{AnsiColor, Style, Styles};

    Styles::styled()
        .header(
            Style::new()
                .bold()
                .underline()
                .fg_color(Some(AnsiColor::Magenta.into())),
        )
        .usage(
            Style::new()
                .bold()
                .fg_color(Some(AnsiColor::Magenta.into())),
        )
        .literal(Style::new().bold().fg_color(Some(AnsiColor::Cyan.into())))
        .placeholder(Style::new().fg_color(Some(AnsiColor::BrightBlack.into())))
        .valid(Style::new().bold().fg_color(Some(AnsiColor::Green.into())))
        .invalid(Style::new().bold().fg_color(Some(AnsiColor::Red.into())))
}

/// The top-level command-line parser for the RBAT application.
#[derive(Parser, Debug, Clone)]
#[command(
    name = "rbat",
    version,
    about = "A terminal-native static binary analysis tool for security researchers",
    long_about = "RBAT performs static analysis on ELF,
    PE, and Mach-O binaries to reconstruct Control Flow Graphs, scan YARA rules, calculate entropy,
    detect code caves, and compute threat risk scores.",
    styles = cli_styles()
)]
pub struct Cli {
    /// Subcommand to execute (`analyze` or `rules`).
    #[command(subcommand)]
    pub command: Commands,
}

/// Subcommands supported by RBAT.
#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Analyze an executable binary file
    Analyze(AnalyzeArgs),
    /// Inspect, validate, or generate custom JSON security rules
    Rules(RulesArgs),
}

/// Arguments for the `rbat analyze` subcommand.
#[derive(Parser, Debug, Clone)]
#[command(styles = cli_styles())]
pub struct AnalyzeArgs {
    /// Path to the binary file to analyze.
    pub path: PathBuf,
    /// Run the interactive Terminal User Interface (TUI) dashboard.
    #[arg(short, long)]
    pub tui: bool,
    /// Generate a PDF report of the analysis findings.
    #[arg(short, long)]
    pub pdf: bool,
    /// Generate a CSV summary of the analysis findings.
    #[arg(short, long)]
    pub csv: bool,
    /// Generate a JSON dump of the raw analysis findings.
    #[arg(short, long)]
    pub json: bool,
    /// Output directory for report generation. Defaults to current directory.
    #[arg(short, long)]
    pub out_dir: Option<PathBuf>,
    /// Run analysis without UI or report output files.
    #[arg(short, long)]
    pub dry_run: bool,
    /// Optional directory containing custom JSON rules to load alongside embedded rules.
    #[arg(short, long)]
    pub rules: Option<PathBuf>,
    /// Output the Control Flow Graph (CFG) in Graphviz DOT format to stdout.
    #[arg(long)]
    pub cfg: bool,
}

/// Arguments for the `rbat rules` subcommand.
#[derive(Parser, Debug, Clone)]
#[command(styles = cli_styles())]
pub struct RulesArgs {
    /// Rule action subcommand (`example`, `schema`, or `validate`).
    #[command(subcommand)]
    pub action: RulesAction,
}

/// Subcommands under `rbat rules`.
#[derive(Subcommand, Debug, Clone)]
pub enum RulesAction {
    /// Print an annotated example JSON rule template to stdout
    Example,
    /// Output the formal JSON schema definition for RBAT rules to stdout
    Schema,
    /// Validate custom JSON rule files in a directory
    Validate {
        /// Directory containing JSON rule files to validate
        #[arg(short, long)]
        dir: PathBuf,
    },
}
