//! # Command Line Interface Definitions
//!
//! This module defines the command-line options and arguments for the RBAT CLI
//! using the `clap` library.

pub use clap::{ArgGroup, Parser};
use std::path::PathBuf;

/// The command-line parser structure for the RBAT application.
#[derive(Parser, Debug, Clone)]
#[command(version, about = "A Rust-based static binary analysis tool", long_about = None, group(
    ArgGroup::new("modes")
    .args(&["tui", "pdf", "csv", "json", "out_dir", "dry_run"])
    .required(true).multiple(true))
)]
pub struct Cli {
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

    /// Optional target output directory for report generation. Defaults to the current directory.
    #[arg(short, long)]
    pub out_dir: Option<PathBuf>,

    /// Run the analysis internally without emitting any UI or report files.
    #[arg(short, long)]
    pub dry_run: bool,
}
