pub use clap::{ArgGroup, Parser};
use std::path::PathBuf;

/// a rust based static binary analysis tool.
#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None, group(
    ArgGroup::new("output")
    .args(&["tui", "pdf", "csv", "json"])
    .required(true).multiple(true))
)]
pub struct Cli {
    /// The path to the binary
    pub path: PathBuf,

    /// TUI result display
    #[arg(short, long)]
    pub tui: bool,

    /// PDF output
    #[arg(short, long)]
    pub pdf: bool,

    /// CSV output
    #[arg(short, long)]
    pub csv: bool,

    /// JSON output
    #[arg(short, long)]
    pub json: bool,
}
