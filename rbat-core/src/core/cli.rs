pub use clap::{ArgGroup, Parser};
use std::path::PathBuf;

/// a rust based static binary analysis tool.
#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None, group(
    ArgGroup::new("modes")
    .args(&["tui", "pdf", "csv", "json", "out_dir"])
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

    /// Output directory for reports (default: current directory)
    #[arg(short, long)]
    pub out_dir: Option<PathBuf>,
}
