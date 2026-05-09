pub use clap::Parser;
use std::path::PathBuf;

/// a rust based static binary analysis tool (This comment becomes the app's description)
#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
pub struct Cli {
    /// The path to the binary
    pub path: PathBuf,

    /// Turn on debugging information
    #[arg(short, long)]
    pub debug: bool,

    /// PDF output
    #[arg(short, long)]
    pub pdf: bool,

    /// CSV output
    #[arg(short, long)]
    pub csv: bool,
}
