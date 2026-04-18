#![allow(unused)] // dont forget to remove

use clap::Parser;

use crate::prelude::Result;
use crate::types::Cli;
use crate::utils::analyzer::analyzer;
mod error;
mod prelude;
mod traits;
mod types;
mod utils;

fn main() -> Result<()> {
    // parses terminal arguments!
    let cli = Cli::parse();

    if cli.debug {
        println!("Debug mode is ON.");
    }

    analyzer(cli.path);
    Ok(())
}
