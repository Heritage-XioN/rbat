use crate::types::App;
use crate::types::Cli;
use crate::utils::analyzer::analyzer;
use crate::utils::pdf::generate_pdf_report;
use clap::Parser;
use color_eyre::Result;

mod error;
mod prelude;
mod traits;
mod types;
mod utils;

fn main() -> Result<()> {
    color_eyre::install()?;
    // parses terminal arguments!
    let cli = Cli::parse();
    let (analysis_result, assessment) = analyzer(&cli.path)?;
    println!("assessment: {:#?}", assessment);
    println!("analysis result: {:#?}", &analysis_result);
    if cli.debug {
        ratatui::run(|terminal| App::new(analysis_result, assessment.clone()).run(terminal))?;
    }
    // generate_pdf_report(&cli.path, &assessment, "result.pdf", "./".into())?;
    Ok(())
}
