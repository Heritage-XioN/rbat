use crate::rbat::{cli::Cli, tui::App};
use crate::utils::pdf::generate_pdf_report;
use crate::utils::{analyzer::analyzer, csv::generate_csv_report};
use clap::Parser;
use color_eyre::Result;

mod rbat;
mod utils;

fn main() -> Result<()> {
    color_eyre::install()?;
    // parses terminal arguments!
    let cli = Cli::parse();
    let (analysis_result, assessment) = analyzer(&cli.path)?;

    if cli.pdf {
        generate_pdf_report(&cli.path, &assessment, &analysis_result, "report.pdf")?;
    }

    if cli.csv {
        generate_csv_report(&cli.path, &assessment, "result.csv")?
    }

    if cli.json {
        println!("json output")
    }

    if cli.tui {
        ratatui::run(|terminal| App::new(analysis_result, assessment.clone()).run(terminal))?;
    }

    Ok(())
}
