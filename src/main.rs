use crate::types::App;
use crate::types::Cli;
use crate::utils::analyzer::analyzer;
use crate::utils::csv::generate_csv_report;
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

    if cli.pdf {
        let heatmap_svg =
            crate::utils::viz::generate_entropy_heatmap_svg(&analysis_result.section_entropy);
        generate_pdf_report(&cli.path, &assessment, "result.pdf", Some(heatmap_svg))?;
        println!("PDF report generated at result.pdf");
    }

    if cli.csv {
        generate_csv_report(&cli.path, &assessment, "result.csv")?
    }

    if cli.debug {
        ratatui::run(|terminal| App::new(analysis_result, assessment.clone()).run(terminal))?;
    }

    Ok(())
}
