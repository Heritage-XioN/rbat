use crate::rbat::cli::Cli;
use crate::rbat::tui::App;
use crate::utils::analyzer::analyzer;
use crate::utils::csv::generate_csv_report;
use crate::utils::pdf::generate_pdf_report;
use clap::Parser;
use color_eyre::Result;

mod error;
mod rbat;
mod utils;

fn main() -> Result<()> {
    color_eyre::install()?;
    // parses terminal arguments!
    let cli = Cli::parse();
    let (analysis_result, assessment) = analyzer(&cli.path)?;
    println!("{:#?} \n {:#?}", analysis_result, assessment); 

    if cli.pdf {
        let heatmap_svg =
            crate::utils::viz::generate_entropy_heatmap_svg(&analysis_result.section_entropy);
        generate_pdf_report(
            &cli.path,
            &assessment,
            &analysis_result,
            "result.pdf",
            heatmap_svg,
        )?;
    }

    if cli.csv {
        generate_csv_report(&cli.path, &assessment, "result.csv")?
    }

    if cli.debug {
        ratatui::run(|terminal| App::new(analysis_result, assessment.clone()).run(terminal))?;
    }

    Ok(())
}
