use crate::rbat::{cli::Cli, tui::App};
use crate::utils::pdf::generate_pdf_report;
use crate::utils::{analyzer::analyzer, csv::generate_csv_report, json::generate_json_report};
use clap::Parser;
use color_eyre::Result;

mod rbat;
mod utils;

fn main() -> Result<()> {
    color_eyre::install()?;
    // parses terminal arguments!
    let cli = Cli::parse();

    let (analysis_result, risk_assessment) = analyzer(&cli.path)?;

    let base_dir = cli.out_dir.unwrap_or_else(|| std::path::PathBuf::from("."));
    if base_dir.exists() {
        if !base_dir.is_dir() {
            return Err(color_eyre::eyre::eyre!(
                "The specified output directory '{}' exists but is not a directory.",
                base_dir.display()
            ));
        }
    } else {
        std::fs::create_dir_all(&base_dir)?;
    }

    if cli.pdf {
        let pdf_path = base_dir.join("report.pdf");
        generate_pdf_report(
            &cli.path,
            &risk_assessment,
            &analysis_result,
            &pdf_path.to_string_lossy(),
        )?;
    }

    if cli.csv {
        let csv_path = base_dir.join("report.csv");
        generate_csv_report(&cli.path, &risk_assessment, &csv_path.to_string_lossy())?;
    }

    if cli.json {
        let json_path = base_dir.join("report.json");
        generate_json_report(
            &cli.path,
            &risk_assessment,
            &analysis_result,
            &json_path.to_string_lossy(),
        )?;
    }

    if cli.tui {
        ratatui::run(|terminal| App::new(analysis_result, risk_assessment.clone()).run(terminal))?;
    }

    Ok(())
}
