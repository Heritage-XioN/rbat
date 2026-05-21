use clap::Parser;
use color_eyre::Result;
use indicatif::{ProgressBar, ProgressStyle};
use rbat::{
    core::{
        AnalysisResult, analyzer::analyze_streaming, cli::Cli, tui::App, types::AnalysisProgress,
    },
    utils::{
        csv::generate_csv_report, json::generate_json_report, pdf::generate_pdf_report,
        scoring::calculate_risk,
    },
};
use std::sync::mpsc;
use std::time::Duration;
use tui_banner::{Banner, Style};

fn main() -> Result<()> {
    color_eyre::install()?;
    // parses terminal arguments!
    let cli = Cli::parse();
    let mv_path = cli.path.clone();

    // Generate and display banner
    let banner = Banner::new("RBAT")?.style(Style::NeonCyber).render();
    println!("\n {}", banner);

    // progress indicator
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::with_template("{spinner:.cyan} [{elapsed_precise}] {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", "✓"]),
    );
    spinner.enable_steady_tick(Duration::from_millis(100));
    spinner.set_message("Starting binary analysis...");

    let (tx, rx) = mpsc::channel();

    // this just runs the streaming analysis on a separate thread so the main thread
    // is free to consume the channel and update the progress spinner.
    let analysis_thread = std::thread::spawn(move || {
        analyze_streaming(&mv_path, move |event| {
            let _ = tx.send(event);
        })
    });

    let mut analysis_result = AnalysisResult::default();

    // analysis progress event loop,
    // updates the progress spinner with real-time feedback from the analysis process.
    for event in rx {
        match event {
            AnalysisProgress::Disassembly((code_cave, blacklisted_mnemonics)) => {
                analysis_result.code_cave = code_cave.clone();
                analysis_result.blacklisted_mnemonics = blacklisted_mnemonics.clone();
                spinner.set_message(format!(
                    "Disassembly complete found {:#?} code cave and {:#?} blacklisted mnemonics",
                    code_cave.len(),
                    blacklisted_mnemonics.len()
                ))
            }
            AnalysisProgress::Strings(string_values) => {
                analysis_result.string_values = string_values.clone();
                spinner.set_message(format!("Found {} strings...", string_values.len()))
            }
            AnalysisProgress::PackerSigs(packer_signatures) => {
                analysis_result.packer_signatures = packer_signatures.clone();
                spinner.set_message(format!("Found {} packers...", packer_signatures.len()))
            }
            AnalysisProgress::Entropy(section_entropy) => {
                analysis_result.section_entropy = section_entropy.clone();
                spinner.set_message(format!(
                    "calculated entropy of {} sections...",
                    section_entropy.len()
                ))
            }
            AnalysisProgress::ApiHooking(api_hooking) => {
                analysis_result.api_hooking = api_hooking.clone();
                spinner.set_message(format!("Found {} api hookers...", api_hooking.len()))
            }
            AnalysisProgress::ProcessInjection(process_injection) => {
                analysis_result.process_injection = process_injection.clone();
                spinner.set_message(format!(
                    "Found {} process injecters...",
                    process_injection.len()
                ))
            }
            AnalysisProgress::BinaryMetadata(metadata) => analysis_result.metadata = metadata,
        }
    }

    // computes risk assessment
    let risk_assessment = calculate_risk(
        &analysis_result.section_entropy,
        analysis_result
            .string_values
            .values()
            .map(|v| v.len())
            .sum(),
        analysis_result.api_hooking.len(),
        analysis_result.process_injection.len(),
        !analysis_result.code_cave.is_empty(),
        !analysis_result.packer_signatures.is_empty(),
    );

    // checks for error onces analysis to fully complete
    match analysis_thread.join().unwrap() {
        Ok(_) => spinner.finish_with_message("Analysis complete! 🚀\n"),
        Err(e) => {
            spinner.finish_with_message("Analysis failed! ❌\n");
            eprintln!("Error: {:?}", e);
        }
    }

    // output directory
    let base_dir = cli.out_dir.unwrap_or_else(|| std::path::PathBuf::from("."));
    if base_dir.exists() && !base_dir.is_dir() {
        return Err(color_eyre::eyre::eyre!(
            "The specified output directory '{}' exists but is not a directory.",
            base_dir.display()
        ));
    } else {
        std::fs::create_dir_all(&base_dir)?;
    }

    // PDF report generation
    if cli.pdf {
        let pdf_path = base_dir.join("report.pdf");
        generate_pdf_report(&cli.path, &risk_assessment, &analysis_result, &pdf_path)?;
    }

    // CSV report generation
    if cli.csv {
        let csv_path = base_dir.join("report.csv");
        generate_csv_report(&cli.path, &risk_assessment, &csv_path)?;
    }

    // JSON report generation
    if cli.json {
        let json_path = base_dir.join("report.json");
        generate_json_report(&cli.path, &risk_assessment, &analysis_result, &json_path)?;
    }

    // TUI report display
    if cli.tui {
        ratatui::run(|terminal| App::new(analysis_result, risk_assessment.clone()).run(terminal))?;
    }

    // dry run mode(analyzes but does not display anything)
    if cli.dry_run {
        println!("[+] Dry run complete");
    }

    Ok(())
}
