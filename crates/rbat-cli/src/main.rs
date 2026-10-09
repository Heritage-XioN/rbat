//! # RBAT CLI Executable Entry Point
//!
//! This module provides the main entry point for the `rbat` command-line executable.
//! It handles subcommand dispatch (`analyze`, `rules`, `completions`), manages the streaming
//! static analysis pipeline, displays terminal progress bars and TrueColor reports, and invokes
//! the Ratatui interactive TUI dashboard.

mod cli;
mod report;
mod rules;
mod tui;

use clap::Parser;
use color_eyre::Result;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::PathBuf;
use std::time::Duration;
use std::{fs, sync::mpsc};
use tui_banner::Banner;

use crate::cli::{AnalyzeArgs, Cli, Commands, CompletionsArgs, RulesAction, RulesArgs};
use crate::report::{
    generate_csv_report, generate_json_report, generate_pdf_report, print_terminal_report,
};
use crate::rules::{print_rule_example, print_rule_schema, validate_rules_directory};
use crate::tui::App;
use rbat::prelude::*;

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn main() -> Result<()> {
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();

    color_eyre::install()?;
    let cli = Cli::parse();

    match cli.command {
        Commands::Analyze(args) => run_analyze(args),
        Commands::Rules(args) => run_rules(args),
        Commands::Completions(args) => run_completions(args),
    }
}

fn run_completions(args: CompletionsArgs) -> Result<()> {
    use clap::CommandFactory;
    let mut cmd = Cli::command();
    clap_complete::generate(args.shell, &mut cmd, "rbat", &mut std::io::stdout());
    Ok(())
}

fn run_rules(args: RulesArgs) -> Result<()> {
    match args.action {
        RulesAction::Example => {
            print_rule_example();
            Ok(())
        }
        RulesAction::Schema => {
            print_rule_schema();
            Ok(())
        }
        RulesAction::Validate { dir } => validate_rules_directory(&dir),
    }
}

fn run_analyze(args: AnalyzeArgs) -> Result<()> {
    // ========================================================
    // Display ASCII banner, read buffer and setup channel
    // ========================================================
    let spinner = ascii_banner_progress_setup(&args)?;
    let buffer = fs::read(&args.path)?;
    let (tx, rx) = mpsc::channel();

    // =====================================================
    // Build the analyzer
    // =====================================================
    let mut builder = Analyzer::builder();
    if let Some(ref path) = args.severity_overrides {
        builder = builder.with_classifier(path)?;
    }
    if let Some(ref path) = args.signatures {
        builder = builder.with_flirt(path)?;
    }
    if let Some(ref path) = args.rules {
        builder = builder.with_rules(path);
    }
    let analyzer = builder.build();

    // =====================================================
    // Begin analysis in streaming mode
    // =====================================================
    let start_time = std::time::Instant::now();
    let result = analyzer.streaming(buffer.as_ref(), move |event| {
        let _ = tx.send(event);
    });

    // =====================================================
    // Collect and emit progress events
    // =====================================================
    let mut analysis_result = AnalysisResult::default();
    for event in rx {
        match event {
            AnalysisProgress::Hashes(hashes) => {
                analysis_result.hashes = hashes;
                spinner.set_message("Computed binary digests & fuzzy hashes");
            }
            AnalysisProgress::Disassembly(code_cave) => {
                analysis_result.code_cave = code_cave;
                spinner.set_message(format!(
                    "Disassembled section (code caves: {})",
                    analysis_result.code_cave.len()
                ));
            }
            AnalysisProgress::Strings(string_values) => {
                let len = string_values.len();
                analysis_result.string_values = string_values;
                spinner.set_message(format!("Extracted {} suspicious string matches", len));
            }
            AnalysisProgress::PackerSigs(packer_signatures) => {
                let len = packer_signatures.len();
                analysis_result.packer_signatures = packer_signatures;
                spinner.set_message(format!("Identified {} packer signatures", len));
            }
            AnalysisProgress::Entropy(section_entropy) => {
                analysis_result.section_entropy = section_entropy;
                spinner.set_message(format!(
                    "Calculated Shannon entropy for {} sections",
                    analysis_result.section_entropy.len()
                ));
            }
            AnalysisProgress::Imports(imports) => {
                analysis_result.imports = imports;
                spinner.set_message(format!(
                    "Extracted {} imported symbols",
                    analysis_result.imports.len()
                ));
            }
            AnalysisProgress::Exports(exports) => {
                analysis_result.exports = exports;
                spinner.set_message(format!(
                    "Extracted {} exported symbols",
                    analysis_result.exports.len()
                ));
            }
            AnalysisProgress::BinaryMetadata(metadata) => {
                analysis_result.metadata = metadata;
                spinner.set_message("Parsed binary headers & section bounds");
            }
            AnalysisProgress::CFG(cfg) => {
                analysis_result.cfg = Some(cfg);
                spinner.set_message("Reconstructed Control Flow Graph");
            }
            AnalysisProgress::LibraryFunctions(library_functions) => {
                analysis_result.library_functions = library_functions;
                spinner.set_message(format!(
                    "Matched {} library functions via FLIRT",
                    analysis_result.library_functions.len()
                ));
            }
        }
    }

    // ========================================================
    // Post analysis result check
    // ========================================================
    match result {
        Ok(_) => {
            spinner.set_message("Plugin analysis complete!");
        }
        Err(e) => {
            spinner.finish_with_message("Analysis failed! ❌");
            return Err(color_eyre::eyre::eyre!(e));
        }
    }

    spinner.set_message(format!(
        "Evaluating binary against {} capa rules...",
        analyzer.rules().len()
    ));

    if let Some(ref mut cfg) = analysis_result.cfg {
        analyzer.needle().populate_cfg(cfg);
    }

    // ========================================================
    // Construct featureset and evaluate against loaded rules
    // ========================================================
    let features = FeatureSet::new(&analysis_result, &buffer);
    let matched_rules = Rule::evaluate(&features, analyzer.rules(), analyzer.needle());
    let risk_assessment = RiskAssessment::calculate_risk(&matched_rules, analyzer.classifier());

    let elapsed = start_time.elapsed();
    analysis_result.total_analysis_time_ms = elapsed.as_millis();
    spinner.finish_with_message(format!("Analysis completed in {:.2?}! ✅", elapsed));

    // ========================================================
    // Output method and renderers
    // ========================================================
    let base_dir = args.out_dir.unwrap_or_else(|| PathBuf::from("."));
    if base_dir.exists() && !base_dir.is_dir() {
        return Err(color_eyre::eyre::eyre!(
            "The specified output directory '{}' exists but is not a directory.",
            base_dir.display()
        ));
    } else {
        std::fs::create_dir_all(&base_dir)?;
    }

    let mut generated_reports: Vec<(&str, PathBuf)> = Vec::new();

    // PDF report generation
    if args.pdf {
        let pdf_path = base_dir.join("report.pdf");
        generate_pdf_report(&args.path, &risk_assessment, &analysis_result, &pdf_path)?;
        generated_reports.push(("PDF", pdf_path));
    }

    // CSV report generation
    if args.csv {
        let csv_path = base_dir.join("report.csv");
        generate_csv_report(&args.path, &risk_assessment, &analysis_result, &csv_path)?;
        generated_reports.push(("CSV", csv_path));
    }

    // JSON report generation
    if args.json {
        let json_path = base_dir.join("report.json");
        generate_json_report(&args.path, &risk_assessment, &analysis_result, &json_path)?;
        generated_reports.push(("JSON", json_path));
    }

    let report_refs: Vec<(&str, &std::path::Path)> = generated_reports
        .iter()
        .map(|(fmt, path)| (*fmt, path.as_path()))
        .collect();

    // Output routing
    if args.cfg {
        if let Some(cfg) = &analysis_result.cfg {
            println!("{}", cfg.to_dot());
        } else {
            return Err(color_eyre::eyre::eyre!(
                "Control Flow Graph reconstruction failed or was unavailable."
            ));
        }
    }

    if args.tui {
        ratatui::run(|terminal| App::new(analysis_result, risk_assessment).run(terminal))?;
    } else if args.dry_run {
        println!("[+] Dry run complete.");
    } else if !args.cfg {
        print_terminal_report(&args.path, &analysis_result, &risk_assessment, &report_refs);
    }

    Ok(())
}

fn ascii_banner_progress_setup(args: &AnalyzeArgs) -> Result<ProgressBar> {
    if !args.cfg {
        let font = tui_banner::Font::from_figlet_str(include_str!("../assets/ansishadow.flf"))
            .map_err(|e| color_eyre::eyre::eyre!("Failed to parse ANSI Shadow font: {:?}", e))?;
        let banner = Banner::new("RBAT")?
            .font(font)
            .gradient(tui_banner::Gradient::vertical(
                tui_banner::Palette::from_hex(&[
                    "#e879a8", // Pink (gradient endpoint)
                    "#c084fc", // Purple-400 (--rbat-accent)
                    "#a855f7", // Purple-500 (chart-2)
                    "#7c3aed", // Violet-600 (chart-3)
                ]),
            ))
            .fill(tui_banner::Fill::Keep)
            .render();
        println!("\n {}", banner);
    }

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::with_template("{spinner:.magenta} [{elapsed_precise}] {msg}")?
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", "✓"]),
    );
    spinner.enable_steady_tick(Duration::from_millis(100));
    spinner.set_message("Initializing binary analysis pipeline...");
    Ok(spinner)
}
