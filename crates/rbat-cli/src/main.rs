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
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;
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
    // Display ASCII banner and read buffer
    // ========================================================
    let spinner = ascii_banner_progress_setup(&args)?;
    let buffer = fs::read(&args.path)?;

    // =====================================================
    // Build the analyzer
    // =====================================================
    let mut builder = Analyzer::builder();
    if let Some(backend) = args.backend {
        builder = builder.with_backend(backend.into());
    }
    if let Some(ref path) = args.severity_overrides {
        builder = builder.with_classifier(path)?;
    }
    if let Some(ref path) = args.signatures {
        builder = builder.with_flirt(path)?;
    }
    if let Some(ref path) = args.rules {
        builder = builder.with_rules(path)?;
    }
    let analyzer = builder.build();

    // =====================================================
    // Begin analysis in streaming mode and emit progress events
    // =====================================================
    let start_time = std::time::Instant::now();
    let analysis_result = Mutex::new(AnalysisResult::default());
    let result = analyzer.streaming(buffer.as_ref(), |event| {
        let mut guard = analysis_result.lock().unwrap_or_else(|e| e.into_inner());
        match event {
            AnalysisProgress::Hashes(hashes) => {
                guard.hashes = hashes;
                spinner.set_message("Computed binary digests & fuzzy hashes");
            }
            AnalysisProgress::Disassembly(code_cave) => {
                let len = code_cave.len();
                guard.code_cave = code_cave;
                spinner.set_message(format!("Disassembled section (code caves: {len})"));
            }
            AnalysisProgress::Strings(string_values) => {
                let len = string_values.len();
                guard.string_values = string_values;
                spinner.set_message(format!("Extracted {len} suspicious string matches"));
            }
            AnalysisProgress::PackerSigs(packer_signatures) => {
                let len = packer_signatures.len();
                guard.packer_signatures = packer_signatures;
                spinner.set_message(format!("Identified {len} packer signatures"));
            }
            AnalysisProgress::Entropy(section_entropy) => {
                let len = section_entropy.len();
                guard.section_entropy = section_entropy;
                spinner.set_message(format!("Calculated Shannon entropy for {len} sections"));
            }
            AnalysisProgress::Imports(imports) => {
                let len = imports.len();
                guard.imports = imports;
                spinner.set_message(format!("Extracted {len} imported symbols"));
            }
            AnalysisProgress::Exports(exports) => {
                let len = exports.len();
                guard.exports = exports;
                spinner.set_message(format!("Extracted {len} exported symbols"));
            }
            AnalysisProgress::BinaryMetadata(metadata) => {
                guard.metadata = metadata;
                spinner.set_message("Parsed binary headers & section bounds");
            }
            AnalysisProgress::CFG(cfg) => {
                guard.cfg = Some(cfg);
                spinner.set_message("Reconstructed Control Flow Graph");
            }
            AnalysisProgress::LibraryFunctions(library_functions) => {
                let len = library_functions.len();
                guard.library_functions = library_functions;
                spinner.set_message(format!("Matched {len} library functions via FLIRT"));
            }
        }
    });
    let mut analysis_result = analysis_result
        .into_inner()
        .unwrap_or_else(|e| e.into_inner());

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
