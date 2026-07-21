//! # RBAT CLI Executable Entry Point
//!
//! This module provides the main entry point for the `rbat` command-line executable.
//! It handles subcommand dispatch (`analyze`, `rules`, `completions`), manages the streaming
//! static analysis pipeline, displays terminal progress bars and TrueColor reports, and invokes
//! the Ratatui interactive TUI dashboard.

use clap::Parser;
use color_eyre::Result;
use indicatif::{ProgressBar, ProgressStyle};
use rbat::{
    core::{
        AnalysisResult,
        analyzer::analyze_streaming,
        cli::{AnalyzeArgs, Cli, Commands, RulesAction, RulesArgs},
        tui::App,
        types::AnalysisProgress,
    },
    utils::{
        csv::generate_csv_report,
        json::generate_json_report,
        pdf::generate_pdf_report,
        rules_cli::{print_rule_example, print_rule_schema, validate_rules_directory},
        scoring::calculate_risk,
        terminal_report::print_terminal_report,
    },
};
use std::path::PathBuf;
use std::time::Duration;
use std::{fs, sync::mpsc};
use tui_banner::Banner;

fn main() -> Result<()> {
    color_eyre::install()?;
    let cli = Cli::parse();

    match cli.command {
        Commands::Analyze(args) => run_analyze(args),
        Commands::Rules(args) => run_rules(args),
        Commands::Completions(args) => run_completions(args),
    }
}

fn run_completions(args: rbat::core::cli::CompletionsArgs) -> Result<()> {
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
    let mv_path = args.path.clone();
    let buffer = fs::read(mv_path)?;

    // Display ASCII banner only when not emitting pure DOT graph syntax to stdout
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

    // Progress spinner indicator (emits to stderr by default)
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::with_template("{spinner:.magenta} [{elapsed_precise}] {msg}")?
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", "✓"]),
    );
    spinner.enable_steady_tick(Duration::from_millis(100));
    spinner.set_message("Initializing binary analysis pipeline...");

    let (tx, rx) = mpsc::channel();

    // Runs streaming analysis on a background thread while main thread updates spinner
    let thread_buffer = buffer.clone();
    let analysis_thread = std::thread::spawn(move || {
        analyze_streaming(&thread_buffer, move |event| {
            let _ = tx.send(event);
        })
    });

    let mut analysis_result = AnalysisResult::default();

    // Event loop receiving real-time progress events
    for event in rx {
        match event {
            AnalysisProgress::Disassembly((code_cave, blacklisted_mnemonics)) => {
                analysis_result.code_cave = code_cave.clone();
                analysis_result.blacklisted_mnemonics = blacklisted_mnemonics.clone();
                spinner.set_message(format!(
                    "Disassembled section (code caves: {}, blacklisted mnemonics: {})",
                    code_cave.len(),
                    blacklisted_mnemonics.len()
                ));
            }
            AnalysisProgress::Strings(string_values) => {
                analysis_result.string_values = string_values.clone();
                spinner.set_message(format!(
                    "Extracted {} suspicious string matches",
                    string_values.len()
                ));
            }
            AnalysisProgress::PackerSigs(packer_signatures) => {
                analysis_result.packer_signatures = packer_signatures.clone();
                spinner.set_message(format!(
                    "Identified {} packer signatures",
                    packer_signatures.len()
                ));
            }
            AnalysisProgress::Entropy(section_entropy) => {
                analysis_result.section_entropy = section_entropy.clone();
                spinner.set_message(format!(
                    "Calculated Shannon entropy for {} sections",
                    section_entropy.len()
                ));
            }
            AnalysisProgress::ApiHooking(api_hooking) => {
                analysis_result.api_hooking = api_hooking.clone();
                spinner.set_message(format!(
                    "Detected {} API hooking targets",
                    api_hooking.len()
                ));
            }
            AnalysisProgress::ProcessInjection(process_injection) => {
                analysis_result.process_injection = process_injection.clone();
                spinner.set_message(format!(
                    "Flagged {} process injection functions",
                    process_injection.len()
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
        }
    }

    // Check analysis thread result
    match analysis_thread.join() {
        Ok(analysis_result_inner) => match analysis_result_inner {
            Ok(_) => spinner.finish_with_message("Analysis complete! 🚀"),
            Err(e) => {
                spinner.finish_with_message("Analysis failed! ❌");
                return Err(color_eyre::eyre::eyre!(e));
            }
        },
        Err(join_panic) => {
            spinner.finish_with_message("Analysis thread panicked! ❌");
            let panic_msg = if let Some(s) = join_panic.downcast_ref::<&str>() {
                *s
            } else if let Some(s) = join_panic.downcast_ref::<String>() {
                s.as_str()
            } else {
                "Unknown panic reason"
            };
            return Err(color_eyre::eyre::eyre!(
                "Analysis thread panicked: {}",
                panic_msg
            ));
        }
    }

    // Compute threat risk assessment
    let features = rbat::core::features::FeatureSet::from_analysis_result(&analysis_result);
    let mut rules = rbat::core::Rule::load_embedded();
    if let Some(ref rules_dir) = args.rules {
        let custom_rules = rbat::core::Rule::load_from_directory(rules_dir);
        rules.extend(custom_rules);
    }
    let matched_rules = rbat::core::Rule::evaluate(&features, &rules);
    let risk_assessment = calculate_risk(&matched_rules);

    // Setup output directory
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
        generate_csv_report(&args.path, &risk_assessment, &csv_path)?;
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
        ratatui::run(|terminal| App::new(analysis_result, risk_assessment.clone()).run(terminal))?;
    } else if args.dry_run {
        println!("[+] Dry run complete.");
    } else if !args.cfg {
        print_terminal_report(&args.path, &analysis_result, &risk_assessment, &report_refs);
    }

    Ok(())
}
