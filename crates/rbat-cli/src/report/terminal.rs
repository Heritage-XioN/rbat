//! # Terminal Summary Report Formatter
//!
//! Formats and renders a high-contrast, colorized terminal summary report
//! to stdout following the RBAT cyber-noir design system palette.

use chrono::Local;
use comfy_table::{
    Attribute, Cell, Color, ContentArrangement, Table, presets::UTF8_FULL_CONDENSED,
};
use crossterm::style::{Color as TermColor, Stylize};
use rbat::prelude::*;
use std::path::Path;

// Palette definitions aligned with Next.js client & TUI palette
const COLOR_ACCENT: Color = Color::Rgb {
    r: 192,
    g: 132,
    b: 252,
}; // #c084fc
const COLOR_MUTED: Color = Color::Rgb {
    r: 156,
    g: 163,
    b: 175,
}; // #9ca3af
const COLOR_DANGER: Color = Color::Rgb {
    r: 239,
    g: 68,
    b: 68,
}; // #ef4444
const COLOR_WARNING: Color = Color::Rgb {
    r: 245,
    g: 158,
    b: 11,
}; // #f59e0b
const COLOR_WARNING_LIGHT: Color = Color::Rgb {
    r: 251,
    g: 191,
    b: 36,
}; // #fbbf24
const COLOR_SUCCESS: Color = Color::Rgb {
    r: 34,
    g: 197,
    b: 94,
}; // #22c55e
const COLOR_SUCCESS_LIGHT: Color = Color::Rgb {
    r: 74,
    g: 222,
    b: 128,
}; // #4ade80

/// Maps a [`SeverityClass`] to its terminal badge color following the
/// progressive scale: green (low) → amber (medium) → orange (high) → red (critical).
fn class_color(class: SeverityClass) -> Color {
    match class {
        SeverityClass::Critical => COLOR_DANGER,
        SeverityClass::High => Color::Rgb {
            r: 249,
            g: 115,
            b: 22,
        },
        SeverityClass::Medium => COLOR_WARNING,
        SeverityClass::Low => COLOR_SUCCESS_LIGHT,
        SeverityClass::Capability => COLOR_MUTED,
        SeverityClass::Informational => Color::Rgb {
            r: 120,
            g: 128,
            b: 140,
        },
    }
}

/// Builds the Target Metadata & Triage Hashes table.
fn build_metadata_table(file_path: &Path, analysis_result: &AnalysisResult<'_>) -> Table {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("RBAT STATIC ANALYSIS REPORT")
                .fg(COLOR_ACCENT)
                .add_attribute(Attribute::Bold),
            Cell::new("VALUE")
                .fg(COLOR_ACCENT)
                .add_attribute(Attribute::Bold),
        ]);

    table.add_row(vec![
        Cell::new("Target File").fg(COLOR_MUTED),
        Cell::new(file_path.display().to_string()).add_attribute(Attribute::Bold),
    ]);
    table.add_row(vec![
        Cell::new("Binary Type").fg(COLOR_MUTED),
        Cell::new(&analysis_result.metadata.binary_type).fg(COLOR_ACCENT),
    ]);
    table.add_row(vec![
        Cell::new("Architecture").fg(COLOR_MUTED),
        Cell::new(analysis_result.metadata.architecture_name()).fg(COLOR_ACCENT),
    ]);
    table.add_row(vec![
        Cell::new("Entry Point").fg(COLOR_MUTED),
        Cell::new(format!("0x{:X}", analysis_result.metadata.entry_point)).fg(COLOR_ACCENT),
    ]);

    let hashes = &analysis_result.hashes;
    for (label, value) in [
        ("MD5", hashes.md5.as_str()),
        ("SHA-1", hashes.sha1.as_str()),
        ("SHA-256", hashes.sha256.as_str()),
        ("SSDEEP", hashes.ssdeep.as_str()),
        ("TLSH", hashes.tlsh.as_str()),
    ] {
        if !value.is_empty() {
            table.add_row(vec![
                Cell::new(label).fg(COLOR_MUTED),
                Cell::new(value).fg(COLOR_ACCENT),
            ]);
        }
    }

    table
}

/// Builds the Risk Assessment gauge and severity overview table.
fn build_risk_table(assessment: &RiskAssessment) -> Table {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("RISK ASSESSMENT")
                .fg(COLOR_ACCENT)
                .add_attribute(Attribute::Bold),
            Cell::new("SCORE")
                .fg(COLOR_ACCENT)
                .add_attribute(Attribute::Bold),
            Cell::new("VERDICT")
                .fg(COLOR_ACCENT)
                .add_attribute(Attribute::Bold),
            Cell::new("SUMMARY")
                .fg(COLOR_ACCENT)
                .add_attribute(Attribute::Bold),
        ]);

    let score = assessment.score.min(100);
    let bar_width = 20;
    let filled = ((score as usize) * bar_width) / 100;
    let empty = bar_width.saturating_sub(filled);

    let (score_color, severity_str) = match assessment.severity.as_str() {
        "Safe" => (COLOR_SUCCESS, "SAFE"),
        "Suspicious" => (COLOR_WARNING, "SUSPICIOUS"),
        _ => (COLOR_DANGER, "MALICIOUS"),
    };

    let gauge = format!("{}{} ({}%)", "█".repeat(filled), "░".repeat(empty), score);

    let summary = format_summary_line(&assessment.finding_counts);
    let summary_text = if summary.is_empty() {
        "No findings".to_string()
    } else {
        summary
    };

    table.add_row(vec![
        Cell::new("Threat Level").fg(COLOR_MUTED),
        Cell::new(gauge)
            .fg(score_color)
            .add_attribute(Attribute::Bold),
        Cell::new(severity_str)
            .fg(score_color)
            .add_attribute(Attribute::Bold),
        Cell::new(summary_text).fg(if assessment.finding_counts.indicator_count() > 0 {
            COLOR_WARNING_LIGHT
        } else {
            COLOR_SUCCESS_LIGHT
        }),
    ]);

    table
}

/// Builds the colorized findings table (`CLASS | CAPABILITY | ATT&CK | MBC | NAMESPACE`).
fn build_findings_table(assessment: &RiskAssessment) -> Table {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("CLASS")
                .fg(COLOR_ACCENT)
                .add_attribute(Attribute::Bold),
            Cell::new("CAPABILITY")
                .fg(COLOR_ACCENT)
                .add_attribute(Attribute::Bold),
            Cell::new("ATT&CK")
                .fg(COLOR_ACCENT)
                .add_attribute(Attribute::Bold),
            Cell::new("MBC")
                .fg(COLOR_ACCENT)
                .add_attribute(Attribute::Bold),
            Cell::new("NAMESPACE")
                .fg(COLOR_ACCENT)
                .add_attribute(Attribute::Bold),
        ]);

    if assessment.findings.is_empty() {
        table.add_row(vec![
            Cell::new("INFO")
                .fg(COLOR_SUCCESS)
                .add_attribute(Attribute::Bold),
            Cell::new("✔ No security threats or anomalies detected.").fg(COLOR_SUCCESS_LIGHT),
            Cell::new("—"),
            Cell::new("—"),
            Cell::new("—").fg(COLOR_MUTED),
        ]);
    } else {
        for finding in &assessment.findings {
            let class_cell = Cell::new(finding.severity_class.label())
                .fg(class_color(finding.severity_class))
                .add_attribute(Attribute::Bold);
            let attack_ids = if finding.attack_ids.is_empty() {
                "—".to_string()
            } else {
                finding.attack_ids.join(", ")
            };
            let mbc_ids = if finding.mbc_ids.is_empty() {
                "—".to_string()
            } else {
                finding.mbc_ids.join(", ")
            };
            let namespace = finding.namespace.as_deref().unwrap_or("—").to_string();

            table.add_row(vec![
                class_cell,
                Cell::new(&finding.indicator),
                Cell::new(attack_ids),
                Cell::new(mbc_ids),
                Cell::new(namespace).fg(COLOR_MUTED),
            ]);
        }
    }

    table
}

/// Builds the Generated Reports table if output files were created.
fn build_reports_table(generated_reports: &[(&str, &Path)]) -> Table {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("REPORT FORMAT")
                .fg(COLOR_ACCENT)
                .add_attribute(Attribute::Bold),
            Cell::new("FILE PATH")
                .fg(COLOR_ACCENT)
                .add_attribute(Attribute::Bold),
        ]);

    for (fmt, path) in generated_reports {
        table.add_row(vec![
            Cell::new(format!("[+] {fmt}"))
                .fg(COLOR_SUCCESS)
                .add_attribute(Attribute::Bold),
            Cell::new(path.display().to_string()).fg(COLOR_MUTED),
        ]);
    }

    table
}

/// Renders a one-line per-class tally such as `2 high · 1 medium · 14 capabilities`.
fn format_summary_line(counts: &FindingCounts) -> String {
    let mut parts: Vec<String> = Vec::new();
    let push = |parts: &mut Vec<String>, n: u32, singular: &str, plural: &str| {
        if n > 0 {
            parts.push(format!("{n} {}", if n == 1 { singular } else { plural }));
        }
    };
    let high_total = counts.critical + counts.high;
    push(&mut parts, high_total, "high", "high");
    push(&mut parts, counts.medium, "medium", "medium");
    push(&mut parts, counts.low, "low", "low");
    push(&mut parts, counts.capability, "capability", "capabilities");
    push(
        &mut parts,
        counts.informational,
        "informational",
        "informational",
    );
    parts.join(" · ")
}

/// Prints a stylized CLI summary report to stdout using comfy-table layouts.
pub fn print_terminal_report(
    file_path: &Path,
    analysis_result: &AnalysisResult<'_>,
    assessment: &RiskAssessment,
    generated_reports: &[(&str, &Path)],
) {
    println!();
    // 1. Target Metadata & Hashes Table
    println!("{}", build_metadata_table(file_path, analysis_result));
    println!();

    // 2. Risk Assessment Gauge Table
    println!("{}", build_risk_table(assessment));
    println!();

    // 3. Matched Rules & Capabilities Table
    println!("{}", build_findings_table(assessment));

    let analyzed_at = Local::now().format("%Y-%m-%d %H:%M:%S");
    println!(
        "  {}",
        format!("Analyzed {analyzed_at} · override classes via --severity-overrides")
            .with(TermColor::Rgb {
                r: 156,
                g: 163,
                b: 175
            })
            .italic()
    );

    // 4. Generated Output Files (if any)
    if !generated_reports.is_empty() {
        println!();
        println!("{}", build_reports_table(generated_reports));
    }

    // 5. Execution Time
    if analysis_result.total_analysis_time_ms > 0 {
        let seconds = (analysis_result.total_analysis_time_ms as f64) / 1000.0;
        println!(
            "\n  {} {}",
            "⏱ Total Analysis Time:"
                .with(TermColor::Rgb {
                    r: 192,
                    g: 132,
                    b: 252
                })
                .bold(),
            format!("{:.2}s", seconds).with(TermColor::Rgb {
                r: 74,
                g: 222,
                b: 128
            })
        );
    }

    // 6. Footer Hint
    println!(
        "  {}",
        "💡 Tip: Run with --tui for an interactive dashboard view or --cfg for Graphviz DOT format."
            .with(TermColor::Rgb { r: 156, g: 163, b: 175 })
            .italic()
    );
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbat::core::{
        scoring::risk::{CategoryScore, Finding, FindingCounts},
        types::analysis::BinaryMetadata,
    };

    #[test]
    fn test_print_terminal_report_runs_without_panic() {
        let result = AnalysisResult {
            metadata: BinaryMetadata {
                binary_type: "Linux ELF".to_string(),
                entry_point: 0x401000,
                architecture: 62,
            },
            ..Default::default()
        };

        let assessment = RiskAssessment {
            score: 44,
            severity: "Suspicious".to_string(),
            findings: vec![
                Finding {
                    indicator: "execute anti-debugging instructions".to_string(),
                    description: "Found anti-debug checks".to_string(),
                    severity_class: SeverityClass::High,
                    attack_ids: vec!["T1622".to_string()],
                    mbc_ids: vec!["B0001.007".to_string()],
                    category: Some("discovery".to_string()),
                    namespace: Some("anti-analysis/anti-debugging".to_string()),
                },
                Finding {
                    indicator: "create directory".to_string(),
                    description: "Creates directories".to_string(),
                    severity_class: SeverityClass::Capability,
                    attack_ids: vec![],
                    mbc_ids: vec![],
                    category: None,
                    namespace: Some("host-interaction/file-system".to_string()),
                },
            ],
            recommendations: vec!["Flagged for manual review.".to_string()],
            category_breakdown: vec![CategoryScore {
                category: "discovery".to_string(),
                score: 22,
            }],
            finding_counts: FindingCounts {
                critical: 0,
                high: 1,
                medium: 0,
                low: 0,
                capability: 1,
                informational: 0,
            },
        };

        let dummy_path = Path::new("test_sample.elf");
        let dummy_reports = vec![("PDF", Path::new("report.pdf"))];

        // Ensure rendering does not panic
        print_terminal_report(dummy_path, &result, &assessment, &dummy_reports);
    }

    #[test]
    fn test_summary_line_formatting() {
        let counts = FindingCounts {
            critical: 0,
            high: 2,
            medium: 0,
            low: 1,
            capability: 14,
            informational: 3,
        };
        assert_eq!(
            format_summary_line(&counts),
            "2 high · 1 low · 14 capabilities · 3 informational"
        );

        assert_eq!(format_summary_line(&FindingCounts::default()), "");
    }
}
