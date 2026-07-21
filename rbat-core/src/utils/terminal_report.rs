//! # Terminal Summary Report Formatter
//!
//! Formats and renders a high-contrast, colorized terminal summary report
//! to stdout following the RBAT cyber-noir design system palette.

use crate::core::{AnalysisResult, Confidence, RiskAssessment};
use crossterm::style::{Color, Stylize};
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
const COLOR_BORDER: Color = Color::Rgb {
    r: 60,
    g: 64,
    b: 110,
}; // Indigo border

const COLOR_DANGER: Color = Color::Rgb {
    r: 239,
    g: 68,
    b: 68,
}; // #ef4444
const COLOR_DANGER_LIGHT: Color = Color::Rgb {
    r: 248,
    g: 113,
    b: 113,
}; // #f87171
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

/// Prints a stylized CLI summary report to stdout.
pub fn print_terminal_report(
    file_path: &Path,
    analysis_result: &AnalysisResult,
    assessment: &RiskAssessment,
    generated_reports: &[(&str, &Path)],
) {
    let line_sep = "─".repeat(64).with(COLOR_BORDER);

    println!("\n{}", line_sep);
    println!(
        " {}",
        "RBAT STATIC ANALYSIS REPORT".with(COLOR_ACCENT).bold()
    );
    println!("{}", line_sep);

    // 1. Target Metadata
    println!(
        "  {:<15} : {}",
        "Target File".with(COLOR_MUTED),
        file_path.display().to_string().bold()
    );
    println!(
        "  {:<15} : {}",
        "Binary Type".with(COLOR_MUTED),
        analysis_result
            .metadata
            .binary_type
            .as_str()
            .with(COLOR_ACCENT)
    );
    println!(
        "  {:<15} : {}",
        "Architecture".with(COLOR_MUTED),
        analysis_result
            .metadata
            .architecture_name()
            .with(COLOR_ACCENT)
    );
    println!(
        "  {:<15} : {}",
        "Entry Point".with(COLOR_MUTED),
        format!("0x{:X}", analysis_result.metadata.entry_point).with(COLOR_ACCENT)
    );

    println!("{}", line_sep);

    // 2. Risk Assessment Gauge
    let score = assessment.score.min(100);
    let bar_width = 24;
    let filled = ((score as usize) * bar_width) / 100;
    let empty = bar_width.saturating_sub(filled);

    let (score_color, severity_badge) = if score >= 75 {
        (COLOR_DANGER, "CRITICAL RISK".with(COLOR_DANGER).bold())
    } else if score >= 40 {
        (COLOR_WARNING, "MEDIUM RISK".with(COLOR_WARNING).bold())
    } else {
        (COLOR_SUCCESS, "LOW RISK".with(COLOR_SUCCESS).bold())
    };

    let progress_bar = format!(
        "[{}{}]",
        "█".repeat(filled).with(score_color),
        "░".repeat(empty).with(COLOR_BORDER)
    );

    println!(
        "  {:<15} : {}  {}% ({})",
        "Risk Score".with(COLOR_MUTED),
        progress_bar,
        score.to_string().with(score_color).bold(),
        severity_badge
    );

    println!("{}", line_sep);

    // 3. Security Findings
    println!(
        " {}",
        "MATCHED THREAT RULES & FINDINGS".with(COLOR_ACCENT).bold()
    );

    if assessment.findings.is_empty() {
        println!(
            "  {}",
            "✔ No security threats or anomalies detected.".with(COLOR_SUCCESS_LIGHT)
        );
    } else {
        for finding in &assessment.findings {
            let (badge, badge_color) = match finding.confidence {
                Confidence::Critical => ("[CRITICAL]", COLOR_DANGER),
                Confidence::High => ("[HIGH]    ", COLOR_DANGER_LIGHT),
                Confidence::Medium => ("[MEDIUM]  ", COLOR_WARNING_LIGHT),
                Confidence::Low => ("[LOW]     ", COLOR_SUCCESS_LIGHT),
            };

            println!(
                "  {} {}",
                badge.with(badge_color).bold(),
                finding.indicator.as_str().bold()
            );
        }
    }

    // 4. Generated Output Files (if any)
    if !generated_reports.is_empty() {
        println!("{}", line_sep);
        println!(" {}", "GENERATED REPORTS".with(COLOR_ACCENT).bold());
        for (fmt, path) in generated_reports {
            println!(
                "  {} {:<8} : {}",
                "[+]".with(COLOR_SUCCESS),
                fmt,
                path.display().to_string().with(COLOR_MUTED)
            );
        }
    }

    println!("{}", line_sep);

    // Footer Hint
    println!(
        "  {}",
        "💡 Tip: Run with --tui for an interactive dashboard view or --cfg for Graphviz DOT format."
            .with(COLOR_MUTED)
            .italic()
    );
    println!("{}\n", line_sep);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::{BinaryMetadata, Finding};

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
            score: 85,
            severity: "CRITICAL".to_string(),
            findings: vec![Finding {
                indicator: "Code cave detected".to_string(),
                description: "Found sequence of NOPs".to_string(),
                confidence: Confidence::Critical,
                weight: 85,
            }],
            recommendations: vec!["Isolate sample".to_string()],
        };

        let dummy_path = Path::new("test_sample.elf");
        let dummy_reports = vec![("PDF", Path::new("report.pdf"))];

        // Ensure rendering does not panic
        print_terminal_report(dummy_path, &result, &assessment, &dummy_reports);
    }
}
