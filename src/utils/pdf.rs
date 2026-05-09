use crate::prelude::*;
use crate::types::{Confidence, RiskAssessment};
use askama::Template;
use chrono::Local;
use std::fs;
use std::path::PathBuf;

#[derive(Template)]
#[template(path = "report.html")]
struct ReportTemplate {
    target_file: String,
    analysis_date: String,
    score: u32,
    severity: String,
    severity_class: String,
    recommendations: Vec<String>,
    has_heatmap: bool,
    heatmap_svg: String,
    findings: Vec<FindingContext>,
}

struct FindingContext {
    indicator: String,
    confidence: String,
    confidence_class: String,
    description: String,
}

/// CSS stylesheet for the PDF report, separated from the HTML body
/// so that fullbleed can consume them independently.
/// Includes @page directives for proper PDF pagination.
const REPORT_CSS: &str = include_str!("../../templates/report.css");

pub fn generate_pdf_report(
    filename: &PathBuf,
    assessment: &RiskAssessment,
    out_path: &str,
    heatmap_svg: Option<String>,
) -> Result<()> {
    let has_heatmap = heatmap_svg.is_some();
    let heatmap_svg_content = heatmap_svg.unwrap_or_default();

    let severity_class = match assessment.severity.to_lowercase().as_str() {
        "malicious" => "malicious",
        "suspicious" => "suspicious",
        "safe" => "safe",
        _ => "safe",
    };

    let findings: Vec<FindingContext> = assessment
        .findings
        .iter()
        .map(|f| {
            let conf_str = format!("{:?}", f.confidence);
            let confidence_class = match f.confidence {
                Confidence::Critical => "critical",
                Confidence::High => "high",
                Confidence::Medium => "medium",
                Confidence::Low => "low",
            };
            FindingContext {
                indicator: f.indicator.clone(),
                confidence: conf_str.to_uppercase(),
                confidence_class: confidence_class.to_string(),
                description: f.description.clone(),
            }
        })
        .collect();

    let template = ReportTemplate {
        target_file: filename
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned(),
        analysis_date: Local::now().format("%Y-%m-%d").to_string(),
        score: assessment.score,
        severity: assessment.severity.clone().to_uppercase(),
        severity_class: severity_class.to_string(),
        recommendations: assessment.recommendations.clone(),
        has_heatmap,
        heatmap_svg: heatmap_svg_content,
        findings,
    };

    let html = template
        .render()
        .map_err(|e| crate::error::RbatError::UnsupportedBinaryFormat(e.to_string()))?;

    match generate_pdf_from_html(&html, out_path) {
        Ok(()) => {
            println!("[+] PDF report generated at {}", out_path);
            Ok(())
        }
        Err(e) => {
            // Fullbleed rendering failed — save as HTML instead
            let html_path = out_path.replace(".pdf", ".html");
            fs::write(&html_path, &html)?;
            eprintln!(
                "[-] PDF generation failed ({}). \
                 Report saved as HTML: {}",
                e, html_path
            );
            Ok(())
        }
    }
}

fn generate_pdf_from_html(html: &str, out_path: &str) -> Result<()> {
    use fullbleed::FullBleed;

    let engine = FullBleed::builder()
        .document_title("RBAT Threat Intelligence Report")
        .document_lang("en")
        .build()
        .map_err(|e| crate::error::RbatError::UnsupportedBinaryFormat(e.to_string()))?;

    let pdf_bytes = engine
        .render_to_buffer(html, REPORT_CSS)
        .map_err(|e| crate::error::RbatError::UnsupportedBinaryFormat(e.to_string()))?;

    fs::write(out_path, pdf_bytes)?;

    Ok(())
}
