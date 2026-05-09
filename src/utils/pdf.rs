use crate::prelude::*;
use crate::types::{AnalysisResult, Confidence, RiskAssessment};
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
    // Technical Analysis Fields
    binary_type: String,
    entry_point: String,
    architecture: String,
    capabilities: Vec<TechnicalFinding>,
    signatures: Vec<TechnicalFinding>,
}

struct TechnicalFinding {
    category: String,
    details: String,
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
    analysis_result: &AnalysisResult,
    out_path: &str,
    heatmap_svg: String,
) -> Result<()> {
    let has_heatmap = heatmap_svg.trim().len() > 0;
    let heatmap_svg_content = heatmap_svg;

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

    // Map Technical Capabilities
    let mut capabilities = Vec::new();

    for (api, count) in &analysis_result.api_hooking {
        capabilities.push(TechnicalFinding {
            category: "API Hooking".to_string(),
            details: format!("{} st_value {}", api, count),
        });
    }

    for func in &analysis_result.process_injection {
        capabilities.push(TechnicalFinding {
            category: "Process Injection".to_string(),
            details: format!("Suspicious function: {}", func),
        });
    }

    for (section, caves) in &analysis_result.code_cave {
        capabilities.push(TechnicalFinding {
            category: "Code Cave".to_string(),
            details: format!("Found {} caves in section {}", caves.len(), section),
        });
    }

    for (mnemonic, count) in &analysis_result.blacklisted_mnemonics {
        capabilities.push(TechnicalFinding {
            category: "Suspicious Instructions".to_string(),
            details: format!("Instruction '{}' used {} times", mnemonic, count),
        });
    }

    // Map Signatures
    let mut signatures = Vec::new();

    for (rule, matches) in &analysis_result.packer_signatures {
        for m in matches {
            signatures.push(TechnicalFinding {
                category: "Packer/Protector".to_string(),
                details: format!(
                    "{} matched in section {} at 0x{:X}",
                    rule, m.section, m.offset
                ),
            });
        }
    }

    for (rule, matches) in &analysis_result.string_values {
        for m in matches {
            signatures.push(TechnicalFinding {
                category: "YARA Rule Match".to_string(),
                details: format!(
                    "Rule {} matched '{}' in {}",
                    rule,
                    m.data.chars().take(30).collect::<String>(),
                    m.section
                ),
            });
        }
    }

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
        // Technical analysis fields
        binary_type: analysis_result.metadata.binary_type.clone(),
        entry_point: format!("0x{:X}", analysis_result.metadata.entry_point),
        architecture: analysis_result.metadata.architecture.to_string(),
        capabilities,
        signatures,
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
