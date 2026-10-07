//! # PDF Report Generation Pipeline
//!
//! This module compiles raw binary analysis findings and section entropy maps
//! into a stylized HTML template (using `askama`) and generates a PDF using the `fullbleed` printing engine.

use super::viz::generate_entropy_heatmap;
use askama::Template;
use chrono::Local;
use color_eyre::Result;
use rbat::prelude::*;
use std::fs;
use std::path::Path;

/// Template context for the HTML/PDF report.
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
    binary_type: String,
    entry_point: String,
    architecture: String,
    total_analysis_time_ms: u128,
    hashes: HashContext,
    capabilities: Vec<TechnicalFinding>,
    signatures: Vec<TechnicalFinding>,
}

/// A simplified representation of a technical finding for the report tables.
struct TechnicalFinding {
    category: String,
    details: String,
}

/// Contextual data for a specific security finding in the report.
struct FindingContext {
    indicator: String,
    class: String,
    class_label: String,
    mappings: String,
    description: String,
}

/// Hash identifiers rendered in the Binary Metadata table.
struct HashContext {
    md5: String,
    sha1: String,
    sha256: String,
    ssdeep: String,
    tlsh: String,
}

/// CSS stylesheet for the PDF report, separated from the HTML body
/// so that fullbleed can consume them independently.
/// Includes @page directives for proper PDF pagination.
const REPORT_CSS: &str = include_str!("../../templates/report.css");

/// Generates a professional, design-compliant PDF threat intelligence report.
///
/// This function:
/// 1. Generates an entropy heatmap SVG.
/// 2. Maps raw analysis findings to a user-friendly template.
/// 3. Renders the template via `askama`.
/// 4. Converts the HTML to PDF using the `fullbleed` engine.
///
/// If PDF generation fails, it saves the report as a standalone HTML file as a fallback.
pub fn generate_pdf_report(
    filename: &Path,
    assessment: &RiskAssessment,
    analysis_result: &AnalysisResult<'_>,
    out_path: &Path,
) -> Result<()> {
    let heatmap_svg_content = generate_entropy_heatmap(&analysis_result.section_entropy);
    let has_heatmap = !heatmap_svg_content.trim().is_empty();

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
            let class = match f.severity_class {
                SeverityClass::Critical => "critical",
                SeverityClass::High => "high",
                SeverityClass::Medium => "medium",
                SeverityClass::Low => "low",
                SeverityClass::Capability => "capability",
                SeverityClass::Informational => "informational",
            };
            let mut mappings = f.attack_ids.clone();
            mappings.extend(f.mbc_ids.iter().cloned());
            FindingContext {
                indicator: f.indicator.clone(),
                class: class.to_string(),
                class_label: f.severity_class.label().to_string(),
                mappings: if mappings.is_empty() {
                    "—".to_string()
                } else {
                    mappings.join(", ")
                },
                description: f.description.clone(),
            }
        })
        .collect();

    // Map Technical Capabilities
    let mut capabilities = Vec::new();

    if !analysis_result.code_cave.nop_sleds.is_empty() {
        capabilities.push(TechnicalFinding {
            category: "Code Cave".to_string(),
            details: format!(
                "Found {} NOP sled addresses",
                analysis_result.code_cave.nop_sleds.len()
            ),
        });
    }
    if !analysis_result.code_cave.null_padding.is_empty() {
        capabilities.push(TechnicalFinding {
            category: "Code Cave".to_string(),
            details: format!(
                "Found {} NULL padding addresses",
                analysis_result.code_cave.null_padding.len()
            ),
        });
    }
    if !analysis_result.code_cave.trap_padding.is_empty() {
        capabilities.push(TechnicalFinding {
            category: "Code Cave".to_string(),
            details: format!(
                "Found {} INT3/trap padding addresses",
                analysis_result.code_cave.trap_padding.len()
            ),
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
        binary_type: analysis_result.metadata.binary_type.clone(),
        entry_point: format!("0x{:X}", analysis_result.metadata.entry_point),
        architecture: analysis_result.metadata.architecture_name(),
        total_analysis_time_ms: analysis_result.total_analysis_time_ms,
        hashes: HashContext {
            md5: analysis_result.hashes.md5.clone(),
            sha1: analysis_result.hashes.sha1.clone(),
            sha256: analysis_result.hashes.sha256.clone(),
            ssdeep: analysis_result.hashes.ssdeep.clone(),
            tlsh: analysis_result.hashes.tlsh.clone(),
        },
        capabilities,
        signatures,
    };

    let html = template
        .render()
        .map_err(|e| color_eyre::eyre::eyre!("Template rendering failed: {e}"))?;

    match generate_pdf_from_html(&html, out_path) {
        Ok(()) => {
            println!("[+] PDF report generated at {}", out_path.display());
            Ok(())
        }
        Err(e) => {
            // Fullbleed rendering failed — save as HTML instead
            let mut html_path = out_path.to_path_buf();
            html_path.set_extension("html");
            fs::write(&html_path, &html)?;
            eprintln!(
                "[-] PDF generation failed ({}). \
                 Report saved as HTML: {}",
                e,
                html_path.display()
            );
            Ok(())
        }
    }
}

/// Uses the `fullbleed` engine to render an HTML report into a PDF buffer.
fn generate_pdf_from_html(html: &str, out_path: &Path) -> Result<()> {
    use fullbleed::FullBleed;

    let engine = FullBleed::builder()
        .document_title("RBAT Threat Intelligence Report")
        .document_lang("en")
        .build()
        .map_err(|e| color_eyre::eyre::eyre!("Failed to build FullBleed engine: {e:?}"))?;

    let pdf_bytes = engine
        .render_to_buffer(html, REPORT_CSS)
        .map_err(|e| color_eyre::eyre::eyre!("Failed to render PDF buffer: {e:?}"))?;

    fs::write(out_path, pdf_bytes)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_generate_pdf_report() {
        let dir = tempdir().unwrap();
        let out_path = dir.path().join("test_report.pdf");

        let assessment = RiskAssessment::default();
        let analysis = AnalysisResult::default();

        // This will likely fallback to HTML in a CI environment without fullbleed setup
        let result = generate_pdf_report(Path::new("test_bin"), &assessment, &analysis, &out_path);
        assert!(result.is_ok());

        // Check if either .pdf or .html was created
        let html_path = dir.path().join("test_report.html");
        assert!(out_path.exists() || html_path.exists());
    }
}
