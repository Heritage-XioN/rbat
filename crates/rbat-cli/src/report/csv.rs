//! # CSV Report Formatter
//!
//! This module formats risk assessments and threat findings into a SOC-ready CSV format,
//! optimized for ingestion into SIEM or other security orchestration tools.

use color_eyre::Result;
use csv::Writer;
use rbat::core::{scoring::RiskAssessment, types::AnalysisResult};
use std::path::Path;

/// Generates a SOC-ready CSV report of the analysis findings.
///
/// This format is optimized for ingestion into SIEM or other security orchestration tools.
/// Each finding is exported as an individual row with its associated risk score, severity
/// class, and ATT&CK/MBC mappings.
pub fn generate_csv_report(
    filename: &Path,
    assessment: &RiskAssessment,
    analysis_result: &AnalysisResult<'_>,
    out_path: &Path,
) -> Result<()> {
    let mut wtr = Writer::from_path(out_path)?;

    // Standard headers expected by SOC tools
    wtr.write_record([
        "Timestamp",
        "Filename",
        "Total_Time_ms",
        "Risk_Score",
        "Severity",
        "Class",
        "Indicator",
        "ATT&CK_IDs",
        "MBC_IDs",
        "Category",
        "Md5",
        "Sha1",
        "Sha256",
        "Ssdeep",
        "Tlsh",
        "Description",
    ])?;

    let severity = &assessment.severity;
    let hashes = &analysis_result.hashes;
    let timestamp_str = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let filename_lossy = filename.to_string_lossy();

    // Flatten the assessment findings into individual rows, or write a clean summary row
    if assessment.findings.is_empty() {
        wtr.write_record([
            &timestamp_str,
            filename_lossy.as_ref(),
            &analysis_result.total_analysis_time_ms.to_string(),
            &assessment.score.to_string(),
            severity.as_str(),
            "NO_FINDINGS",
            "N/A",
            "",
            "",
            "",
            &hashes.md5,
            &hashes.sha1,
            &hashes.sha256,
            &hashes.ssdeep,
            &hashes.tlsh,
            "No security threats or anomalies detected.",
        ])?;
    } else {
        for finding in &assessment.findings {
            wtr.write_record([
                timestamp_str.as_str(),
                filename_lossy.as_ref(),
                analysis_result.total_analysis_time_ms.to_string().as_str(),
                assessment.score.to_string().as_str(),
                severity.as_str(),
                finding.severity_class.label(),
                finding.indicator.as_str(),
                finding.attack_ids.join("|").as_str(),
                finding.mbc_ids.join("|").as_str(),
                finding.category.as_deref().unwrap_or(""),
                &hashes.md5,
                &hashes.sha1,
                &hashes.sha256,
                &hashes.ssdeep,
                &hashes.tlsh,
                finding.description.as_str(),
            ])?;
        }
    }

    wtr.flush()?;

    println!("[+] CSV report generated at {}", out_path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbat::core::scoring::{Finding, SeverityClass};
    use tempfile::tempdir;

    #[test]
    fn test_generate_csv_report() {
        let dir = tempdir().unwrap();
        let out_path = dir.path().join("test_report.csv");

        let assessment = RiskAssessment {
            score: 44,
            severity: "Suspicious".to_string(),
            findings: vec![Finding {
                indicator: "execute anti-debugging instructions".to_string(),
                description: "Found anti-debug checks".to_string(),
                severity_class: SeverityClass::High,
                attack_ids: vec!["T1622".to_string()],
                mbc_ids: vec![],
                category: Some("discovery".to_string()),
                namespace: None,
            }],
            recommendations: vec![],
            ..Default::default()
        };

        let analysis = AnalysisResult::default();
        let result = generate_csv_report(Path::new("test_bin"), &assessment, &analysis, &out_path);
        assert!(result.is_ok());
        assert!(out_path.exists());

        let contents = std::fs::read_to_string(&out_path).unwrap();
        assert!(contents.contains("ATT&CK_IDs"));
        assert!(contents.contains("HIGH"));
        assert!(contents.contains("T1622"));
    }
}
