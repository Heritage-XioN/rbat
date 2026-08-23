//! # CSV Report Formatter
//!
//! This module formats risk assessments and threat findings into a SOC-ready CSV format,
//! optimized for ingestion into SIEM or other security orchestration tools.

use crate::core::{Result, RiskAssessment};
use csv::Writer;
use std::path::Path;

/// Generates a SOC-ready CSV report of the analysis findings.
///
/// This format is optimized for ingestion into SIEM or other security orchestration tools.
/// Each finding is exported as an individual row with its associated risk score and severity.
pub fn generate_csv_report(
    filename: &Path,
    assessment: &RiskAssessment,
    analysis_result: &crate::core::AnalysisResult<'_>,
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
        "Indicator_Type",
        "Confidence",
        "Description",
    ])?;

    let severity = &assessment.severity;
    let timestamp_str = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let filename_lossy = filename.to_string_lossy();

    // Flatten the assessment findings into individual rows, or write a clean summary row
    if assessment.findings.is_empty() {
        wtr.serialize((
            &timestamp_str,
            &filename_lossy,
            analysis_result.total_analysis_time_ms,
            assessment.score,
            severity,
            "NO_FINDINGS",
            "N/A",
            "No security threats or anomalies detected.",
        ))?;
    } else {
        for finding in &assessment.findings {
            wtr.serialize((
                &timestamp_str,
                &filename_lossy,
                analysis_result.total_analysis_time_ms,
                assessment.score,
                severity,
                &finding.indicator,
                &finding.confidence,
                &finding.description,
            ))?;
        }
    }

    wtr.flush()?;

    println!("[+] CSV report generated at {}", out_path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_generate_csv_report() {
        let dir = tempdir().unwrap();
        let out_path = dir.path().join("test_report.csv");

        let assessment = RiskAssessment {
            score: 85,
            severity: "Suspicious".to_string(),
            findings: vec![],
            recommendations: vec![],
        };

        let analysis = crate::core::AnalysisResult::default();
        let result = generate_csv_report(Path::new("test_bin"), &assessment, &analysis, &out_path);
        assert!(result.is_ok());
        assert!(out_path.exists());
    }
}
