use crate::rbat::{Result, RiskAssessment};
use csv::Writer;
use std::path::Path;

/// Generates a SOC-ready CSV report of the analysis findings.
///
/// This format is optimized for ingestion into SIEM or other security orchestration tools.
/// Each finding is exported as an individual row with its associated risk score and severity.
pub fn generate_csv_report(
    filename: &Path,
    assessment: &RiskAssessment,
    out_path: &str,
) -> Result<()> {
    let mut wtr = Writer::from_path(out_path)?;
    let filename_str = filename.to_string_lossy().to_string();
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    // Standard headers expected by SOC tools
    wtr.write_record([
        "Timestamp",
        "Filename",
        "Risk_Score",
        "Severity",
        "Indicator_Type",
        "Confidence",
        "Description",
    ])?;

    let score = assessment.score.to_string();
    let severity = &assessment.severity;

    // Flatten the assessment findings into individual rows
    for finding in &assessment.findings {
        wtr.write_record([
            &timestamp,
            &filename_str,
            &score,
            severity,
            &finding.indicator,
            &format!("{:?}", finding.confidence),
            &finding.description,
        ])?;
    }

    wtr.flush()?;
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
        let out_path_str = out_path.to_str().unwrap();

        let assessment = RiskAssessment {
            score: 85,
            severity: "Suspicious".to_string(),
            findings: vec![],
            recommendations: vec![],
        };

        let result = generate_csv_report(Path::new("test_bin"), &assessment, out_path_str);
        assert!(result.is_ok());
        assert!(out_path.exists());
    }
}
