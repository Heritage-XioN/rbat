use crate::rbat::*;
use csv::Writer;
use std::path::PathBuf;

pub fn generate_csv_report(
    filename: &PathBuf,
    assessment: &RiskAssessment,
    out_path: &str,
) -> Result<()> {
    let mut wtr = Writer::from_path(out_path)?;
    let filename_str = filename.to_string_lossy().to_string();
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    // Standard headers expected by SOC tools
    wtr.write_record(&[
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
        wtr.write_record(&[
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
