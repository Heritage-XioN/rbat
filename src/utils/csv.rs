use crate::types::RiskAssessment;
use csv::Writer;
use std::error::Error;

pub fn generate_csv_report(
    filename: &str,
    assessment: &RiskAssessment,
    out_path: &str,
) -> Result<(), Box<dyn Error>> {
    let mut wtr = Writer::from_path(out_path)?;

    // Write the standard headers expected by SOC tools
    wtr.write_record(&[
        "Timestamp",
        "Filename",
        "Risk_Score",
        "Severity",
        "Indicator_Type",
        "Confidence",
        "Description",
    ])?;

    let timestamp = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S").to_string();

    // Flatten the findings into individual rows
    for finding in &assessment.findings {
        let confidence_str = format!("{:?}", finding.confidence);

        wtr.write_record(&[
            &timestamp,
            filename,
            &assessment.score.to_string(),
            &assessment.severity,
            &finding.indicator,
            &confidence_str,
            &finding.description,
        ])?;
    }

    wtr.flush()?;
    Ok(())
}
