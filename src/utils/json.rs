use crate::rbat::{AnalysisResult, Result, RiskAssessment};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

/// Generates a comprehensive JSON report of the analysis findings and risk assessment.
pub fn generate_json_report(
    _filename: &PathBuf,
    assessment: &RiskAssessment,
    analysis_result: &AnalysisResult,
    out_path: &str,
) -> Result<()> {
    let report = serde_json::json!({
        "target": {
            "name": _filename.file_name().unwrap_or_default().to_string_lossy(),
            "path": _filename.to_string_lossy(),
        },
        "timestamp": chrono::Local::now().to_rfc3339(),
        "risk_assessment": assessment,
        "analysis_details": analysis_result,
    });

    let json_string = serde_json::to_string_pretty(&report)
        .map_err(|e| crate::rbat::RbatError::UnsupportedBinaryFormat(e.to_string()))?;

    let mut file = File::create(out_path)?;
    file.write_all(json_string.as_bytes())?;

    println!("[+] JSON report generated at {}", out_path);
    Ok(())
}
