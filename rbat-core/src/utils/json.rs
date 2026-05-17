use crate::core::{AnalysisResult, RbatError, Result, RiskAssessment};
use std::fs::File;
use std::io::Write;
use std::path::Path;

/// Generates a comprehensive JSON report containing all raw analysis details and the final risk assessment.
///
/// This format is ideal for integration into automated security pipelines or custom visualization tools.
pub fn generate_json_report(
    filename: &Path,
    assessment: &RiskAssessment,
    analysis_result: &AnalysisResult,
    out_path: &Path,
) -> Result<()> {
    let report = serde_json::json!({
        "target": {
            "name": filename.file_name().unwrap_or_default().to_string_lossy(),
            "path": filename.to_string_lossy(),
        },
        "timestamp": chrono::Local::now().to_rfc3339(),
        "risk_assessment": assessment,
        "analysis_details": analysis_result,
    });

    let json_string = serde_json::to_string_pretty(&report)
        .map_err(|e| RbatError::UnsupportedBinaryFormat(e.to_string()))?;

    let mut file = File::create(out_path)?;
    file.write_all(json_string.as_bytes())?;

    println!("[+] JSON report generated at {}", out_path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_generate_json_report() {
        let dir = tempdir().unwrap();
        let out_path = dir.path().join("test_report.json");

        let assessment = RiskAssessment::default();
        let analysis = AnalysisResult::default();

        // This will likely fallback to HTML in a CI environment without fullbleed setup
        let result = generate_json_report(Path::new("test_bin"), &assessment, &analysis, &out_path);
        assert!(result.is_ok());

        // Check if either .pdf or .html was created
        let html_path = dir.path().join("test_report.html");
        assert!(out_path.exists() || html_path.exists());
    }
}
