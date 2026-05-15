use crate::rbat::{Confidence, Finding, RiskAssessment};
use std::{cmp, collections::HashMap};

pub fn calculate_risk(
    section_entropy: &HashMap<String, f64>,
    network_indicators: usize,
    suspicious_apis: usize,
    process_injection: usize,
    has_code_caves: bool,
    has_packer_signatures: bool,
) -> RiskAssessment {
    let mut score: u32 = 0;
    let mut findings: Vec<Finding> = Vec::new();

    // Heuristic 1: Section Entropy (Focus on .text / executable sections)
    let text_entropy = section_entropy
        .get(".text")
        .or_else(|| section_entropy.get("__text"))
        .or_else(|| section_entropy.get("CODE"))
        .cloned()
        .unwrap_or_else(|| {
            // Fallback: max entropy of all sections
            section_entropy.values().cloned().fold(0.0, f64::max)
        });

    if text_entropy >= 7.5 {
        score += 40;
        findings.push(Finding {
            indicator: "High Section Entropy".to_string(),
            description: format!(
                "Executable section entropy is {:.2}. Highly indicative of packed or encrypted code.",
                text_entropy
            ),
            confidence: Confidence::Critical,
            weight: 40,
        });
    } else if text_entropy >= 6.8 {
        score += 15;
        findings.push(Finding {
            indicator: "Elevated Section Entropy".to_string(),
            description: format!(
                "Executable section entropy is {:.2}, suggesting compressed data or minor obfuscation.",
                text_entropy
            ),
            confidence: Confidence::Medium,
            weight: 15,
        });
    }

    // Heuristic 2: Network Indicators (Requires multiple or high-confidence matches)
    if network_indicators > 0 {
        let weight = if network_indicators > 3 { 25 } else { 10 };
        score += weight;
        findings.push(Finding {
            indicator: "Network Indicators".to_string(),
            description: format!(
                "Detected {} network-related strings (URLs, IPs, C2 patterns).",
                network_indicators
            ),
            confidence: if network_indicators > 3 {
                Confidence::High
            } else {
                Confidence::Low
            },
            weight,
        });
    }

    // Heuristic 3: Process Injection & Suspicious APIs
    if process_injection > 0 {
        let weight = cmp::min(40, (process_injection * 15) as u32);
        score += weight;
        findings.push(Finding {
            indicator: "Process Injection APIs".to_string(),
            description: format!(
                "Binary imports {} APIs often used for process injection or memory manipulation.",
                process_injection
            ),
            confidence: Confidence::High,
            weight,
        });
    }

    if suspicious_apis > 0 {
        let weight = cmp::min(20, (suspicious_apis * 5) as u32);
        score += weight;
        findings.push(Finding {
            indicator: "Suspicious API Hooks".to_string(),
            description: format!(
                "Detected {} suspicious exported functions or API hooking patterns.",
                suspicious_apis
            ),
            confidence: Confidence::Medium,
            weight,
        });
    }

    // Heuristic 4: Evasion Techniques
    if has_code_caves {
        score += 35;
        findings.push(Finding {
            indicator: "Code Caves".to_string(),
            description:
                "Large blocks of executable null bytes detected. Potential payload injection site."
                    .to_string(),
            confidence: Confidence::High,
            weight: 35,
        });
    }

    // Heuristic 5: Known Packer Signatures (Critical Confidence)
    if has_packer_signatures {
        score += 45;
        findings.push(Finding {
            indicator: "Known Packer".to_string(),
            description: "Binary matches signatures of known packers (UPX, ASPack, PECompact, Themida, etc.).".to_string(),
            confidence: Confidence::Critical,
            weight: 45,
        });
    }

    // the score is capped at 100
    let final_score = cmp::min(100, score);

    // Determine Severity and Recommendations based on final score
    let severity = match final_score {
        0..=25 => "Safe".to_string(),
        26..=60 => "Suspicious".to_string(),
        _ => "Malicious".to_string(),
    };

    let recommendations = generate_recommendations(final_score);

    RiskAssessment {
        score: final_score,
        severity,
        findings,
        recommendations,
    }
}

fn generate_recommendations(score: u32) -> Vec<String> {
    let mut recs = Vec::new();

    if score < 26 {
        recs.push("No immediate threat detected. Standard execution is permissible.".to_string());
    } else if score < 61 {
        recs.push(
            "Flagged for manual review. Do not execute in a production environment.".to_string(),
        );
        recs.push("Submit binary hash to VirusTotal for community correlation.".to_string());
    } else {
        recs.push("IMMEDIATE QUARANTINE REQUIRED.".to_string());
        recs.push(
            "Execute strictly within a heavily monitored, isolated sandbox environment."
                .to_string(),
        );
        recs.push(
            "Extract and block all associated network IOCs at the firewall level.".to_string(),
        );
    }

    recs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_risk_safe() {
        let entropy = HashMap::new();
        let assessment = calculate_risk(&entropy, 0, 0, 0, false, false);
        assert_eq!(assessment.score, 0);
        assert_eq!(assessment.severity, "Safe");
        assert!(assessment.findings.is_empty());
    }

    #[test]
    fn test_calculate_risk_malicious_packer() {
        let mut entropy = HashMap::new();
        entropy.insert(".text".to_string(), 8.0);
        let assessment = calculate_risk(&entropy, 0, 0, 0, false, true);
        // 40 (entropy) + 45 (packer) = 85
        assert_eq!(assessment.score, 85);
        assert_eq!(assessment.severity, "Malicious");
        assert_eq!(assessment.findings.len(), 2);
    }

    #[test]
    fn test_calculate_risk_suspicious() {
        let mut entropy = HashMap::new();
        entropy.insert(".text".to_string(), 6.9);
        let assessment = calculate_risk(&entropy, 1, 0, 0, false, false);
        assert_eq!(assessment.score, 25);
        assert_eq!(assessment.severity, "Safe");
    }

    #[test]
    fn test_calculate_risk_capped() {
        let mut entropy = HashMap::new();
        entropy.insert(".text".to_string(), 8.0);
        let assessment = calculate_risk(&entropy, 10, 10, 10, true, true);
        // 40 + 25 + 20 + 40 + 35 + 45 = 205 -> capped at 100
        assert_eq!(assessment.score, 100);
        assert_eq!(assessment.severity, "Malicious");
    }
}
