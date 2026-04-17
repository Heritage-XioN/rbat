use crate::types::{Confidence, Finding, RiskAssessment};
use std::cmp;

pub fn calculate_risk(
    entropy: f64,
    has_network_urls: bool,
    has_suspicious_apis: bool,
    has_code_caves: bool,
) -> RiskAssessment {
    let mut score = 0;
    let mut findings: Vec<Finding> = Vec::new();

    // Heuristic 1: Packing & Obfuscation (High Confidence)
    if entropy >= 7.5 {
        score += 40;
        findings.push(Finding {
            indicator: "High Entropy".to_string(),
            description: format!(
                "Section entropy is {:.2}. Highly indicative of packed or encrypted code.",
                entropy
            ),
            confidence: Confidence::Critical,
            weight: 40,
        });
    } else if entropy >= 6.8 {
        score += 15;
        findings.push(Finding {
            indicator: "Elevated Entropy".to_string(),
            description:
                "Entropy is slightly elevated, suggesting compressed data or minor obfuscation."
                    .to_string(),
            confidence: Confidence::Medium,
            weight: 15,
        });
    }

    // Heuristic 2: Command & Control Indicators (Medium/High Confidence)
    if has_network_urls {
        score += 25;
        findings.push(Finding {
            indicator: "Network Indicators".to_string(),
            description: "Hardcoded URLs or IP addresses detected. Potential C2 infrastructure."
                .to_string(),
            confidence: Confidence::High,
            weight: 25,
        });
    }

    // Heuristic 3: Suspicious Windows APIs (Medium Confidence)
    if has_suspicious_apis {
        score += 30;
        findings.push(Finding {
            indicator: "Suspicious Imports".to_string(),
            description:
                "Binary imports APIs often used for process injection or memory manipulation."
                    .to_string(),
            confidence: Confidence::High,
            weight: 30,
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

    // Cap the score at a maximum of 100
    let final_score = cmp::min(100, score);

    // Determine Severity and Recommendations based on final score
    let severity = match final_score {
        0..=30 => "Safe".to_string(),
        31..=69 => "Suspicious".to_string(),
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

    if score < 30 {
        recs.push("No immediate threat detected. Standard execution is permissible.".to_string());
    } else if score < 70 {
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
