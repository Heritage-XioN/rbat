//! # Category-Based Security Scoring Engine
//!
//! This module implements a weighted category scoring system that evaluates matched
//! rule findings grouped by MITRE ATT&CK tactics. Each category has a maximum
//! contribution cap, preventing double-counting within the same tactic.
//!
//! # Example
//! ```rust
//! use rbat::utils::scoring::calculate_risk;
//! use rbat::core::RuleMeta;
//!
//! let matches = vec![
//!     RuleMeta {
//!         name: "Test".to_string(),
//!         description: "Test rule".to_string(),
//!         mitre_attack: "T1055".to_string(),
//!         severity: "High".to_string(),
//!         category: "privilege_escalation".to_string(),
//!         weight: 35,
//!     },
//! ];
//! let assessment = calculate_risk(&matches);
//! println!("Risk: {} ({})", assessment.score, assessment.severity);
//! ```

use crate::core::RuleMeta;
use crate::core::{Confidence, Finding, RiskAssessment};
use std::cmp;
use std::collections::HashMap;

/// Maximum contribution cap per MITRE ATT&CK tactic category.
fn category_cap(category: &str) -> u32 {
    match category {
        "execution" => 25,
        "persistence" => 20,
        "privilege_escalation" => 30,
        "defense_evasion" => 35,
        "discovery" => 15,
        "collection" => 15,
        "command_and_control" => 25,
        "impact" => 20,
        _ => 20,
    }
}

/// Calculates a final risk score (0-100) using weighted category scoring.
///
/// Each matched rule contributes its weight to its declared MITRE ATT&CK tactic
/// category. Category contributions are individually capped to prevent
/// double-counting within the same tactic. The final score is the sum of
/// all capped category contributions.
pub fn calculate_risk(matched_rules: &[RuleMeta]) -> RiskAssessment {
    let mut category_scores: HashMap<String, u32> = HashMap::new();
    let mut findings: Vec<Finding> = Vec::new();

    for rule in matched_rules {
        let confidence = match rule.severity.to_lowercase().as_str() {
            "low" => Confidence::Low,
            "medium" => Confidence::Medium,
            "high" => Confidence::High,
            "critical" => Confidence::Critical,
            _ => Confidence::Medium,
        };

        findings.push(Finding {
            indicator: rule.name.clone(),
            description: format!("{} (MITRE ATT&CK: {})", rule.description, rule.mitre_attack),
            confidence,
            weight: rule.weight,
        });

        let entry = category_scores.entry(rule.category.clone()).or_insert(0);
        *entry += rule.weight;
    }

    // Apply per-category caps and sum
    let mut total_score: u32 = 0;
    for (category, raw_score) in &category_scores {
        let cap = category_cap(category);
        total_score += cmp::min(*raw_score, cap);
    }

    let final_score = cmp::min(100, total_score);

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

/// Generates high-level recommendations for security analysts based on the final risk score.
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
        let matches: Vec<RuleMeta> = vec![];
        let assessment = calculate_risk(&matches);
        assert_eq!(assessment.score, 0);
        assert_eq!(assessment.severity, "Safe");
        assert!(assessment.findings.is_empty());
    }

    #[test]
    fn test_calculate_risk_single_category() {
        let matches = vec![RuleMeta {
            name: "Test Rule".to_string(),
            description: "Test".to_string(),
            mitre_attack: "T1055".to_string(),
            severity: "Critical".to_string(),
            category: "privilege_escalation".to_string(),
            weight: 35,
        }];
        let assessment = calculate_risk(&matches);
        // Cap for privilege_escalation is 30, so 35 gets capped to 30
        assert_eq!(assessment.score, 30);
        assert_eq!(assessment.severity, "Suspicious");
        assert_eq!(assessment.findings.len(), 1);
    }

    #[test]
    fn test_calculate_risk_multiple_categories() {
        let matches = vec![
            RuleMeta {
                name: "Evasion Rule".to_string(),
                description: "Test".to_string(),
                mitre_attack: "T1027".to_string(),
                severity: "High".to_string(),
                category: "defense_evasion".to_string(),
                weight: 30,
            },
            RuleMeta {
                name: "Injection Rule".to_string(),
                description: "Test".to_string(),
                mitre_attack: "T1055".to_string(),
                severity: "Critical".to_string(),
                category: "privilege_escalation".to_string(),
                weight: 35,
            },
        ];
        let assessment = calculate_risk(&matches);
        // defense_evasion: min(30, 35) = 30
        // privilege_escalation: min(35, 30) = 30
        // total = 60
        assert_eq!(assessment.score, 60);
        assert_eq!(assessment.severity, "Suspicious");
    }

    #[test]
    fn test_calculate_risk_same_category_capped() {
        let matches = vec![
            RuleMeta {
                name: "Rule A".to_string(),
                description: "Test".to_string(),
                mitre_attack: "T1027".to_string(),
                severity: "High".to_string(),
                category: "defense_evasion".to_string(),
                weight: 25,
            },
            RuleMeta {
                name: "Rule B".to_string(),
                description: "Test".to_string(),
                mitre_attack: "T1622".to_string(),
                severity: "High".to_string(),
                category: "defense_evasion".to_string(),
                weight: 30,
            },
        ];
        let assessment = calculate_risk(&matches);
        // defense_evasion: min(25 + 30, 35) = 35
        assert_eq!(assessment.score, 35);
        assert_eq!(assessment.severity, "Suspicious");
        assert_eq!(assessment.findings.len(), 2);
    }
}
