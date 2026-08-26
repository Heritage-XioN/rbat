//! # Noisy-OR Risk Scoring Engine
//!
//! This module aggregates matched rule findings into a single risk score using
//! **noisy-OR probabilistic combination**:
//!
//! ```text
//! score = 100 · (1 − Π (1 − pᵢ))
//! ```
//!
//! where `pᵢ` is the per-finding probability derived from its [`SeverityClass`].
//! Each matched rule contributes exactly once regardless of how many ATT&CK
//! techniques it lists, eliminating the double-counting of the previous capped-sum
//! model. `Informational` and `Capability` findings carry zero probability mass, so
//! binaries that only exhibit ordinary capabilities trend naturally toward zero,
//! while corroborating hostile indicators compound smoothly toward the ceiling —
//! without arbitrary per-category caps.
//!
//! Classification of each rule is delegated to the [`SeverityClassifier`], which
//! honors explicit rule severities, TOML override tables, namespace defaults, and
//! built-in ATT&CK/MBC inference.
//!
//! # Example
//! ```rust
//! use rbat::utils::scoring::calculate_risk_with;
//! use rbat::core::RuleMeta;
//! use rbat::utils::rules::StringOrVec;
//! use rbat::utils::severity::SeverityClassifier;
//!
//! let rule = RuleMeta {
//!     name: "Test".to_string(),
//!     description: Some("Test rule".to_string()),
//!     mitre_attack: Some(StringOrVec::Single(
//!         "Privilege Escalation::Process Injection [T1055]".to_string(),
//!     )),
//!     severity: Some("Critical".to_string()),
//!     ..Default::default()
//! };
//!
//! let matches = vec![&rule];
//! let classifier = SeverityClassifier::embedded();
//!
//! let assessment = calculate_risk_with(&matches, &classifier);
//! println!("Risk: {} ({})", assessment.score, assessment.severity);
//! ```

use crate::core::types::{SAFE_MAX_SCORE, SUSPICIOUS_MAX_SCORE, SeverityClass};
use crate::core::{CategoryScore, Finding, FindingCounts, RiskAssessment, RuleMeta};
use crate::utils::rules::StringOrVec;
use crate::utils::severity::{SeverityClassifier, tactic_slug};
use ahash::{AHashMap, AHashSet};

/// Calculates a final risk score (0-100) using noisy-OR aggregation and a custom
/// [`SeverityClassifier`] (e.g. one extended with user override files).
pub fn calculate_risk_with(
    matched_rules: &[&RuleMeta],
    classifier: &SeverityClassifier,
) -> RiskAssessment {
    let mut findings: Vec<Finding> = Vec::with_capacity(matched_rules.len());
    let mut counts = FindingCounts::default();
    // Noisy-OR survival product: Π(1 − pᵢ) over weighted indicators.
    let mut survival: f64 = 1.0;
    // Per-tactic probability sums powering the dimensional breakdown.
    let mut category_probabilities: AHashMap<String, f64> = AHashMap::new();

    for rule in matched_rules {
        let severity_class = classifier.classify(rule);
        let description = rule.description.as_deref().unwrap_or("");
        let attack_ids = extract_bracketed_ids(rule.mitre_attack.as_ref());
        let mbc_ids = extract_bracketed_ids(rule.mbc.as_ref());
        let category = rule
            .mitre_attack
            .as_ref()
            .map(|m| m.as_vec())
            .unwrap_or_default()
            .iter()
            .find_map(|entry| tactic_slug(entry));

        match severity_class {
            SeverityClass::Informational => counts.informational += 1,
            SeverityClass::Capability => counts.capability += 1,
            SeverityClass::Low => counts.low += 1,
            SeverityClass::Medium => counts.medium += 1,
            SeverityClass::High => counts.high += 1,
            SeverityClass::Critical => counts.critical += 1,
        }

        survival *= 1.0 - severity_class.probability();
        if let Some(category) = &category {
            *category_probabilities
                .entry(category.clone())
                .or_insert(0.0) += severity_class.probability();
        }

        findings.push(Finding {
            indicator: rule.name.clone(),
            description: description.to_string(),
            severity_class,
            attack_ids,
            mbc_ids,
            category,
            namespace: rule.namespace.clone(),
        });
    }

    findings.sort_by(|a, b| {
        b.severity_class
            .cmp(&a.severity_class)
            .then_with(|| a.indicator.cmp(&b.indicator))
    });

    let score = (((1.0 - survival) * 100.0).round() as u32).min(100);

    let mut category_breakdown: Vec<CategoryScore> = category_probabilities
        .into_iter()
        .map(|(category, probability)| CategoryScore {
            category,
            score: saturating_percentage(probability),
        })
        .collect();
    category_breakdown.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.category.cmp(&b.category))
    });

    let severity = verdict_band(score);

    RiskAssessment {
        score,
        severity,
        recommendations: generate_recommendations(score, &counts),
        findings,
        category_breakdown,
        finding_counts: counts,
    }
}

/// Maps an aggregated score to its qualitative verdict band.
fn verdict_band(score: u32) -> String {
    if score <= SAFE_MAX_SCORE {
        "Safe"
    } else if score <= SUSPICIOUS_MAX_SCORE {
        "Suspicious"
    } else {
        "Malicious"
    }
    .to_string()
}

/// Saturating percentage conversion: `100 · (1 − e^(−Σp))`, rounded and clamped.
fn saturating_percentage(probability_sum: f64) -> u8 {
    let pct = (1.0 - (-probability_sum).exp()) * 100.0;
    pct.round().clamp(0.0, 100.0) as u8
}

/// Extracts deduplicated bracketed identifiers (`[T1059.003]`, `[C0029]`) from a
/// rule mapping field, falling back to bare IDs like `"T1098"`.
fn extract_bracketed_ids(mapping: Option<&StringOrVec>) -> Vec<String> {
    let mut ids: AHashSet<String> = mapping
        .map(|m| m.as_vec())
        .unwrap_or_default()
        .iter()
        .map(|entry| StringOrVec::extract_mitre_id_from(entry))
        .filter(|id| !id.is_empty())
        .collect();
    // Bare fallbacks that still look like MITRE technique IDs stay meaningful.
    ids.retain(|id| id.starts_with(|c: char| c.is_ascii_alphabetic()));
    let mut sorted: Vec<String> = ids.into_iter().collect();
    sorted.sort();
    sorted
}

/// Generates high-level recommendations for security analysts based on the verdict band.
fn generate_recommendations(score: u32, counts: &FindingCounts) -> Vec<String> {
    let mut recs = Vec::new();

    if counts.indicator_count() == 0 && counts.capability + counts.informational > 0 {
        recs.push(
            "No threat indicators detected; matched items are ordinary capabilities or \
             build artifacts."
                .to_string(),
        );
    }

    match verdict_band(score).as_str() {
        "Safe" => {
            recs.push(
                "No immediate threat detected. Standard execution is permissible.".to_string(),
            );
        }
        "Suspicious" => {
            recs.push(
                "Flagged for manual review. Do not execute in a production environment."
                    .to_string(),
            );
            recs.push("Submit binary hash to VirusTotal for community correlation.".to_string());
        }
        _ => {
            recs.push("IMMEDIATE QUARANTINE REQUIRED.".to_string());
            recs.push(
                "Execute strictly within a heavily monitored, isolated sandbox environment."
                    .to_string(),
            );
        }
    }

    recs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(name: &str, attack: StringOrVec, severity: &str) -> RuleMeta {
        RuleMeta {
            name: name.to_string(),
            description: Some("Desc".to_string()),
            mitre_attack: Some(attack),
            severity: Some(severity.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn test_calculate_risk_empty() {
        let assessment = calculate_risk_with(&[], &SeverityClassifier::embedded());

        assert_eq!(assessment.score, 0);
        assert_eq!(assessment.severity, "Safe");
        assert!(assessment.findings.is_empty());
        assert_eq!(assessment.finding_counts.indicator_count(), 0);
    }

    #[test]
    fn test_single_critical_indicator() {
        let r1 = rule(
            "Injection",
            StringOrVec::Single("Privilege Escalation::Process Injection [T1055]".to_string()),
            "critical",
        );

        let assessment = calculate_risk_with(&[&r1], &SeverityClassifier::embedded());
        // Critical carries probability 0.4 → 40% after noisy-OR.
        assert_eq!(assessment.score, 40);
        assert_eq!(assessment.severity, "Suspicious");
        assert_eq!(
            assessment.findings[0].severity_class,
            SeverityClass::Critical
        );
        assert_eq!(assessment.findings[0].attack_ids, vec!["T1055"]);
        assert_eq!(
            assessment.findings[0].category.as_deref(),
            Some("privilege_escalation")
        );
    }

    #[test]
    fn test_capabilities_never_contribute_to_score() {
        let mut file_op = RuleMeta {
            name: "create directory".to_string(),
            ..Default::default()
        };
        file_op.mitre_attack = Some(StringOrVec::Single(
            "Discovery::File and Directory Discovery [T1083]".to_string(),
        ));
        let compiler_artifact = RuleMeta {
            name: "compiled with AutoHotKey".to_string(),
            namespace: Some("compiler/autohotkey".to_string()),
            mitre_attack: Some(StringOrVec::Single(
                "Execution::Command and Scripting Interpreter [T1059]".to_string(),
            )),
            ..Default::default()
        };

        let assessment = calculate_risk_with(
            &[&file_op, &compiler_artifact],
            &SeverityClassifier::embedded(),
        );
        assert_eq!(assessment.score, 0);
        assert_eq!(assessment.severity, "Safe");
        assert_eq!(assessment.finding_counts.capability, 1);
        assert_eq!(assessment.finding_counts.informational, 1);
        assert_eq!(assessment.finding_counts.indicator_count(), 0);
    }

    #[test]
    fn test_noisy_or_corroboration_compounds() {
        let highs: Vec<RuleMeta> = [
            "Privilege Escalation::Process Injection [T1055]",
            "Defense Evasion::Obfuscated Files or Information [T1027]",
        ]
        .into_iter()
        .map(|attack| rule("High Rule", StringOrVec::Single(attack.to_string()), "high"))
        .collect();

        let refs: Vec<&RuleMeta> = highs.iter().collect();
        let assessment = calculate_risk_with(&refs, &SeverityClassifier::embedded());
        // Two High indicators: 1 − 0.75² ≈ 43.75% → 44 (Suspicious).
        assert_eq!(assessment.score, 44);
        assert_eq!(assessment.severity, "Suspicious");

        let mediums: Vec<RuleMeta> = [
            "Execution::A [T1106]",
            "Persistence::B [T1060]",
            "Command and Control::C [T1095]",
        ]
        .into_iter()
        .map(|attack| {
            rule(
                "Med Rule",
                StringOrVec::Single(attack.to_string()),
                "medium",
            )
        })
        .collect();
        let combined: Vec<&RuleMeta> = highs.iter().chain(mediums.iter()).collect();
        let combined_assessment = calculate_risk_with(&combined, &SeverityClassifier::embedded());
        // 1 − 0.75² · 0.92³ ≈ 56% → 56 (Malicious).
        assert_eq!(combined_assessment.score, 56);
        assert_eq!(combined_assessment.severity, "Malicious");
    }

    #[test]
    fn test_generic_capabilities_do_not_reach_malicious_band() {
        // Regression: ffmpeg-like profiles (many generic capabilities + a few weak
        // crypto primitives) must not aggregate into the Malicious band.
        let generic_names = [
            "accept command line arguments",
            "create directory",
            "delete file",
            "get common file path",
            "get hostname",
            "resolve DNS",
            "connect socket",
            "send data on socket",
            "create thread",
            "terminate process",
        ];
        let rules: Vec<RuleMeta> = generic_names
            .iter()
            .chain(std::iter::once(&"generate random numbers via RtlGenRandom"))
            .map(|name| RuleMeta {
                name: (*name).to_string(),
                ..Default::default()
            })
            .collect();
        let refs: Vec<&RuleMeta> = rules.iter().collect();

        let assessment = calculate_risk_with(&refs, &SeverityClassifier::embedded());
        assert_eq!(assessment.score, 2);
        assert_eq!(assessment.severity, "Safe");
    }

    #[test]
    fn test_iced_backend_ffmpeg_style_profile_is_suspicious_not_malicious() {
        // Regression: the iced backend surfaces AES-NI + anti-debug instruction
        // rules on ffmpeg. The crypto primitives must demote to Low, leaving a
        // single High (rdtsc anti-debug) → ~31% Suspicious, never Malicious.
        // Single High indicator: rdtsc-based anti-debugging. Classification runs
        // through the full inference chain (anti-analysis MBC objective → High).
        let high_rule = RuleMeta {
            name: "execute anti-debugging instructions".to_string(),
            namespace: Some("anti-analysis/anti-debugging/debugger-detection".to_string()),
            mbc: Some(crate::utils::rules::StringOrVec::Single(
                "Anti-Behavioral Analysis::Debugger Detection::Anti-debugging Instructions [B0001.034]"
                    .to_string(),
            )),
            ..Default::default()
        };

        let aes_rule = |mitre: &str| {
            let mut r = RuleMeta {
                name: "AES via x86 extensions".to_string(),
                namespace: Some("data-manipulation/encryption/aes".to_string()),
                mbc: Some(crate::utils::rules::StringOrVec::Single(
                    "Cryptography::Encrypt Data [C0027.001]".to_string(),
                )),
                ..Default::default()
            };
            r.mitre_attack = Some(crate::utils::rules::StringOrVec::Single(mitre.to_string()));
            r
        };

        let ioctl = RuleMeta {
            name: "interact with driver via IOCTL".to_string(),
            ..Default::default()
        };

        let capabilities: Vec<RuleMeta> = [
            "accept command line arguments",
            "connect socket",
            "send data on socket",
            "receive data on socket",
            "resolve DNS",
        ]
        .iter()
        .map(|name| RuleMeta {
            name: (*name).to_string(),
            ..Default::default()
        })
        .collect();

        let rules: Vec<RuleMeta> = std::iter::once(high_rule)
            .chain([
                aes_rule("Defense Evasion::Obfuscated Files or Information [T1027]"),
                aes_rule("Defense Evasion::Deobfuscate/Decode Files or Information [T1140]"),
                ioctl,
            ])
            .chain(capabilities)
            .collect();
        let refs: Vec<&RuleMeta> = rules.iter().collect();

        let assessment = calculate_risk_with(&refs, &SeverityClassifier::embedded());
        // 1 − 0.75 · 0.98³ ≈ 29.4% (anti-debug High + 3 Lows; capabilities free).
        assert_eq!(assessment.score, 29);
        assert_eq!(assessment.severity, "Suspicious");
        assert_eq!(assessment.finding_counts.high, 1);
        assert_eq!(assessment.finding_counts.low, 3);
    }

    #[test]
    fn test_multi_technique_rule_counts_once() {
        let single = rule(
            "Single",
            StringOrVec::Single("Execution::DLL Injection [T1055.001]".to_string()),
            "high",
        );
        let multi = rule(
            "Multi",
            StringOrVec::List(vec![
                "Execution::DLL Injection [T1055.001]".to_string(),
                "Persistence::Boot Autostart Execution [T1060]".to_string(),
                "Defense Evasion::Extra [T1027]".to_string(),
            ]),
            "high",
        );

        let a = calculate_risk_with(&[&single], &SeverityClassifier::embedded());
        let b = calculate_risk_with(&[&multi], &SeverityClassifier::embedded());
        // Identical probability mass despite three listed techniques.
        assert_eq!(a.score, b.score);
        assert_eq!(a.score, 25);
        // Primary category resolves to the first resolvable tactic.
        assert_eq!(b.findings[0].category.as_deref(), Some("execution"));
        assert_eq!(b.findings[0].attack_ids.len(), 3);
    }

    #[test]
    fn test_unmapped_rule_defaults_to_low() {
        let bare = RuleMeta {
            name: "NoMitre".to_string(),
            ..Default::default()
        };

        let assessment = calculate_risk_with(&[&bare], &SeverityClassifier::embedded());
        assert_eq!(assessment.score, 2);
        assert_eq!(assessment.findings[0].severity_class, SeverityClass::Low);
        assert!(assessment.findings[0].category.is_none());
        assert_eq!(assessment.category_breakdown, vec![]);
    }

    #[test]
    fn test_findings_sorted_by_severity_desc_then_name() {
        let low = rule("aaa Low", StringOrVec::Single("T1098".to_string()), "low");
        let high = rule("zzz High", StringOrVec::Single("T1027".to_string()), "high");
        let capability = RuleMeta {
            name: "create thread".to_string(),
            ..Default::default()
        };

        let assessment =
            calculate_risk_with(&[&low, &capability, &high], &SeverityClassifier::embedded());
        let classes: Vec<SeverityClass> = assessment
            .findings
            .iter()
            .map(|f| f.severity_class)
            .collect();
        assert_eq!(
            classes,
            vec![
                SeverityClass::High,
                SeverityClass::Low,
                SeverityClass::Capability
            ]
        );
    }

    #[test]
    fn test_category_breakdown_saturates_per_tactic() {
        let rules: Vec<RuleMeta> = ["High One", "High Two"]
            .iter()
            .map(|name| {
                rule(
                    name,
                    StringOrVec::Single(
                        "Defense Evasion::Obfuscated Files or Information [T1027]".to_string(),
                    ),
                    "high",
                )
            })
            .collect();
        let refs: Vec<&RuleMeta> = rules.iter().collect();

        let assessment = calculate_risk_with(&refs, &SeverityClassifier::embedded());
        assert_eq!(assessment.category_breakdown.len(), 1);
        let entry = &assessment.category_breakdown[0];
        assert_eq!(entry.category, "defense_evasion");
        // Σp = 0.5 → 1 − e^(−0.5) ≈ 39.3% → 39.
        assert_eq!(entry.score, 39);
    }

    #[test]
    fn test_score_clamped_at_100() {
        let rules: Vec<RuleMeta> = (0..20)
            .map(|i| {
                rule(
                    &format!("Rule {i}"),
                    StringOrVec::Single(format!("Impact::X [T1486.{i}]")),
                    "critical",
                )
            })
            .collect();
        let refs: Vec<&RuleMeta> = rules.iter().collect();

        let assessment = calculate_risk_with(&refs, &SeverityClassifier::embedded());
        assert_eq!(assessment.score, 100);
        assert_eq!(assessment.severity, "Malicious");
    }

    #[test]
    fn test_probability_constants_are_monotonic() {
        use crate::core::types::{
            CRITICAL_PROBABILITY, HIGH_PROBABILITY, LOW_PROBABILITY, MEDIUM_PROBABILITY,
        };
        const {
            assert!(LOW_PROBABILITY < MEDIUM_PROBABILITY);
            assert!(MEDIUM_PROBABILITY < HIGH_PROBABILITY);
            assert!(HIGH_PROBABILITY < CRITICAL_PROBABILITY);
        }
    }
}
