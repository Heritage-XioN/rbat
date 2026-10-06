//! # Probabilistic Threat Risk Scoring Engine
//!
//! Aggregates classified security findings into an objective risk assessment using
//! **noisy-OR probabilistic combination**, dimensional MITRE ATT&CK tactic breakdowns,
//! and calibrated qualitative verdict bands.
//!
//! Rather than relying on simple linear addition or arbitrary heuristic caps, `rbat` models
//! each detected behavioral rule as an independent probabilistic indicator of malicious intent.
//! The resulting score represents the cumulative probability that at least one detected behavior
//! reflects genuine threat activity.
//!
//! ## Core Types
//!
//! - [`RiskAssessment`]: Comprehensive risk assessment containing final score, verdict, findings, breakdowns, and recommendations.
//! - [`Finding`]: Individual behavioral capability or threat indicator discovered during analysis.
//! - [`CategoryScore`]: Saturated sub-score (`0..=100`) measuring threat concentration within a specific MITRE ATT&CK tactic.
//! - [`FindingCounts`]: Granular tallies of findings across all [`SeverityClass`] tiers.
//!
//! ## Noisy-OR Mathematical Model
//!
//! The aggregated threat score is computed via the noisy-OR formulation:
//!
//! ```text
//! Score = min(100, round(100 × (1 − ∏ (1 − pᵢ))))
//! ```
//!
//! where $p_i \in [0.0, 1.0]$ represents the independent malicious probability assigned to finding $i$
//! based on its [`SeverityClass`]:
//!
//! - **Benign Immunity**: Findings classified as [`SeverityClass::Informational`] or [`SeverityClass::Capability`]
//!   carry $p_i = 0.0$. They never contribute to the product, ensuring that binaries rich in benign OS
//!   capabilities (network sockets, file manipulation, thread pools) trend naturally toward a score of `0`.
//! - **Corroborating Evidence**: Weak and medium indicators compound asymptotically. For example, multiple
//!   medium findings ($p = 0.08$) compound cleanly ($1 - (1 - 0.08)^5 \approx 34\%$) without premature
//!   saturation or arbitrary clipping.
//! - **Saturated Upper Bound**: A single critical finding ($p = 0.40$) immediately yields a score of `40`
//!   (Suspicious), and two critical findings compound to $1 - (1 - 0.40)^2 = 64\%$ (Malicious).
//!
//! ## Verdict Bands and Operational Guidance
//!
//! Scores are mapped into three qualitative evaluation bands:
//!
//! | Score Range | Verdict Band | Interpretation & Operational Guidance |
//! | :--- | :--- | :--- |
//! | `0..=14` | `"Safe"` | Standard execution permissible. Benign capabilities or harmless compiler artifacts. |
//! | `15..=49` | `"Suspicious"` | Flagged for manual analyst inspection. Do not run in production. Community hash lookup advised. |
//! | `50..=100` | `"Malicious"` | Immediate quarantine required. Restrict execution strictly to an isolated sandbox. |
//!
//! ## Dimensional Tactic Breakdowns
//!
//! In addition to global risk aggregation, the engine independently tracks survival probabilities
//! across MITRE ATT&CK tactic categories. Each category's saturated sub-score is reported in
//! [`RiskAssessment::category_breakdown`], enabling analysts to immediately pinpoint the dominant
//! threat dimension (e.g. `defense_evasion` vs `credential_access`).
//!
//! ## Examples
//!
//! ```rust
//! use rbat::core::{
//!   rule::RuleMeta,
//!   scoring::{risk::RiskAssessment, classifier::SeverityClassifier},
//! };
//!
//! let classifier = SeverityClassifier::embedded();
//! let rule = RuleMeta {
//!     name: "create process suspended".to_string(),
//!     namespace: Some("process/creation".to_string()),
//!     ..Default::default()
//! };
//!
//! let assessment = RiskAssessment::calculate_risk(&[&rule], &classifier);
//! assert!(assessment.score <= 100);
//! assert!(matches!(assessment.severity.as_str(), "Safe" | "Suspicious" | "Malicious"));
//! ```

use crate::core::{
    rule::{RuleMeta, StringOrVec},
    scoring::classifier::{SeverityClass, SeverityClassifier},
};
use ahash::{AHashMap, AHashSet};
use serde::{Deserialize, Serialize};

/// Maximum score (inclusive, `14`) classified under the `"Safe"` verdict band.
pub const SAFE_MAX_SCORE: u32 = 14;
/// Maximum score (inclusive, `49`) classified under the `"Suspicious"` verdict band; scores `50` and above are `"Malicious"`.
pub const SUSPICIOUS_MAX_SCORE: u32 = 49;

/// Comprehensive security assessment encapsulating the overall risk score, verdict, and findings.
///
/// Includes qualitative threat rating, full list of findings ordered by descending severity,
/// actionable mitigation guidance, and dimensional category sub-scores.
///
/// # Examples
///
/// ```rust
/// use rbat::core::scoring::{RiskAssessment, SeverityClassifier};
///
/// let assessment = RiskAssessment::calculate_risk(&[], &SeverityClassifier::embedded());
/// assert_eq!(assessment.score, 0);
/// assert_eq!(assessment.severity, "Safe");
/// assert!(assessment.findings.is_empty());
/// ```
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct RiskAssessment {
    /// The final numeric score ranging from `0` (Safe) to `100` (Highly Malicious).
    pub score: u32,
    /// Qualitative severity evaluation: `"Safe"`, `"Suspicious"`, or `"Malicious"`.
    pub severity: String,
    /// Detailed list of security findings sorted by descending severity.
    pub findings: Vec<Finding>,
    /// Actionable mitigation and remediation steps.
    pub recommendations: Vec<String>,
    /// Per-ATT&CK-tactic saturated sub-scores for dimensional breakdowns.
    #[serde(default)]
    pub category_breakdown: Vec<CategoryScore>,
    /// Per-class finding tallies powering summary lines.
    #[serde(default)]
    pub finding_counts: FindingCounts,
}

impl RiskAssessment {
    /// Aggregates a slice of matched security rules into a unified [`RiskAssessment`].
    ///
    /// Evaluates rules against the supplied [`SeverityClassifier`] to resolve severities,
    /// applies noisy-OR combination to compute global and per-category threat scores,
    /// maps the numeric score to a qualitative verdict band, and generates targeted
    /// analyst recommendations.
    ///
    /// # Parameters
    ///
    /// - `matched_rules`: Slice of references to [`RuleMeta`] for rules that triggered during analysis.
    /// - `classifier`: Reference to the [`SeverityClassifier`] used for severity determination.
    ///
    /// # Returns
    ///
    /// A fully populated [`RiskAssessment`] with findings sorted by descending severity,
    /// granular finding counts, dimensional category breakdown, and operational recommendations.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rbat::core::{
    ///   rule::RuleMeta,
    ///   scoring::{RiskAssessment, SeverityClassifier},
    /// };
    ///
    /// let classifier = SeverityClassifier::embedded();
    /// let rule = RuleMeta {
    ///     name: "create thread in remote process".to_string(),
    ///     namespace: Some("injection/remote-thread".to_string()),
    ///     severity: Some("high".to_string()),
    ///     ..Default::default()
    /// };
    ///
    /// let assessment = RiskAssessment::calculate_risk(&[&rule], &classifier);
    /// assert_eq!(assessment.score, 25);
    /// assert_eq!(assessment.severity, "Suspicious");
    /// assert_eq!(assessment.finding_counts.high, 1);
    /// ```
    pub fn calculate_risk(matched_rules: &[&RuleMeta], classifier: &SeverityClassifier) -> Self {
        let mut findings: Vec<Finding> = Vec::with_capacity(matched_rules.len());
        let mut counts = FindingCounts::default();
        // Noisy-OR survival product: Π(1 − pᵢ) over weighted indicators.
        let mut survival: f64 = 1.0;
        // Per-tactic Noisy-OR survival products powering the dimensional breakdown.
        let mut category_survivals: AHashMap<String, f64> = AHashMap::new();

        for rule in matched_rules {
            let severity_class = classifier.classify(rule);
            let description = rule.description.as_deref().unwrap_or("");
            let attack_ids = Self::extract_bracketed_ids(rule.mitre_attack.as_ref());
            let mbc_ids = Self::extract_bracketed_ids(rule.mbc.as_ref());
            let category = rule
                .mitre_attack
                .as_ref()
                .map(|m| m.to_vec())
                .unwrap_or_default()
                .iter()
                .find_map(|entry| SeverityClassifier::tactic_slug(entry));

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
                *category_survivals.entry(category.clone()).or_insert(1.0) *=
                    1.0 - severity_class.probability();
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

        let mut category_breakdown: Vec<CategoryScore> = category_survivals
            .into_iter()
            .map(|(category, survival)| CategoryScore {
                category,
                score: (((1.0 - survival) * 100.0).round() as u8).min(100),
            })
            .collect();
        category_breakdown.sort_by(|a, b| {
            b.score
                .cmp(&a.score)
                .then_with(|| a.category.cmp(&b.category))
        });

        let severity = Self::verdict_band(score);

        RiskAssessment {
            score,
            severity,
            recommendations: Self::generate_recommendations(score, &counts),
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

    /// Extracts deduplicated bracketed identifiers (`[T1059.003]`, `[C0029]`) from a
    /// rule mapping field, falling back to bare IDs like `"T1098"`.
    fn extract_bracketed_ids(mapping: Option<&StringOrVec>) -> Vec<String> {
        let mut ids: AHashSet<String> = mapping
            .map(|m| m.to_vec())
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

        match Self::verdict_band(score).as_str() {
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
                recs.push(
                    "Submit binary hash to VirusTotal for community correlation.".to_string(),
                );
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
}

/// A specific behavioral capability or threat indicator discovered during analysis.
///
/// Findings capture matched rule metadata, assigned severity, MITRE ATT&CK and MBC
/// technique mappings, and high-level categorization.
///
/// # Examples
///
/// ```rust
/// use rbat::core::scoring::{Finding, SeverityClass};
///
/// let finding = Finding {
///     indicator: "process_hollowing".to_string(),
///     description: "Injects code into a suspended host process".to_string(),
///     severity_class: SeverityClass::High,
///     ..Default::default()
/// };
/// assert_eq!(finding.severity_class, SeverityClass::High);
/// ```
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Finding {
    /// The shorthand description or type of the finding.
    pub indicator: String,
    /// A detailed explanation of what was found and why it is flagged.
    pub description: String,
    /// Behavioral classification controlling risk weight and rendering color.
    #[serde(default)]
    pub severity_class: SeverityClass,
    /// MITRE ATT&CK technique IDs mapped by the source rule (e.g. `"T1059.003"`).
    #[serde(default)]
    pub attack_ids: Vec<String>,
    /// Malware Behavior Catalog IDs mapped by the source rule (e.g. `"C0029"`).
    #[serde(default)]
    pub mbc_ids: Vec<String>,
    /// Primary MITRE ATT&CK tactic slug bucketing this finding (e.g. `"execution"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Source rule namespace path (e.g. `"communication/c2/shell"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

/// Saturated sub-score measuring threat concentration within a specific MITRE ATT&CK tactic category.
///
/// Computed via independent noisy-OR aggregation of findings belonging to that tactic.
///
/// # Examples
///
/// ```rust
/// use rbat::core::scoring::CategoryScore;
///
/// let cat = CategoryScore {
///     category: "defense_evasion".to_string(),
///     score: 45,
/// };
/// assert_eq!(cat.score, 45);
/// ```
#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq, Eq)]
pub struct CategoryScore {
    /// ATT&CK tactic slug (e.g. `"defense_evasion"`).
    pub category: String,
    /// Saturated category score in `0..=100`.
    pub score: u8,
}

/// Aggregated tallies of findings categorized by [`SeverityClass`].
///
/// Used in summary badges, terminal banners, and JSON report headers.
///
/// # Examples
///
/// ```rust
/// use rbat::core::scoring::FindingCounts;
///
/// let counts = FindingCounts {
///     critical: 1,
///     high: 2,
///     medium: 0,
///     low: 3,
///     capability: 5,
///     informational: 2,
/// };
/// assert_eq!(counts.indicator_count(), 6);
/// ```
#[derive(Serialize, Deserialize, Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct FindingCounts {
    /// Number of critical-severity findings.
    pub critical: u32,
    /// Number of high-severity findings.
    pub high: u32,
    /// Number of medium-severity findings.
    pub medium: u32,
    /// Number of low-severity findings.
    pub low: u32,
    /// Number of capability-class (benign behavioral) findings.
    pub capability: u32,
    /// Number of informational (compiler/artifact) findings.
    pub informational: u32,
}

impl FindingCounts {
    /// Computes the total number of genuine threat indicators (`Critical` + `High` + `Medium` + `Low`).
    ///
    /// Benign `Capability` and `Informational` items are excluded from this count.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rbat::core::scoring::FindingCounts;
    ///
    /// let counts = FindingCounts {
    ///     critical: 1,
    ///     high: 1,
    ///     ..Default::default()
    /// };
    /// assert_eq!(counts.indicator_count(), 2);
    /// ```
    pub fn indicator_count(&self) -> u32 {
        self.critical + self.high + self.medium + self.low
    }
}

#[cfg(test)]
mod tests {
    use crate::core::scoring::classifier::{
        CRITICAL_PROBABILITY, HIGH_PROBABILITY, LOW_PROBABILITY, MEDIUM_PROBABILITY,
    };

    use super::*;

    fn rule_with_attack(name: &str, attack: StringOrVec, severity: &str) -> RuleMeta {
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
        let assessment = RiskAssessment::calculate_risk(&[], &SeverityClassifier::embedded());

        assert_eq!(assessment.score, 0);
        assert_eq!(assessment.severity, "Safe");
        assert!(assessment.findings.is_empty());
        assert_eq!(assessment.finding_counts.indicator_count(), 0);
    }

    #[test]
    fn test_single_critical_indicator() {
        let r1 = rule_with_attack(
            "Injection",
            StringOrVec::Single("Privilege Escalation::Process Injection [T1055]".to_string()),
            "critical",
        );

        let assessment = RiskAssessment::calculate_risk(&[&r1], &SeverityClassifier::embedded());
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

        let assessment = RiskAssessment::calculate_risk(
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
        .map(|attack| {
            rule_with_attack("High Rule", StringOrVec::Single(attack.to_string()), "high")
        })
        .collect();

        let refs: Vec<&RuleMeta> = highs.iter().collect();
        let assessment = RiskAssessment::calculate_risk(&refs, &SeverityClassifier::embedded());
        assert_eq!(assessment.score, 44);
        assert_eq!(assessment.severity, "Suspicious");

        let mediums: Vec<RuleMeta> = [
            "Execution::A [T1106]",
            "Persistence::B [T1060]",
            "Command and Control::C [T1095]",
        ]
        .into_iter()
        .map(|attack| {
            rule_with_attack(
                "Med Rule",
                StringOrVec::Single(attack.to_string()),
                "medium",
            )
        })
        .collect();
        let combined: Vec<&RuleMeta> = highs.iter().chain(mediums.iter()).collect();
        let combined_assessment =
            RiskAssessment::calculate_risk(&combined, &SeverityClassifier::embedded());
        assert_eq!(combined_assessment.score, 56);
        assert_eq!(combined_assessment.severity, "Malicious");
    }

    #[test]
    fn test_generic_capabilities_do_not_reach_malicious_band() {
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

        let assessment = RiskAssessment::calculate_risk(&refs, &SeverityClassifier::embedded());
        assert_eq!(assessment.score, 2);
        assert_eq!(assessment.severity, "Safe");
    }

    #[test]
    fn test_iced_backend_ffmpeg_style_profile_is_suspicious_not_malicious() {
        let high_rule = RuleMeta {
            name: "execute anti-debugging instructions".to_string(),
            namespace: Some("anti-analysis/anti-debugging/debugger-detection".to_string()),
            mbc: Some(StringOrVec::Single(
                "Anti-Behavioral Analysis::Debugger Detection::Anti-debugging Instructions [B0001.034]"
                    .to_string(),
            )),
            ..Default::default()
        };

        let aes_rule = |mitre: &str| {
            let mut r = RuleMeta {
                name: "AES via x86 extensions".to_string(),
                namespace: Some("data-manipulation/encryption/aes".to_string()),
                mbc: Some(StringOrVec::Single(
                    "Cryptography::Encrypt Data [C0027.001]".to_string(),
                )),
                ..Default::default()
            };
            r.mitre_attack = Some(StringOrVec::Single(mitre.to_string()));
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

        let assessment = RiskAssessment::calculate_risk(&refs, &SeverityClassifier::embedded());
        assert_eq!(assessment.score, 29);
        assert_eq!(assessment.severity, "Suspicious");
        assert_eq!(assessment.finding_counts.high, 1);
        assert_eq!(assessment.finding_counts.low, 3);
    }

    #[test]
    fn test_multi_technique_rule_counts_once() {
        let single = rule_with_attack(
            "Single",
            StringOrVec::Single("Execution::DLL Injection [T1055.001]".to_string()),
            "high",
        );
        let multi = rule_with_attack(
            "Multi",
            StringOrVec::List(vec![
                "Execution::DLL Injection [T1055.001]".to_string(),
                "Persistence::Boot Autostart Execution [T1060]".to_string(),
                "Defense Evasion::Extra [T1027]".to_string(),
            ]),
            "high",
        );

        let a = RiskAssessment::calculate_risk(&[&single], &SeverityClassifier::embedded());
        let b = RiskAssessment::calculate_risk(&[&multi], &SeverityClassifier::embedded());
        assert_eq!(a.score, b.score);
        assert_eq!(a.score, 25);
        assert_eq!(b.findings[0].category.as_deref(), Some("execution"));
        assert_eq!(b.findings[0].attack_ids.len(), 3);
    }

    #[test]
    fn test_unmapped_rule_defaults_to_low() {
        let bare = RuleMeta {
            name: "NoMitre".to_string(),
            ..Default::default()
        };

        let assessment = RiskAssessment::calculate_risk(&[&bare], &SeverityClassifier::embedded());
        assert_eq!(assessment.score, 2);
        assert_eq!(assessment.findings[0].severity_class, SeverityClass::Low);
        assert!(assessment.findings[0].category.is_none());
        assert_eq!(assessment.category_breakdown, vec![]);
    }

    #[test]
    fn test_findings_sorted_by_severity_desc_then_name() {
        let low = rule_with_attack("aaa Low", StringOrVec::Single("T1098".to_string()), "low");
        let high = rule_with_attack("zzz High", StringOrVec::Single("T1027".to_string()), "high");
        let capability = RuleMeta {
            name: "create thread".to_string(),
            ..Default::default()
        };

        let assessment = RiskAssessment::calculate_risk(
            &[&low, &capability, &high],
            &SeverityClassifier::embedded(),
        );
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
                rule_with_attack(
                    name,
                    StringOrVec::Single(
                        "Defense Evasion::Obfuscated Files or Information [T1027]".to_string(),
                    ),
                    "high",
                )
            })
            .collect();
        let refs: Vec<&RuleMeta> = rules.iter().collect();

        let assessment = RiskAssessment::calculate_risk(&refs, &SeverityClassifier::embedded());
        assert_eq!(assessment.category_breakdown.len(), 1);
        let entry = &assessment.category_breakdown[0];
        assert_eq!(entry.category, "defense_evasion");
        assert_eq!(entry.score, 44);
    }

    #[test]
    fn test_score_clamped_at_100() {
        let rules: Vec<RuleMeta> = (0..20)
            .map(|i| {
                rule_with_attack(
                    &format!("Rule {i}"),
                    StringOrVec::Single(format!("Impact::X [T1486.{i}]")),
                    "critical",
                )
            })
            .collect();
        let refs: Vec<&RuleMeta> = rules.iter().collect();

        let assessment = RiskAssessment::calculate_risk(&refs, &SeverityClassifier::embedded());
        assert_eq!(assessment.score, 100);
        assert_eq!(assessment.severity, "Malicious");
    }

    #[test]
    fn test_probability_constants_are_monotonic() {
        const {
            assert!(LOW_PROBABILITY < MEDIUM_PROBABILITY);
            assert!(MEDIUM_PROBABILITY < HIGH_PROBABILITY);
            assert!(HIGH_PROBABILITY < CRITICAL_PROBABILITY);
        }
    }
}
