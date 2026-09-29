//! Risk scoring structures and severity classification.

use serde::{Deserialize, Serialize};

/// Noisy-OR probability weights per non-neutral [`SeverityClass`].
pub const LOW_PROBABILITY: f64 = 0.02;
pub const MEDIUM_PROBABILITY: f64 = 0.08;
pub const HIGH_PROBABILITY: f64 = 0.25;
pub const CRITICAL_PROBABILITY: f64 = 0.4;

/// Verdict band thresholds applied to the aggregated noisy-OR score (0-100).
pub const SAFE_MAX_SCORE: u32 = 14;
pub const SUSPICIOUS_MAX_SCORE: u32 = 49;

/// Behavioral classification of a matched rule, driving both risk weighting and presentation.
///
/// Ordered from least to most severe; the derived [`Ord`] implementation powers
/// sort-by-severity rendering. `Informational` and `Capability` classes describe what a
/// binary *does* without asserting hostile intent and carry zero risk weight, while
/// `Low` through `Critical` are genuine threat indicators.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum SeverityClass {
    /// Build/compiler artifact or other non-behavioral match (e.g. `compiler/msvc`).
    #[default]
    Informational,
    /// Ordinary capability common in benign software (file ops, sockets, threads...).
    Capability,
    /// Weak threat indicator with high false-positive potential.
    Low,
    /// Notable indicator of potentially hostile behavior.
    Medium,
    /// Strong indicator of hostile behavior (evasion, credential access, impact...).
    High,
    /// Direct indicator of active evasion or hijacking techniques.
    Critical,
}

impl SeverityClass {
    /// Per-finding probability used by the noisy-OR risk aggregation.
    ///
    /// `Informational` and `Capability` findings contribute no probability mass and are
    /// excluded from the product entirely, so capability-heavy benign software trends
    /// toward a zero score.
    pub fn probability(self) -> f64 {
        match self {
            Self::Informational | Self::Capability => 0.0,
            Self::Low => LOW_PROBABILITY,
            Self::Medium => MEDIUM_PROBABILITY,
            Self::High => HIGH_PROBABILITY,
            Self::Critical => CRITICAL_PROBABILITY,
        }
    }

    /// Short uppercase label suitable for badge columns.
    pub fn label(self) -> &'static str {
        match self {
            Self::Informational => "INFO",
            Self::Capability => "CAPABILITY",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

/// A specific behavioral capability or threat indicator discovered during analysis.
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

/// Saturated per-tactic contribution to the overall risk score, for dimensional breakdowns.
#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq, Eq)]
pub struct CategoryScore {
    /// ATT&CK tactic slug (e.g. `"defense_evasion"`).
    pub category: String,
    /// Saturated category score in `0..=100`.
    pub score: u8,
}

/// Tallies of findings per [`SeverityClass`] for summary lines.
#[derive(Serialize, Deserialize, Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct FindingCounts {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub capability: u32,
    pub informational: u32,
}

impl FindingCounts {
    /// Total number of genuine threat indicators (`Critical`+`High`+`Medium`+`Low`).
    pub fn indicator_count(&self) -> u32 {
        self.critical + self.high + self.medium + self.low
    }
}

/// The aggregated security assessment containing the threat score and findings.
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
