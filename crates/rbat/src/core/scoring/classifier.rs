//! # Risk Scoring and Severity Classification Engine
//!
//! Maps matched capa rules to [`SeverityClass`] values and aggregates findings into a single
//! risk score using **noisy-OR probabilistic combination**:
//!
//! ```text
//! score = 100 · (1 − Π (1 − pᵢ))
//! ```
//!
//! where `pᵢ` is the per-finding probability derived from its [`SeverityClass`].
//! Classification honors explicit rule severities, TOML override tables, namespace defaults,
//! and built-in ATT&CK/MBC inference.

use crate::core::rule::RuleMeta;
use crate::core::types::{RbatError, RbatResult};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Embedded default override table shipped with the binary.
const EMBEDDED_OVERRIDES: &str = include_str!("../../../assets/capa-overrides.toml");

/// MITRE ATT&CK tactics recognized by the classification/scoring engines, in slug form.
const KNOWN_TACTICS: &[&str] = &[
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "discovery",
    "collection",
    "command_and_control",
    "impact",
    "credential_access",
    "exfiltration",
    "lateral_movement",
    "reconnaissance",
    "initial_access",
];

/// Tactics whose presence alone signals likely hostile intent.
const HIGH_THREAT_TACTICS: &[&str] = &[
    "defense_evasion",
    "credential_access",
    "privilege_escalation",
    "impact",
    "collection",
    "exfiltration",
    "lateral_movement",
];

/// Tactics commonly exercised by legitimate software; only moderately indicative.
const MEDIUM_THREAT_TACTICS: &[&str] = &["persistence", "command_and_control", "execution"];

/// MBC objective prefixes describing neutral cryptographic primitives. Usage of
/// hardware/SIMD crypto instructions (AES-NI, SHA extensions) is ubiquitous in
/// benign software, so such rules are demoted unless paired with evasion context.
const NEUTRAL_CRYPTO_OBJECTIVE: &str = "cryptography";

/// Namespace root under which neutral cryptographic primitive rules live.
const CRYPTO_NAMESPACE_ROOT: &str = "data-manipulation";

/// Noisy-OR probability weights per non-neutral [`SeverityClass`].
pub const LOW_PROBABILITY: f64 = 0.02;
pub const MEDIUM_PROBABILITY: f64 = 0.08;
pub const HIGH_PROBABILITY: f64 = 0.25;
pub const CRITICAL_PROBABILITY: f64 = 0.4;

/// Raw deserialized shape of the TOML override table.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct OverrideTable {
    /// Namespace root (e.g. `"compiler"`) → class string.
    namespace_defaults: BTreeMap<String, String>,
    /// Exact rule name → class string.
    overrides: BTreeMap<String, String>,
}

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

/// Classifies matched rules into [`SeverityClass`] values for scoring and rendering.
#[derive(Debug, Clone, Default)]
pub struct SeverityClassifier {
    namespace_defaults: BTreeMap<String, SeverityClass>,
    rule_overrides: BTreeMap<String, SeverityClass>,
}

impl SeverityClassifier {
    /// Builds the classifier from the embedded default override table.
    pub fn embedded() -> Self {
        Self::from_toml_str(EMBEDDED_OVERRIDES).unwrap_or_default()
    }

    /// Builds a standalone classifier from a TOML string. Returns an error describing
    /// the offending entry if the table cannot be parsed.
    pub fn from_toml_str(src: &str) -> RbatResult<Self> {
        let table: OverrideTable = toml::from_str(src)
            .map_err(|e| RbatError::ConfigError(format!("invalid override table: {e}")))?;
        Ok(Self::from_table(table))
    }

    fn from_table(table: OverrideTable) -> Self {
        let map_entries = |entries: BTreeMap<String, String>| {
            entries
                .into_iter()
                .filter_map(|(key, class)| match Self::parse_class(&class) {
                    Some(c) => Some((key.to_lowercase(), c)),
                    None => {
                        eprintln!("warning: unrecognized severity class '{class}' for '{key}'");
                        None
                    }
                })
                .collect()
        };
        Self {
            namespace_defaults: map_entries(table.namespace_defaults),
            rule_overrides: map_entries(table.overrides),
        }
    }

    /// Merges a TOML override file on top of the current tables. Later entries win,
    /// so user files can retune both built-in and custom classifications.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read or parsed.
    pub fn extend(path: &Option<PathBuf>) -> RbatResult<Self> {
        let mut classifier = SeverityClassifier::embedded();
        if let Some(path) = path {
            let src = std::fs::read_to_string(path).map_err(|e| {
                RbatError::ConfigError(format!("cannot read override file {}: {e}", path.display()))
            })?;
            let table: OverrideTable = toml::from_str(&src)
                .map_err(|e| RbatError::ConfigError(format!("invalid override file: {e}")))?;

            for (key, class) in table.namespace_defaults {
                if let Some(c) = Self::parse_class(&class) {
                    classifier.namespace_defaults.insert(key.to_lowercase(), c);
                } else {
                    eprintln!(
                        "warning: unrecognized severity class '{class}' for namespace '{key}' in {}",
                        path.display()
                    );
                }
            }
            for (key, class) in table.overrides {
                if let Some(c) = Self::parse_class(&class) {
                    classifier.rule_overrides.insert(key.to_lowercase(), c);
                } else {
                    eprintln!(
                        "warning: unrecognized severity class '{class}' for rule '{key}' in {}",
                        path.display()
                    );
                }
            }
        }
        Ok(classifier)
    }

    /// Resolves the effective [`SeverityClass`] for a matched rule.
    pub fn classify(&self, rule: &RuleMeta) -> SeverityClass {
        // 1. Explicit severity declared on the rule itself.
        if let Some(class) = rule.severity.as_deref().and_then(Self::parse_class) {
            return class;
        }

        // 2. Per-rule override entry.
        if let Some(class) = self.rule_overrides.get(&rule.name.to_lowercase()) {
            return *class;
        }

        // 3. Namespace-root default (compiler/, runtime/, ... artifacts).
        let namespace_root = rule
            .namespace
            .as_deref()
            .and_then(|ns| ns.split('/').next())
            .unwrap_or("")
            .to_lowercase();
        if let Some(class) = self.namespace_defaults.get(&namespace_root) {
            return *class;
        }

        Self::infer_from_mappings(rule)
    }

    /// Fallback inference from ATT&CK tactics, MBC objectives, and anti-analysis namespaces.
    fn infer_from_mappings(rule: &RuleMeta) -> SeverityClass {
        // Anti-analysis namespaces or MBC objectives are strong evasion indicators.
        let is_anti_analysis = Self::namespace_root_is(rule, "anti-analysis")
            || Self::mbc_objectives(rule)
                .iter()
                .any(|objective| objective.starts_with("anti-"));
        if is_anti_analysis {
            return SeverityClass::High;
        }

        let tactics = Self::attack_tactics(rule);

        // Cryptographic primitives (encrypt/decrypt/hash via AES-NI, SHA extensions,
        // generic implementations...) are ubiquitous in benign software. When the rule
        // lives under `data-manipulation` and its MBC mapping is purely cryptographic,
        // downgrade even if ATT&CK labels it Defense Evasion (T1027/T1140): primitive
        // usage alone is weak evidence of hostile intent.
        let objectives = Self::mbc_objectives(rule);
        let is_pure_crypto_primitive = Self::namespace_root_is(rule, CRYPTO_NAMESPACE_ROOT)
            && !objectives.is_empty()
            && objectives
                .iter()
                .all(|o| o.starts_with(NEUTRAL_CRYPTO_OBJECTIVE))
            // Defense Evasion alone (T1027/T1140-style obfuscation mappings) still
            // qualifies for the demotion; any other threat tactic blocks it.
            && tactics
                .iter()
                .all(|t| t == "defense_evasion");
        if is_pure_crypto_primitive {
            return SeverityClass::Low;
        }

        if tactics
            .iter()
            .any(|t| HIGH_THREAT_TACTICS.contains(&t.as_str()))
        {
            return SeverityClass::High;
        }
        if tactics
            .iter()
            .any(|t| MEDIUM_THREAT_TACTICS.contains(&t.as_str()))
        {
            return SeverityClass::Medium;
        }
        SeverityClass::Low
    }

    fn namespace_root_is(rule: &RuleMeta, expected: &str) -> bool {
        rule.namespace
            .as_deref()
            .and_then(|ns| ns.split('/').next())
            .is_some_and(|root| root.eq_ignore_ascii_case(expected))
    }

    /// Lowercase ATT&CK tactic slugs referenced by the rule.
    fn attack_tactics(rule: &RuleMeta) -> Vec<String> {
        rule.mitre_attack
            .as_ref()
            .map(|m| m.as_vec())
            .unwrap_or_default()
            .iter()
            .filter_map(|entry| Self::tactic_slug(entry))
            .collect()
    }

    /// Uppercase/lowercase-normalized MBC objective prefixes (segment before `::`).
    fn mbc_objectives(rule: &RuleMeta) -> Vec<String> {
        rule.mbc
            .as_ref()
            .map(|m| m.as_vec())
            .unwrap_or_default()
            .iter()
            .map(|entry| {
                entry
                    .split_once("::")
                    .map_or(entry.as_str(), |(objective, _)| objective)
                    .trim()
                    .to_lowercase()
            })
            .collect()
    }

    /// Normalizes a MITRE ATT&CK tactic name to its slug form
    /// (e.g. `"Defense Evasion"` -> `"defense_evasion"`).
    fn normalize_tactic(tactic: &str) -> String {
        tactic.trim().to_lowercase().replace([' ', '-'], "_")
    }

    /// Extracts the tactic slug from a formatted ATT&CK mapping such as
    /// `"Defense Evasion::Obfuscated Files or Information [T1027]"`.
    ///
    /// Returns `None` when the entry does not resolve to a known tactic, either
    /// because it lacks the `::` tactic prefix entirely or because the prefix is
    /// unrecognized.
    pub fn tactic_slug(entry: &str) -> Option<String> {
        let candidate = match entry.split_once("::") {
            Some((prefix, _)) => prefix,
            None => entry,
        };
        let slug = Self::normalize_tactic(candidate);
        KNOWN_TACTICS.contains(&slug.as_str()).then_some(slug)
    }

    /// Parses a human-readable class name into a [`SeverityClass`].
    fn parse_class(value: &str) -> Option<SeverityClass> {
        match value.trim().to_lowercase().as_str() {
            "informational" | "info" => Some(SeverityClass::Informational),
            "capability" | "benign" => Some(SeverityClass::Capability),
            "low" => Some(SeverityClass::Low),
            "medium" => Some(SeverityClass::Medium),
            "high" => Some(SeverityClass::High),
            "critical" => Some(SeverityClass::Critical),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::core::rule::StringOrVec;

    use super::*;

    fn crypto_primitive_rule(namespace: &str, mitre: &str) -> RuleMeta {
        let mut r = rule("encrypt data using AES via x86 extensions", Some(namespace));
        r.mbc = Some(StringOrVec::Single(
            "Cryptography::Encrypt Data [C0027.001]".to_string(),
        ));
        r.mitre_attack = Some(StringOrVec::Single(mitre.to_string()));
        r
    }

    fn rule(name: &str, namespace: Option<&str>) -> RuleMeta {
        RuleMeta {
            name: name.to_string(),
            namespace: namespace.map(str::to_string),
            ..Default::default()
        }
    }

    #[test]
    fn test_embedded_table_parses_and_applies_overrides() {
        let classifier = SeverityClassifier::embedded();
        assert_eq!(
            classifier.classify(&rule("create directory", None)),
            SeverityClass::Capability
        );
        assert_eq!(
            classifier.classify(&rule(
                "compiled with AutoHotKey",
                Some("compiler/autohotkey")
            )),
            SeverityClass::Informational
        );
    }

    #[test]
    fn test_explicit_rule_severity_wins() {
        let mut r = rule("create directory", None);
        r.severity = Some("critical".to_string());
        assert_eq!(
            SeverityClassifier::embedded().classify(&r),
            SeverityClass::Critical
        );
    }

    #[test]
    fn test_rule_override_beats_namespace_default() {
        let classifier = SeverityClassifier::from_toml_str(
            "[namespace_defaults]\ncompiler = \"informational\"\n[overrides]\n\"my custom rule\" = \"high\"\n",
        )
        .expect("valid toml");
        assert_eq!(
            classifier.classify(&rule("My Custom Rule", Some("compiler/x"))),
            SeverityClass::High
        );
        assert_eq!(
            classifier.classify(&rule("other artifact", Some("compiler/x"))),
            SeverityClass::Informational
        );
    }

    #[test]
    fn test_invalid_class_entries_are_skipped() {
        let classifier = SeverityClassifier::from_toml_str(
            "[overrides]\n\"bad entry\" = \"nonsense\"\n\"good entry\" = \"low\"\n",
        )
        .expect("valid toml");
        assert_eq!(
            classifier.classify(&rule("good entry", None)),
            SeverityClass::Low
        );
        // Unmatched names fall through to tactic inference (no mappings => Low).
        assert_eq!(
            classifier.classify(&rule("bad entry", None)),
            SeverityClass::Low
        );
    }

    #[test]
    fn test_anti_analysis_namespace_infers_high() {
        assert_eq!(
            SeverityClassifier::embedded().classify(&rule(
                "execute anti-debugging instructions",
                Some("anti-analysis/anti-debugging")
            )),
            SeverityClass::High
        );
    }

    #[test]
    fn test_mbc_anti_objective_infers_high() {
        let mut r = rule("pack the binary", None);
        r.mbc = Some(StringOrVec::Single(
            "Anti-Static Analysis::Software Packing [F0001]".to_string(),
        ));
        assert_eq!(
            SeverityClassifier::embedded().classify(&r),
            SeverityClass::High
        );
    }

    #[test]
    fn test_tactic_inference_ladder() {
        let mut high = rule("steal creds", None);
        high.mitre_attack = Some(StringOrVec::Single(
            "Credential Access::Credentials from Password Stores [T1555]".to_string(),
        ));

        let mut med = rule("spawn shell", None);
        med.mitre_attack = Some(StringOrVec::Single(
            "Execution::Windows Command Shell [T1059.003]".to_string(),
        ));

        let classifier = SeverityClassifier::embedded();
        assert_eq!(classifier.classify(&high), SeverityClass::High);
        assert_eq!(classifier.classify(&med), SeverityClass::Medium);
    }

    #[test]
    fn test_pure_crypto_primitive_demoted_to_low() {
        let classifier = SeverityClassifier::embedded();
        assert_eq!(
            classifier.classify(&crypto_primitive_rule(
                "data-manipulation/encryption/aes",
                "Defense Evasion::Obfuscated Files or Information [T1027]"
            )),
            SeverityClass::Low
        );
        assert_eq!(
            classifier.classify(&crypto_primitive_rule(
                "data-manipulation/encryption/aes",
                "Defense Evasion::Deobfuscate/Decode Files or Information [T1140]"
            )),
            SeverityClass::Low
        );
    }

    #[test]
    fn test_crypto_with_anti_analysis_context_stays_high() {
        let mut r = crypto_primitive_rule(
            "data-manipulation/encryption/aes",
            "Defense Evasion::Obfuscated Files or Information [T1027]",
        );
        r.namespace = Some("data-manipulation/encryption/aes".to_string());
        r.mbc = Some(StringOrVec::List(vec![
            "Anti-Static Analysis::Executable Code Obfuscation [B0032]".to_string(),
            "Cryptography::Encrypt Data [C0027.001]".to_string(),
        ]));

        assert_eq!(
            SeverityClassifier::embedded().classify(&r),
            SeverityClass::High
        );
    }

    #[test]
    fn test_crypto_outside_data_manipulation_namespace_unchanged() {
        let classifier = SeverityClassifier::embedded();
        assert_eq!(
            classifier.classify(&crypto_primitive_rule(
                "communication/c2/encryption",
                "Defense Evasion::Obfuscated Files or Information [T1027]"
            )),
            SeverityClass::High
        );
    }

    #[test]
    fn test_crypto_with_high_threat_tactic_not_demoted() {
        let classifier = SeverityClassifier::embedded();
        assert_eq!(
            classifier.classify(&crypto_primitive_rule(
                "data-manipulation/encryption/aes",
                "Credential Access::Credentials from Password Stores [T1555]"
            )),
            SeverityClass::High
        );
    }

    #[test]
    fn test_crypto_without_mbc_mapping_not_demoted() {
        let mut r = rule("obfuscate payload", Some("data-manipulation/encryption"));
        r.mitre_attack = Some(StringOrVec::Single(
            "Defense Evasion::Obfuscated Files or Information [T1027]".to_string(),
        ));

        assert_eq!(
            SeverityClassifier::embedded().classify(&r),
            SeverityClass::High
        );
    }

    #[test]
    fn test_tactic_slug_extraction() {
        assert_eq!(
            SeverityClassifier::tactic_slug(
                "Defense Evasion::Obfuscated Files or Information [T1027]"
            ),
            Some("defense_evasion".to_string())
        );
        assert_eq!(SeverityClassifier::tactic_slug("T1055"), None);
        assert_eq!(SeverityClassifier::tactic_slug("Mobile::Unknown"), None);
    }
}
