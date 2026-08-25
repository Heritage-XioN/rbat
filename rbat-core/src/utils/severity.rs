//! # Severity Classification Engine
//!
//! Maps matched capa rules to [`SeverityClass`] values using a precedence chain:
//!
//! 1. Explicit `severity` field on the rule (custom/user-authored rules win)
//! 2. Per-rule overrides from the TOML table (`assets/capa-overrides.toml` or a user file)
//! 3. Namespace-root defaults from the same table (e.g. `compiler/` → Informational)
//! 4. Built-in ATT&CK tactic / MBC objective inference
//!
//! The TOML table ships embedded but can be extended at runtime via
//! [`SeverityClassifier::merge_from_file`], letting operators retune classifications
//! without recompiling.
//!
//! This module also owns the shared MITRE ATT&CK tactic vocabulary and ID
//! extraction helpers reused by the scoring engine.

use crate::core::RuleMeta;
use crate::core::types::SeverityClass;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

/// Embedded default override table shipped with the binary.
const EMBEDDED_OVERRIDES: &str = include_str!("../../assets/capa-overrides.toml");

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

/// Raw deserialized shape of the TOML override table.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct OverrideTable {
    /// Namespace root (e.g. `"compiler"`) → class string.
    namespace_defaults: BTreeMap<String, String>,
    /// Exact rule name → class string.
    overrides: BTreeMap<String, String>,
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
    pub fn from_toml_str(src: &str) -> Result<Self, String> {
        let table: OverrideTable =
            toml::from_str(src).map_err(|e| format!("invalid override table: {e}"))?;
        Ok(Self::from_table(table))
    }

    fn from_table(table: OverrideTable) -> Self {
        let map_entries = |entries: BTreeMap<String, String>| {
            entries
                .into_iter()
                .filter_map(|(key, class)| parse_class(&class).map(|c| (key.to_lowercase(), c)))
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
    pub fn merge_from_file(&mut self, path: &Path) -> Result<(), String> {
        let src = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read override file {}: {e}", path.display()))?;
        let table: OverrideTable =
            toml::from_str(&src).map_err(|e| format!("invalid override file: {e}"))?;

        for (key, class) in table.namespace_defaults {
            if let Some(c) = parse_class(&class) {
                self.namespace_defaults.insert(key.to_lowercase(), c);
            }
        }
        for (key, class) in table.overrides {
            if let Some(c) = parse_class(&class) {
                self.rule_overrides.insert(key.to_lowercase(), c);
            }
        }
        Ok(())
    }

    /// Resolves the effective [`SeverityClass`] for a matched rule.
    pub fn classify(&self, rule: &RuleMeta) -> SeverityClass {
        // 1. Explicit severity declared on the rule itself.
        if let Some(class) = rule.severity.as_deref().and_then(parse_class) {
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

        infer_from_mappings(rule)
    }
}

/// Fallback inference from ATT&CK tactics, MBC objectives, and anti-analysis namespaces.
fn infer_from_mappings(rule: &RuleMeta) -> SeverityClass {
    // Anti-analysis namespaces or MBC objectives are strong evasion indicators.
    let is_anti_analysis = namespace_root_is(rule, "anti-analysis")
        || mbc_objectives(rule)
            .iter()
            .any(|objective| objective.starts_with("anti-"));
    if is_anti_analysis {
        return SeverityClass::High;
    }

    let tactics = attack_tactics(rule);
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
        .filter_map(|entry| tactic_slug(entry))
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
    let slug = normalize_tactic(candidate);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::rules::StringOrVec;

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
    fn test_merge_from_file_extends_tables() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("overrides.toml");
        std::fs::write(&path, "[overrides]\n\"create directory\" = \"high\"\n").unwrap();

        let mut classifier = SeverityClassifier::embedded();
        classifier.merge_from_file(&path).expect("merge ok");
        assert_eq!(
            classifier.classify(&rule("create directory", None)),
            SeverityClass::High
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
    fn test_tactic_slug_extraction() {
        assert_eq!(
            tactic_slug("Defense Evasion::Obfuscated Files or Information [T1027]"),
            Some("defense_evasion".to_string())
        );
        assert_eq!(tactic_slug("T1055"), None);
        assert_eq!(tactic_slug("Mobile::Unknown"), None);
    }
}
