//! Capa rule metadata structures.

use crate::core::types::RuleCondition;
use crate::utils::rules::StringOrVec;
use ahash::AHashMap;
use serde::{Deserialize, Serialize};

/// Metadata describing a security rule aligned with the Mandiant `capa` specification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct RuleMeta {
    /// The unique rule identifier name.
    pub name: String,
    /// Rule namespace path (e.g. `"communication/c2/shell"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Authors list or author attribution string.
    #[serde(default, alias = "author", skip_serializing_if = "Option::is_none")]
    pub authors: Option<StringOrVec>,
    /// Rule evaluation scopes (e.g. `{ "static": "function" }`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<AHashMap<String, String>>,
    /// Mapped MITRE ATT&CK technique list or ID (e.g. `["Execution::Windows Command Shell [T1059.003]"]` or `"T1055"`).
    #[serde(
        default,
        alias = "att&ck",
        alias = "attack",
        alias = "mitre_attack",
        skip_serializing_if = "Option::is_none"
    )]
    pub mitre_attack: Option<StringOrVec>,
    /// Malware Behavior Catalog (MBC) technique mappings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mbc: Option<StringOrVec>,
    /// Example binary hash offsets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub examples: Option<Vec<String>>,
    /// Detailed behavior explanation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Threat severity rating (`"Low"`, `"Medium"`, `"High"`, `"Critical"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// Reference URLs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub references: Option<Vec<String>>,
    /// Tag labels.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    /// Whether this is a library rule (referenced by other rules but not standalone).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lib: Option<bool>,
    /// MAEC malware category mapping.
    #[serde(
        default,
        rename = "maec/malware-category",
        skip_serializing_if = "Option::is_none"
    )]
    pub maec_malware_category: Option<String>,
    /// MAEC malware family mapping.
    #[serde(
        default,
        rename = "maec/malware-family",
        skip_serializing_if = "Option::is_none"
    )]
    pub maec_malware_family: Option<String>,
}

/// Supported tag-based feature conditions represented as raw strings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleTag {
    /// Signifies a code cave (NOP sled or null padding).
    CodeCave,
    /// Signifies a known packer signature.
    PackerSig,
    /// Signifies a tight loop construct.
    Loop,
}

/// The inner structure of the rules struct containing rule metadata and feature triggers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleInner {
    /// The rule metadata.
    pub meta: RuleMeta,
    /// The condition tree/features to evaluate.
    pub features: Vec<RuleCondition>,
}
