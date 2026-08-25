//! # Threat Detection Rules Parsers & Serialization Helpers
//!
//! This module provides parsing and deserialization logic for Capa-formatted threat rules,
//! including helper enums for flexible parameter types and count condition evaluations.

use serde::{Deserialize, Serialize};

/// Helper enum to deserialize either a single String or a `Vec<String>` from Serde
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum StringOrVec {
    /// Single string value.
    Single(String),
    /// List of string values.
    List(Vec<String>),
}

impl StringOrVec {
    /// Returns the contents as a `Vec<String>`.
    pub fn as_vec(&self) -> Vec<String> {
        match self {
            Self::Single(s) => vec![s.clone()],
            Self::List(v) => v.clone(),
        }
    }

    /// Extracts a MITRE ATT&CK technique ID from a single formatted string such as
    /// `"Execution::Command Shell [T1059.003]"` or raw `"T1059.003"`.
    pub fn extract_mitre_id_from(entry: &str) -> String {
        if let Some(start) = entry.find('[')
            && let Some(end) = entry[start..].find(']')
        {
            return entry[start + 1..start + end].to_string();
        }
        entry.to_string()
    }
}

impl Default for StringOrVec {
    fn default() -> Self {
        Self::List(Vec::new())
    }
}

/// Parses threshold count values (e.g. `"2 or more"`, `3`, or raw integers) from rule condition properties.
pub fn parse_count_threshold(val: &serde_json::Value) -> usize {
    if let Some(n) = val.as_u64() {
        return n as usize;
    }
    if let Some(s) = val.as_str() {
        let parts: Vec<&str> = s.split_whitespace().collect();
        if let Some(n) = parts.first().and_then(|f| f.parse::<usize>().ok()) {
            return n;
        }
    }
    1
}

/// Parses number constraints (e.g. `"1 = HANDLE_FLAG_INHERIT"`, `-1`, or raw integers) from rule condition constants.
pub fn parse_number_constant(val: &serde_json::Value) -> String {
    if let Some(n) = val.as_u64() {
        return n.to_string();
    }
    if let Some(n) = val.as_i64() {
        return n.to_string();
    }
    if let Some(s) = val.as_str() {
        let parts: Vec<&str> = s.split('=').collect();
        if !parts.is_empty() {
            return parts[0].trim().to_string();
        }
    }
    String::new()
}
