//! # Threat Detection Rules Parsers & Serialization Helpers
//!
//! This module provides parsing and deserialization logic for Capa-formatted threat rules,
//! including helper enums for flexible parameter types and count condition evaluations.

use serde::{Deserialize, Serialize};

/// Helper enum to deserialize either a single String or a Vec<String> from Serde
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

    /// Returns the first string or an empty string.
    pub fn first_string(&self) -> String {
        match self {
            Self::Single(s) => s.clone(),
            Self::List(v) => v.first().cloned().unwrap_or_default(),
        }
    }

    /// Extracts MITRE ATT&CK technique ID (e.g. `"T1059.003"`) from formatted strings like
    /// `"Execution::Command Shell [T1059.003]"` or raw `"T1059.003"`.
    #[allow(clippy::collapsible_if)]
    pub fn extract_mitre_id(&self) -> String {
        let first = self.first_string();
        if let Some(start) = first.find('[') {
            if let Some(end) = first[start..].find(']') {
                return first[start + 1..start + end].to_string();
            }
        }
        first
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
