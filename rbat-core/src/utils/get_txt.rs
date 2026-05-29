//! # Text Asset Parser
//!
//! This module reads line-separated text files from the embedded asset store (e.g. lists of blacklisted APIs or mnemonics)
//! and extracts them as vectors of whitespace-split strings.

use crate::core::{Asset, RbatError, Result};

/// Loads and parses a text file from the embedded asset compilation.
/// Splits lines into words/strings, filtering out extra whitespace.
///
/// # Errors
/// Returns `RbatError::MissingAsset` if the asset filename is not registered in the binary assets.
pub fn get_txt_from_file(file: &str) -> Result<Vec<String>> {
    let file = Asset::get(file).ok_or_else(|| RbatError::MissingAsset(file.to_string()))?;

    // converts bytes to string
    let content = String::from_utf8(file.data.to_vec())?;

    // inserts string from each line to texts vec
    let mut texts = Vec::new();
    for line in content.lines() {
        texts.extend(line.split_whitespace().map(|text| text.to_string()));
    }
    Ok(texts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_txt_from_file_valid() {
        let result = get_txt_from_file("blacklisted_mnemonics.txt");
        assert!(result.is_ok());
        let list = result.unwrap();
        assert!(!list.is_empty());
        assert!(list.contains(&"rdtsc".to_string()));
    }

    #[test]
    fn test_get_txt_from_file_invalid() {
        let result = get_txt_from_file("non_existent_asset_file_123.txt");
        assert!(result.is_err());
        match result {
            Err(RbatError::MissingAsset(name)) => {
                assert_eq!(name, "non_existent_asset_file_123.txt");
            }
            _ => panic!("Expected MissingAsset error"),
        }
    }
}
