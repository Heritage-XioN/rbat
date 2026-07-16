//! # YARA Rules Compilation and Memory Scanning
//!
//! This module coordinates compiling rules from embedded assets (e.g. `yara/api_hooking.yar`)
//! and scanning raw byte buffers to extract signature matches with section offsets.

use super::{Asset, RbatError, Result, YaraMatches};
use crate::{core::SectionRange, utils::section_offset::get_section_for_offset};
use std::collections::HashMap;
use yara::{Compiler, Rules};

/// A handler for loading, compiling, and executing YARA rule scans against in-memory buffers.
///
/// # Example
/// ```rust
/// use rbat::core::yarahandler::YaraHandler;
///
/// let handler = YaraHandler::new("yara/api_hooking.yar".to_owned());
/// let rules = handler.compile_yara_rule().unwrap();
/// let matches = handler.scan_mem(&rules, &[0x00; 100], &[]).unwrap();
/// ```
#[derive(Debug)]
pub struct YaraHandler {
    path: String,
}

impl YaraHandler {
    /// Creates a new `YaraHandler` for the specified embedded YARA rule asset filename.
    pub fn new(path: String) -> Self {
        YaraHandler { path }
    }

    /// Compiles YARA rules from the embedded assets and returns a compiled `Rules` object.
    ///
    /// # Errors
    /// Returns `RbatError::MissingAsset` if the rule file does not exist in the embedded directory,
    /// or `RbatError::YaraCompileError` if the rule string contains syntax errors.
    pub fn compile_yara_rule(&self) -> Result<Rules> {
        let file =
            Asset::get(&self.path).ok_or_else(|| RbatError::MissingAsset(self.path.to_string()))?;
        let rules = String::from_utf8(file.data.to_vec())?;
        let compiler = Compiler::new()?.add_rules_str(&rules)?;
        let compiled_rule_file = compiler.compile_rules()?;
        Ok(compiled_rule_file)
    }

    /// Scans a memory buffer using the provided compiled YARA rules.
    /// Maps matches to their corresponding binary section name based on their file offsets.
    ///
    /// # Errors
    /// Returns `RbatError::YaraIO` if the scan engine encounters a runtime scanning error.
    pub fn scan_mem(
        &self,
        compiled_rules: &Rules,
        buffer: &[u8],
        section_ranges: &[SectionRange],
    ) -> Result<HashMap<String, Vec<YaraMatches>>> {
        let mut scanner = compiled_rules.scanner()?;
        let results = scanner.scan_mem(buffer)?;
        let mut yara_result: HashMap<String, Vec<YaraMatches>> = HashMap::new();

        if !results.is_empty() {
            for rule in results {
                for yr_string in rule.strings {
                    if yr_string.matches.is_empty() {
                        continue;
                    }

                    for m in yr_string.matches {
                        let section_name = get_section_for_offset(section_ranges, m.offset);
                        let decoded_string = String::from_utf8_lossy(&m.data).to_string();

                        yara_result
                            .entry(yr_string.identifier.to_string())
                            .or_default()
                            .push(YaraMatches {
                                offset: m.offset,
                                section: section_name,
                                length: m.length,
                                data: decoded_string,
                            });
                    }
                }
            }
        }
        Ok(yara_result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compile_yara_rule_valid() {
        // Use an existing rule file from assets
        let handler = YaraHandler::new("yara/api_hooking.yar".to_string());
        let result = handler.compile_yara_rule();
        assert!(result.is_ok());
    }

    #[test]
    fn test_compile_yara_rule_invalid() {
        let handler = YaraHandler::new("non_existent.yar".to_string());
        let result = handler.compile_yara_rule();
        assert!(result.is_err());
    }
}
