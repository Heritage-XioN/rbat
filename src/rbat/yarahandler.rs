use super::{Asset, RbatError, Result, YaraMatches};
use crate::utils::section_offset::get_section_for_offset;
use std::path::PathBuf;
use std::{collections::HashMap, fs};
use yara::{Compiler, Rules};

#[derive(Debug)]
pub struct YaraHandler {
    path: String,
}

impl YaraHandler {
    pub fn new(path: String) -> Self {
        YaraHandler { path }
    }

    /// Compiles YARA rules from the embedded assets
    /// and returns a compiled `Rules` object that can be used for scanning.
    pub fn compile_yara_rule(&self) -> Result<Rules> {
        let file =
            Asset::get(&self.path).ok_or_else(|| RbatError::MissingAsset(self.path.to_string()))?;
        let rules = String::from_utf8(file.data.to_vec())?;
        let compiler = Compiler::new()?.add_rules_str(&rules)?;
        let compiled_rule_file = compiler.compile_rules()?;
        Ok(compiled_rule_file)
    }

    /// Scans a file using the provided compiled YARA rules and returns a structured result
    /// with offsets, sections, length and matched data.
    pub fn scan_file(
        &self,
        compiled_rules: Rules,
        scan_file: &PathBuf,
    ) -> Result<HashMap<String, Vec<YaraMatches>>> {
        let mut scanner = compiled_rules.scanner()?;
        let results = scanner.scan_file(scan_file)?;
        let mut yara_result: HashMap<String, Vec<YaraMatches>> = HashMap::new();
        let buffer = fs::read(scan_file)?;

        if !results.is_empty() {
            for rule in results {
                for yr_string in rule.strings {
                    if yr_string.matches.is_empty() {
                        continue;
                    }

                    for m in yr_string.matches {
                        let section_name = get_section_for_offset(m.offset, &buffer)?;
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
            Ok(yara_result)
        } else {
            Ok(yara_result)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compile_yara_rule_valid() {
        // Use an existing rule file from assets
        let handler = YaraHandler::new("api_hooking.yar".to_string());
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
