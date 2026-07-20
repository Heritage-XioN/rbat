//! # Rules Subcommand Helper
//!
//! Provides rule template generation, JSON schema output, and custom JSON rule
//! directory validation for the `rbat rules` subcommand.

use crossterm::style::{Color, Stylize};
use std::fs;
use std::path::Path;

const COLOR_ACCENT: Color = Color::Rgb {
    r: 192,
    g: 132,
    b: 252,
};
const COLOR_MUTED: Color = Color::Rgb {
    r: 156,
    g: 163,
    b: 175,
};
const COLOR_BORDER: Color = Color::Rgb {
    r: 60,
    g: 64,
    b: 110,
};
const COLOR_SUCCESS: Color = Color::Rgb {
    r: 34,
    g: 197,
    b: 94,
};
const COLOR_DANGER: Color = Color::Rgb {
    r: 239,
    g: 68,
    b: 68,
};

/// Outputs an annotated example JSON rule template to stdout.
pub fn print_rule_example() {
    let example_json = r#"{
  "meta": {
    "name": "suspicious_process_injection",
    "description": "Flags process memory injection API call sequences",
    "mitre_attack": "T1055",
    "severity": "High",
    "category": "process_injection",
    "weight": 80,
    "author": "RBAT Security Team",
    "references": [
      "https://attack.mitre.org/techniques/T1055/"
    ],
    "tags": [
      "injection",
      "malware"
    ]
  },
  "condition": {
    "and": [
      {
        "feature": {
          "api": "VirtualAllocEx"
        }
      },
      {
        "feature": {
          "api": "WriteProcessMemory"
        }
      },
      {
        "feature": {
          "api": "CreateRemoteThread"
        }
      }
    ]
  }
}"#;

    println!(
        "\n{}",
        "── RBAT CUSTOM JSON RULE EXAMPLE ──────────────────────────────".with(COLOR_BORDER)
    );
    println!("{}", example_json);
    println!(
        "{}\n",
        "─────────────────────────────────────────────────────────────────".with(COLOR_BORDER)
    );
    println!(
        "  {}",
        "Save this template as a .json file inside your custom rules directory."
            .with(COLOR_MUTED)
            .italic()
    );
    println!(
        "  {}",
        "Supported feature conditions: api, string, mnemonic, entropy, code_cave, packer_sig."
            .with(COLOR_MUTED)
            .italic()
    );
    println!(
        "  {}",
        "Condition operators: and, or, not."
            .with(COLOR_MUTED)
            .italic()
    );
}

/// Outputs the JSON Schema definition for RBAT rules to stdout.
pub fn print_rule_schema() {
    let schema_json = r#"{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Rule",
  "type": "object",
  "additionalProperties": false,
  "required": ["meta", "condition"],
  "properties": {
    "meta": {
      "type": "object",
      "additionalProperties": false,
      "required": ["name", "description", "mitre_attack", "severity", "category", "weight"],
      "properties": {
        "name": { "type": "string" },
        "description": { "type": "string" },
        "mitre_attack": { "type": "string" },
        "severity": { "type": "string" },
        "category": { "type": "string" },
        "weight": { "type": "integer", "minimum": 0, "maximum": 100 },
        "author": { "type": "string" },
        "references": {
          "type": "array",
          "items": { "type": "string" }
        },
        "tags": {
          "type": "array",
          "items": { "type": "string" }
        }
      }
    },
    "condition": {
      "type": "object"
    }
  }
}"#;

    println!("{}", schema_json);
}

/// Validates all custom JSON rule files in the target directory.
pub fn validate_rules_directory(dir: &Path) -> color_eyre::Result<()> {
    if !dir.exists() || !dir.is_dir() {
        return Err(color_eyre::eyre::eyre!(
            "Directory '{}' does not exist or is not a directory.",
            dir.display()
        ));
    }

    let line_sep = "─".repeat(64).with(COLOR_BORDER);
    println!("\n{}", line_sep);
    println!(
        " {}",
        "VALIDATING CUSTOM RULES DIRECTORY"
            .with(COLOR_ACCENT)
            .bold()
    );
    println!(
        "  Target Directory: {}\n{}",
        dir.display().to_string().bold(),
        line_sep
    );

    let entries = fs::read_dir(dir)?;
    let mut valid_count = 0;
    let mut invalid_count = 0;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() && path.extension().is_some_and(|ext| ext == "json") {
            let filename = path.file_name().unwrap_or_default().to_string_lossy();
            match fs::read(&path) {
                Ok(data) => match serde_json::from_slice::<crate::core::Rule>(&data) {
                    Ok(rule) => {
                        valid_count += 1;
                        println!(
                            "  {} {} -> \"{}\"",
                            "✔ [VALID]".with(COLOR_SUCCESS).bold(),
                            filename.with(COLOR_MUTED),
                            rule.meta.name.with(COLOR_ACCENT)
                        );
                    }
                    Err(err) => {
                        invalid_count += 1;
                        println!(
                            "  {} {} -> {}",
                            "❌ [INVALID]".with(COLOR_DANGER).bold(),
                            filename.with(COLOR_DANGER),
                            err.to_string().with(COLOR_MUTED)
                        );
                    }
                },
                Err(err) => {
                    invalid_count += 1;
                    println!(
                        "  {} {} -> Failed to read file: {}",
                        "❌ [ERROR]".with(COLOR_DANGER).bold(),
                        filename.with(COLOR_DANGER),
                        err
                    );
                }
            }
        }
    }

    println!("{}", line_sep);
    println!(
        " Summary: {} valid, {} invalid rules.",
        valid_count.to_string().with(COLOR_SUCCESS).bold(),
        invalid_count
            .to_string()
            .with(if invalid_count > 0 {
                COLOR_DANGER
            } else {
                COLOR_MUTED
            })
            .bold()
    );
    println!("{}\n", line_sep);

    if invalid_count > 0 {
        Err(color_eyre::eyre::eyre!(
            "Validation failed: {} invalid rule file(s) detected.",
            invalid_count
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_print_example_and_schema_runs_without_panic() {
        print_rule_example();
        print_rule_schema();
    }

    #[test]
    fn test_validate_rules_directory() {
        let dir = tempdir().unwrap();
        let rule_path = dir.path().join("test_rule.json");
        let valid_json = r#"{
  "meta": {
    "name": "test_rule",
    "description": "test",
    "mitre_attack": "T1000",
    "severity": "Low",
    "category": "test",
    "weight": 10,
    "author": "Alice",
    "references": ["https://example.com"],
    "tags": ["test"]
  },
  "condition": {
    "feature": {
      "code_cave": null
    }
  }
}"#;
        fs::write(&rule_path, valid_json).unwrap();

        assert!(validate_rules_directory(dir.path()).is_ok());
    }

    #[test]
    fn test_validate_rules_directory_rejects_unknown_fields() {
        let dir = tempdir().unwrap();
        let rule_path = dir.path().join("invalid_rule.json");
        let invalid_json = r#"{
  "meta": {
    "name": "test_rule",
    "description": "test",
    "mitre_attack": "T1000",
    "severity": "Low",
    "category": "test",
    "weight": 10,
    "unknown_typo_field": "invalid"
  },
  "condition": {
    "feature": {
      "code_cave": null
    }
  }
}"#;
        fs::write(&rule_path, invalid_json).unwrap();

        assert!(validate_rules_directory(dir.path()).is_err());
    }
}
