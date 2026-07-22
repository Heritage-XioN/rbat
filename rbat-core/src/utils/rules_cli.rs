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

/// Outputs an annotated example JSON and YAML rule template to stdout.
pub fn print_rule_example() {
    let example_json = r#"{
  "rule": {
    "meta": {
      "name": "privilege_escalation_process_injection",
      "description": "Flags classical process injection sequence: VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread",
      "mitre_attack": "Privilege Escalation::Process Injection [T1055]",
      "severity": "Critical",
      "category": "privilege_escalation",
      "weight": 80,
      "authors": "RBAT Security Team",
      "tags": ["injection", "process_memory", "remote_thread"]
    },
    "features": [
      {
        "and": [
          { "api": "VirtualAllocEx" },
          { "api": "WriteProcessMemory" },
          { "api": "CreateRemoteThread" }
        ]
      }
    ]
  }
}"#;

    let example_yaml = r#"rule:
  meta:
    name: privilege_escalation_process_injection
    description: Flags classical process injection sequence VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread
    mitre_attack:
      - Privilege Escalation::Process Injection [T1055]
    severity: Critical
    category: privilege_escalation
    weight: 80
    authors:
      - RBAT Security Team
    tags:
      - injection
      - process_memory
      - remote_thread
  features:
    - and:
      - api: VirtualAllocEx
      - api: WriteProcessMemory
      - api: CreateRemoteThread"#;

    println!(
        "\n{}",
        "── RBAT CUSTOM JSON RULE TEMPLATE ─────────────────────────────".with(COLOR_BORDER)
    );
    println!("{}", example_json);
    println!(
        "{}\n",
        "─────────────────────────────────────────────────────────────────".with(COLOR_BORDER)
    );

    println!(
        "{}",
        "── RBAT CUSTOM YAML RULE TEMPLATE (CAPA COMPATIBLE) ───────────".with(COLOR_BORDER)
    );
    println!("{}", example_yaml);
    println!(
        "{}\n",
        "─────────────────────────────────────────────────────────────────".with(COLOR_BORDER)
    );

    println!(
        "  {}",
        "Save this template as a .json or .yaml file inside your custom rules directory."
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
        "Condition operators: and, or, not, basic block, call."
            .with(COLOR_MUTED)
            .italic()
    );
    println!(
        "  {}",
        "Upstream Mandiant Capa Rules Repository: https://github.com/mandiant/capa-rules"
            .with(COLOR_ACCENT)
            .bold()
    );
}

/// Outputs the JSON Schema definition for RBAT rules to stdout.
pub fn print_rule_schema() {
    let schema_json = r#"{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Rule",
  "type": "object",
  "required": ["rule"],
  "properties": {
    "rule": {
      "type": "object",
      "required": ["meta", "features"],
      "properties": {
        "meta": {
          "type": "object",
          "required": ["name"],
          "properties": {
            "name": { "type": "string" },
            "description": { "type": "string" },
            "namespace": { "type": "string" },
            "authors": { "type": ["string", "array"] },
            "mitre_attack": { "type": ["string", "array"] },
            "severity": { "type": "string" },
            "category": { "type": "string" },
            "weight": { "type": "integer", "minimum": 0, "maximum": 100 }
          }
        },
        "features": {
          "type": "array"
        }
      }
    }
  }
}"#;

    eprintln!(
        "// Note: This JSON Schema specifies the shape of both custom JSON and YAML threat rules."
    );
    eprintln!("// Upstream Mandiant Capa Rules: https://github.com/mandiant/capa-rules\n");
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

    let mut valid_count = 0;
    let mut invalid_count = 0;

    validate_dir_recursive(dir, &mut valid_count, &mut invalid_count)?;

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

fn validate_dir_recursive(
    dir: &Path,
    valid_count: &mut usize,
    invalid_count: &mut usize,
) -> color_eyre::Result<()> {
    let entries = fs::read_dir(dir)?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|name| name.starts_with('.'))
        {
            continue;
        }
        if path.is_dir() {
            validate_dir_recursive(&path, valid_count, invalid_count)?;
        } else if path.is_file()
            && path
                .extension()
                .is_some_and(|ext| ext == "json" || ext == "yaml" || ext == "yml")
        {
            let filename = path.file_name().unwrap_or_default().to_string_lossy();
            match fs::read(&path) {
                Ok(data) => match crate::core::Rule::from_slice(&data) {
                    Ok(rule) => {
                        *valid_count += 1;
                        println!(
                            "  {} {} -> \"{}\"",
                            "✔ [VALID]".with(COLOR_SUCCESS).bold(),
                            filename.with(COLOR_MUTED),
                            rule.rule.meta.name.with(COLOR_ACCENT)
                        );
                    }
                    Err(err) => {
                        *invalid_count += 1;
                        println!(
                            "  {} {} -> {}",
                            "❌ [INVALID]".with(COLOR_DANGER).bold(),
                            filename.with(COLOR_DANGER),
                            err.to_string().with(COLOR_MUTED)
                        );
                    }
                },
                Err(err) => {
                    *invalid_count += 1;
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
    Ok(())
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
  "rule": {
    "meta": {
      "name": "test_rule",
      "description": "test",
      "mitre_attack": "T1000",
      "severity": "Low",
      "category": "test",
      "weight": 10
    },
    "features": [
      "code_cave"
    ]
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
  "rule": {
    "meta": {
      "name": "test_rule",
      "description": "test",
      "mitre_attack": "T1000",
      "severity": "Low",
      "category": "test",
      "weight": 10,
      "unknown_typo_field": "invalid"
    },
    "features": [
      "code_cave"
    ]
  }
}"#;
        fs::write(&rule_path, invalid_json).unwrap();

        assert!(validate_rules_directory(dir.path()).is_err());
    }

    #[test]
    fn test_validate_rules_directory_yaml_and_capa() {
        let dir = tempdir().unwrap();
        let rule_path = dir.path().join("capa_rule.yaml");
        let valid_yaml = r#"
rule:
  meta:
    name: "capa_process_injection"
    description: "Detects process injection API calls"
    att&ck: "T1055"
    severity: "High"
    category: "privilege_escalation"
    weight: 80
  features:
    - and:
        - api: VirtualAllocEx
        - api: WriteProcessMemory
"#;
        fs::write(&rule_path, valid_yaml).unwrap();

        assert!(validate_rules_directory(dir.path()).is_ok());
    }

    #[test]
    fn test_validate_authentic_mandiant_capa_rule() {
        let dir = tempdir().unwrap();
        let rule_path = dir.path().join("reverse_shell.yaml");
        let authentic_capa_yaml = r#"
rule:
  meta:
    name: create reverse shell
    namespace: communication/c2/shell
    authors:
      - moritz.raabe@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Execution::Command and Scripting Interpreter::Windows Command Shell [T1059.003]
    mbc:
      - Impact::Remote Access::Reverse Shell [B0022.001]
    examples:
      - C91887D861D9BD4A5872249B641BC9F9:0x401A77
  features:
    - or:
        - and:
            - api: PeekNamedPipe
            - api: CreateProcess
            - api: ReadFile
            - api: WriteFile
        - and:
            - match: host-interaction/process/create
            - match: read pipe
            - match: write pipe
        - and:
            - match: create pipe
            - match: host-interaction/process/create
            - or:
                - basic block:
                    - and:
                        - count(api(SetHandleInformation)): 2 or more
                        - number: 1 = HANDLE_FLAG_INHERIT
                - call:
                    - and:
                        - count(api(SetHandleInformation)): 2 or more
                        - number: 1 = HANDLE_FLAG_INHERIT
"#;
        fs::write(&rule_path, authentic_capa_yaml).unwrap();

        let data = fs::read(&rule_path).unwrap();
        assert!(crate::core::Rule::from_slice(&data).is_ok());
        assert!(validate_rules_directory(dir.path()).is_ok());
    }
}
