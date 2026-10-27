use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;
use tempfile::tempdir;

/// Helper to get the absolute path to a sample in capa-testfiles
fn get_sample_path(filename: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../rbat/tests/capa-testfiles");
    path.push(filename);
    path
}

#[test]
fn test_cli_help() {
    let mut cmd = Command::cargo_bin("rbat").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("RBAT performs static analysis"));
}

#[test]
fn test_cli_completions() {
    let mut cmd = Command::cargo_bin("rbat").unwrap();
    cmd.arg("completions")
        .arg("bash")
        .assert()
        .success()
        .stdout(predicate::str::contains("_rbat"));
}

#[test]
fn test_cli_rules_example() {
    let mut cmd = Command::cargo_bin("rbat").unwrap();
    cmd.arg("rules")
        .arg("example")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            r#""name": "privilege_escalation_process_injection""#,
        ));
}

#[test]
fn test_cli_rules_schema() {
    let mut cmd = Command::cargo_bin("rbat").unwrap();
    cmd.arg("rules")
        .arg("schema")
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""$schema":"#));
}

#[test]
fn test_cli_rules_validate() {
    let mut rules_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    rules_dir.push("../rbat/assets/capa-rules");

    let mut cmd = Command::cargo_bin("rbat").unwrap();
    cmd.arg("rules")
        .arg("validate")
        .arg("--dir")
        .arg(&rules_dir)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "VALIDATING CUSTOM RULES DIRECTORY",
        ));
}

#[test]
fn test_cli_analyze_reports_and_output() {
    let sample_path = get_sample_path("al-khaser_x86.exe_");
    if !sample_path.exists() {
        return;
    }

    let out_dir = tempdir().expect("Failed to create temp dir");

    let mut cmd = Command::cargo_bin("rbat").unwrap();
    cmd.arg("analyze")
        .arg(&sample_path)
        .arg("--json")
        .arg("--csv")
        .arg("--pdf")
        .arg("--out-dir")
        .arg(out_dir.path())
        .assert()
        .success()
        // The terminal report should still be printed because we didn't specify --dry-run
        // and when not using --tui, it defaults to printing the terminal report.
        .stdout(predicate::str::contains("RBAT STATIC ANALYSIS REPORT"));

    // Verify files were actually created
    let mut json_exists = false;
    let mut csv_exists = false;
    let mut pdf_exists = false;

    for entry in std::fs::read_dir(out_dir.path()).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        let ext = path.extension().unwrap_or_default().to_string_lossy();
        if ext == "json" {
            json_exists = true;
        }
        if ext == "csv" {
            csv_exists = true;
        }
        if ext == "pdf" {
            pdf_exists = true;
        }
    }

    assert!(json_exists, "JSON report was not created");
    assert!(csv_exists, "CSV report was not created");
    assert!(pdf_exists, "PDF report was not created");
}

#[test]
fn test_cli_analyze_cfg_output() {
    let sample_path = get_sample_path("microsocks.elf_");
    if !sample_path.exists() {
        return;
    }

    let mut cmd = Command::cargo_bin("rbat").unwrap();
    cmd.arg("analyze")
        .arg(&sample_path)
        .arg("--cfg")
        .arg("--dry-run")
        .assert()
        .success()
        .stdout(predicate::str::contains("digraph CFG {"));
}

#[test]
fn test_cli_analyze_dry_run() {
    let sample_path = get_sample_path("mimikatz.exe_");
    if !sample_path.exists() {
        return;
    }

    let mut cmd = Command::cargo_bin("rbat").unwrap();
    cmd.arg("analyze")
        .arg(&sample_path)
        .arg("--dry-run")
        .assert()
        .success();
}

#[test]
fn test_cli_analyze_backend_selection() {
    let sample_path = get_sample_path("mimikatz.exe_");
    if !sample_path.exists() {
        return;
    }

    // Test with --backend capstone
    #[cfg(feature = "backend-capstone")]
    {
        let mut cmd = Command::cargo_bin("rbat").unwrap();
        cmd.arg("analyze")
            .arg(&sample_path)
            .arg("--backend")
            .arg("capstone")
            .arg("--dry-run")
            .assert()
            .success();
    }

    // Test with --backend iced
    #[cfg(feature = "backend-iced")]
    {
        let mut cmd = Command::cargo_bin("rbat").unwrap();
        cmd.arg("analyze")
            .arg(&sample_path)
            .arg("--backend")
            .arg("iced")
            .arg("--dry-run")
            .assert()
            .success();

        // Test with -b short flag
        let mut cmd = Command::cargo_bin("rbat").unwrap();
        cmd.arg("analyze")
            .arg(&sample_path)
            .arg("-b")
            .arg("iced")
            .arg("--dry-run")
            .assert()
            .success();

        // Test with --disassembler alias
        let mut cmd = Command::cargo_bin("rbat").unwrap();
        cmd.arg("analyze")
            .arg(&sample_path)
            .arg("--disassembler")
            .arg("iced")
            .arg("--dry-run")
            .assert()
            .success();
    }
}

#[test]
fn test_cli_analyze_invalid_backend() {
    let sample_path = get_sample_path("mimikatz.exe_");
    if !sample_path.exists() {
        return;
    }

    let mut cmd = Command::cargo_bin("rbat").unwrap();
    cmd.arg("analyze")
        .arg(&sample_path)
        .arg("--backend")
        .arg("nonexistent_backend")
        .arg("--dry-run")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "invalid value 'nonexistent_backend' for '--backend <BACKEND>'",
        ));
}
