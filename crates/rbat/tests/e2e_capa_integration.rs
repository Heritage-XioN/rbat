use rbat::core::analyzer::Analyzer;
use std::path::PathBuf;

/// Helper to get the absolute path to a sample in capa-testfiles
fn get_sample_path(filename: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/capa-testfiles");
    path.push(filename);
    path
}

#[test]
fn test_e2e_capa_al_khaser_api_matches() {
    let sample_path = get_sample_path("al-khaser_x86.exe_");

    // If the submodule isn't checked out or the file is missing, skip the test gracefully.
    // This prevents CI failures if submodules aren't initialized.
    if !sample_path.exists() {
        println!(
            "Skipping e2e test: capa-testfiles submodule not found at {:?}",
            sample_path
        );
        return;
    }

    let buffer = std::fs::read(&sample_path).expect("Failed to read al-khaser testfile");
    let analyzer = Analyzer::builder().build().unwrap();

    // Run the batch analysis (which automatically parses headers, disassembles, and evaluates embedded rules)
    let (_, assessment) = analyzer
        .batch(&buffer)
        .expect("Failed to analyze al-khaser");

    // We expect embedded CAPA behavior rules to trigger because Al-Khaser performs
    // command execution, process termination, and socket communication.
    // NOTE: upstream anti-debugging rules require richer feature extraction
    // (unsupported `format:` conditions) and are currently inert.
    let expected_rules = [
        "execute command",
        "terminate process",
        "send data on socket",
        "delete file",
    ];
    let has_behavior_match = assessment
        .findings
        .iter()
        .any(|f| expected_rules.contains(&f.indicator.as_str()));

    assert!(
        has_behavior_match,
        "Failed to match any CAPA behavior rule on Al-Khaser"
    );
}

#[test]
fn test_e2e_capa_mimikatz_entropy() {
    let sample_path = get_sample_path("mimikatz.exe_");

    if !sample_path.exists() {
        println!(
            "Skipping e2e test: capa-testfiles not found at {:?}",
            sample_path
        );
        return;
    }

    let buffer = std::fs::read(&sample_path).expect("Failed to read mimikatz testfile");
    let analyzer = Analyzer::builder().build().unwrap();

    let (analysis_result, _) = analyzer.batch(&buffer).expect("Failed to analyze mimikatz");

    // We expect mimikatz to have a highly packed/encrypted or dense .text section (or similar).
    // Just verify that section_entropies were calculated and are reasonably high for some section.
    let high_entropy = analysis_result.section_entropy.values().any(|&e| e > 6.0);
    assert!(
        high_entropy,
        "Failed to calculate high entropy for Mimikatz"
    );
}

#[test]
fn test_e2e_capa_elf_microsocks_cfg_and_os() {
    let sample_path = get_sample_path("microsocks.elf_");
    if !sample_path.exists() {
        return;
    }

    let buffer = std::fs::read(&sample_path).expect("Failed to read microsocks testfile");
    let analyzer = Analyzer::builder().build().unwrap();
    let (analysis_result, _) = analyzer
        .batch(&buffer)
        .expect("Failed to analyze microsocks");

    // Verify OS and Arch
    assert!(
        analysis_result
            .metadata
            .binary_type
            .to_lowercase()
            .contains("elf"),
        "Failed to detect ELF binary"
    );

    // Verify CFG capabilities were extracted
    use rbat::core::features::FeatureSet;
    let features = FeatureSet::from_analysis_result(&analysis_result);
    assert!(
        features.basic_blocks_count >= 3,
        "Failed to extract basic blocks from ELF"
    );
    assert!(
        features.max_cyclomatic_complexity >= 2,
        "Failed to calculate cyclomatic complexity"
    );
}

#[test]
fn test_e2e_capa_pe_packed_upx() {
    let sample_path = get_sample_path("Practical Malware Analysis Lab 01-02.exe_");
    if !sample_path.exists() {
        return;
    }

    let buffer = std::fs::read(&sample_path).expect("Failed to read packed testfile");
    let analyzer = Analyzer::builder().build().unwrap();
    let (analysis_result, assessment) = analyzer
        .batch(&buffer)
        .expect("Failed to analyze UPX binary");

    // Verify UPX packer signature was extracted via YARA
    assert!(
        !analysis_result.packer_signatures.is_empty(),
        "Failed to extract packer signature via YARA"
    );

    // Verify the CAPA "packed with UPX" rule fires via its `format: pe` gate
    // combined with the UPX0/UPX1 section checks.
    assert!(
        assessment
            .findings
            .iter()
            .any(|f| f.indicator == "packed with UPX"),
        "Failed to match 'packed with UPX' CAPA rule"
    );
}
