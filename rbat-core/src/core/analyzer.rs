use goblin::Object;
use rayon;
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;

use super::{AnalysisProgress, AnalysisResult, MapValue, Result, RiskAssessment, parser::Parser};
use crate::{
    core::{AnalysisContext, traits::HeuristicPlugin},
    utils::{scoring::calculate_risk, stream_error_helper::capture_error_and_cancel},
};

pub fn analyze_streaming<F>(bin_path: &Path, on_progress: F) -> Result<()>
where
    F: Fn(AnalysisProgress) + Send + Sync,
{
    let error_state = Mutex::new(None);
    let cancel_flag = AtomicBool::new(false);

    let buffer = fs::read(bin_path)?;
    let binary_object = Object::parse(&buffer)?;
    let section_ranges = crate::utils::section_offset::build_section_map(&binary_object, &buffer)?;
    let parsed = Parser::new(&buffer, &binary_object);
    let binary_data = parsed.parse_buffer()?;

    if let (
        Some(MapValue::OS(os)),
        Some(MapValue::Arch(arch)),
        Some(MapValue::Bytes(text_bytes)),
        Some(MapValue::Word(entry_addr)),
    ) = (
        binary_data.get("os"),
        binary_data.get("arch"),
        binary_data.get("text_bytes"),
        binary_data.get("entry_addr"),
    ) {
        let ctx = AnalysisContext {
            path: bin_path,
            buffer: &buffer,
            binary_object: &binary_object,
            section_ranges: &section_ranges,
            os: *os,
            arch: *arch,
            text_bytes,
            entry_addr: *entry_addr,
        };

        let plugins: Vec<Box<dyn HeuristicPlugin>> = vec![
            Box::new(crate::core::plugins::DisassemblyPlugin),
            Box::new(crate::core::plugins::StringCheckPlugin),
            Box::new(crate::core::plugins::PackerSigCheckPlugin),
            Box::new(crate::core::plugins::EntropyPlugin),
            Box::new(crate::core::plugins::ApiHookingPlugin),
            Box::new(crate::core::plugins::ProcessInjectionPlugin),
            Box::new(crate::core::plugins::MetadataPlugin),
        ];

        rayon::scope(|s| {
            for plugin in &plugins {
                s.spawn(|_| {
                    if cancel_flag.load(std::sync::atomic::Ordering::Relaxed) {
                        return;
                    }
                    match plugin.run(&ctx) {
                        Ok(progress) => on_progress(progress),
                        Err(e) => capture_error_and_cancel(&error_state, e, &cancel_flag),
                    }
                });
            }
        });
    }

    if let Some(err) = error_state.into_inner().unwrap() {
        return Err(err);
    }

    Ok(())
}

pub fn analyze_batch(bin_path: &Path) -> Result<(AnalysisResult, RiskAssessment)> {
    let (tx, rx) = std::sync::mpsc::channel();

    analyze_streaming(bin_path, move |event| {
        let _ = tx.send(event);
    })?;

    let mut analysis_result = AnalysisResult::default();

    for event in rx {
        match event {
            AnalysisProgress::Disassembly((code_cave, blacklisted_mnemonics)) => {
                analysis_result.code_cave = code_cave;
                analysis_result.blacklisted_mnemonics = blacklisted_mnemonics;
            }
            AnalysisProgress::Strings(string_values) => {
                analysis_result.string_values = string_values
            }
            AnalysisProgress::PackerSigs(packer_signatures) => {
                analysis_result.packer_signatures = packer_signatures
            }
            AnalysisProgress::Entropy(section_entropy) => {
                analysis_result.section_entropy = section_entropy
            }
            AnalysisProgress::ApiHooking(api_hooking) => analysis_result.api_hooking = api_hooking,
            AnalysisProgress::ProcessInjection(process_injection) => {
                analysis_result.process_injection = process_injection
            }
            AnalysisProgress::BinaryMetadata(metadata) => analysis_result.metadata = metadata,
        }
    }

    let score = calculate_risk(
        &analysis_result.section_entropy,
        analysis_result
            .string_values
            .values()
            .map(|v| v.len())
            .sum(),
        analysis_result.api_hooking.len(),
        analysis_result.process_injection.len(),
        !analysis_result.code_cave.is_empty(),
        !analysis_result.packer_signatures.is_empty(),
    );
    Ok((analysis_result, score))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_helpers::test_helpers;
    use tempfile::tempdir;

    #[test]
    fn test_analyze_batch_elf() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("mock_elf");
        test_helpers::generate_elf(&path);

        let result = analyze_batch(&path);
        assert!(result.is_ok());
        let (analysis, assessment) = result.unwrap();
        
        assert_eq!(analysis.metadata.binary_type, "Linux ELF");
        assert!(assessment.score <= 100);
    }

    #[test]
    fn test_analyze_streaming_err() {
        let path = Path::new("non_existent_binary_file_abc.bin");
        let result = analyze_streaming(path, |_| {});
        assert!(result.is_err());
    }
}
