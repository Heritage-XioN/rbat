use goblin::Object;
use rayon;
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;

use super::{
    AnalysisProgress, AnalysisResult, MapValue, Result, RiskAssessment, disassemble_section,
    packer_sig_check, parser::Parser, string_check,
};
use crate::utils::{
    get_metadata::get_binary_metadata, scoring::calculate_risk,
    stream_error_helper::capture_error_and_cancel,
};

pub fn analyze_streaming<F>(bin_path: &Path, on_progress: F) -> Result<()>
where
    F: Fn(AnalysisProgress) + Send + Sync,
{
    let error_state = Mutex::new(None);
    let cancel_flag = AtomicBool::new(false);

    let buffer = fs::read(bin_path)?;
    let binary_object = Object::parse(&buffer)?;
    let parsed = Parser::new(bin_path, buffer.to_owned(), &binary_object);
    let binary_data = parsed.parse_buffer()?;

    if let (
        Some(MapValue::OS(os)),
        Some(MapValue::Arch(arch)),
        Some(MapValue::Bytes(bytes)),
        Some(MapValue::Word(entry_addr)),
    ) = (
        binary_data.get("os"),
        binary_data.get("arch"),
        binary_data.get("text_bytes"),
        binary_data.get("entry_addr"),
    ) {
        rayon::scope(|s| {
            // Task 1: Disassembly
            s.spawn(|_| match disassemble_section(bytes, entry_addr, os, arch) {
                Ok((code_cave, blacklisted_mnemonics)) => on_progress(
                    AnalysisProgress::Disassembly((code_cave, blacklisted_mnemonics)),
                ),
                Err(e) => capture_error_and_cancel(&error_state, e, &cancel_flag),
            });

            // Task 2: check for strings
            s.spawn(|_| match string_check(bin_path) {
                Ok(string_check_result) => {
                    on_progress(AnalysisProgress::Strings(string_check_result))
                }
                Err(e) => capture_error_and_cancel(&error_state, e, &cancel_flag),
            });

            // Task 3: check for packer signatures
            s.spawn(|_| match packer_sig_check(bin_path) {
                Ok(packer_results) => on_progress(AnalysisProgress::PackerSigs(packer_results)),
                Err(e) => capture_error_and_cancel(&error_state, e, &cancel_flag),
            });

            // Task 4: Evaluate section entropy
            s.spawn(|_| match parsed.evaluate_section_entropy() {
                Ok(entropy_results) => on_progress(AnalysisProgress::Entropy(entropy_results)),
                Err(e) => capture_error_and_cancel(&error_state, e, &cancel_flag),
            });

            // Task 5: Detect API hooking
            s.spawn(|_| match parsed.detect_api_hooking() {
                Ok(api_hooking) => on_progress(AnalysisProgress::ApiHooking(api_hooking)),
                Err(e) => capture_error_and_cancel(&error_state, e, &cancel_flag),
            });

            // Task 6: Check for process injection patterns
            s.spawn(|_| match parsed.check_process_injec() {
                Ok(prc_result) => on_progress(AnalysisProgress::ProcessInjection(prc_result)),
                Err(e) => capture_error_and_cancel(&error_state, e, &cancel_flag),
            });

            // Task 6: Get bin metadata
            s.spawn(|_| match get_binary_metadata(&binary_object) {
                Ok(metadata) => on_progress(AnalysisProgress::BinaryMetadata(metadata)),
                Err(e) => capture_error_and_cancel(&error_state, e, &cancel_flag),
            });
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
