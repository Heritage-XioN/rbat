//! # Parallel Static Analysis Orchestrator
//!
//! This module coordinates the concurrent execution of static analysis plugins against
//! a target binary. It exposes both a streaming API (which pushes progress updates to a callback)
//! and a blocking batch API (which waits for all plugins to complete and calculates a risk score).

use goblin::Object;
use rayon;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;

use super::{AnalysisProgress, AnalysisResult, MapValue, Result, RiskAssessment, parser::Parser};
use crate::{
    core::{AnalysisContext, traits::HeuristicPlugin, types::InstructionInfo},
    utils::{
        flirt::collect_function_entry_points, scoring::calculate_risk,
        stream_error_helper::capture_error_and_cancel,
    },
};

/// Starts the parallel static analysis pipeline in streaming mode.
///
/// Spawns analysis plugins concurrently in a Rayon thread pool scope. Progress events are sent
/// to the `on_progress` callback. If any plugin fails, the remaining plugins are cancelled
/// and the first encountered error is returned.
///
/// FLIRT matching with bundled signatures runs automatically if no custom matcher is provided.
/// To add custom signatures, load them at the call site and pass a merged `FlirtMatcher`.
///
/// # Example
/// ```rust,no_run
/// use rbat::core::analyzer::analyze_streaming;
///
/// analyze_streaming(b"some binary bytes", None, |progress| {
///     // Handle progress updates here
/// }).unwrap();
/// ```
///
/// # Errors
/// Returns `RbatError` if file operations, binary parsing, or plugin scanning fails.
pub fn analyze_streaming<F>(
    buffer: &[u8],
    custom_flirt: Option<crate::core::flirt::FlirtMatcher>,
    on_progress: F,
) -> Result<()>
where
    F: Fn(AnalysisProgress) + Send + Sync,
{
    let error_state = Mutex::new(None);
    let cancel_flag = AtomicBool::new(false);

    let binary_object = Object::parse(buffer)?;
    let section_ranges = crate::utils::section_offset::build_section_map(&binary_object, buffer)?;
    let parsed = Parser::new(buffer, &binary_object);
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
        let factory = crate::core::disassembler::Factory::disasm(*os, *arch);
        let cs = factory.disassemble()?;
        let cs_insns = cs.disasm_all(text_bytes, *entry_addr)?;
        let instructions: Vec<InstructionInfo> = cs_insns
            .iter()
            .map(|insn| InstructionInfo {
                address: insn.address(),
                mnemonic: insn.mnemonic().unwrap_or("").into(),
                op_str: insn.op_str().unwrap_or("").into(),
            })
            .collect();

        // Run FLIRT signature matching (either with custom matcher or fallback to embedded)
        let entry_points =
            collect_function_entry_points(&binary_object, &instructions, arch, *entry_addr);

        let library_functions = match custom_flirt {
            Some(ref matcher) => {
                matcher.identify_library_functions(&entry_points, text_bytes, *entry_addr)
            }
            None => {
                let embedded = crate::core::flirt::FlirtMatcher::load_embedded();
                embedded.identify_library_functions(&entry_points, text_bytes, *entry_addr)
            }
        };

        on_progress(AnalysisProgress::LibraryFunctions(library_functions));

        let ctx = AnalysisContext {
            buffer,
            binary_object: &binary_object,
            section_ranges: &section_ranges,
            os: *os,
            arch: *arch,
            text_bytes,
            entry_addr: *entry_addr,
            instructions: &instructions,
        };

        let plugins: Vec<Box<dyn HeuristicPlugin>> = vec![
            Box::new(crate::core::plugins::DisassemblyPlugin),
            Box::new(crate::core::plugins::StringCheckPlugin),
            Box::new(crate::core::plugins::PackerSigCheckPlugin),
            Box::new(crate::core::plugins::EntropyPlugin),
            Box::new(crate::core::plugins::ApiHookingPlugin),
            Box::new(crate::core::plugins::ProcessInjectionPlugin),
            Box::new(crate::core::plugins::MetadataPlugin),
            Box::new(crate::core::plugins::CfgPlugin),
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

/// Performs a blocking batch analysis of the specified binary file.
///
/// Runs the parallel heuristic plugins under the hood, aggregates all findings into
/// an [`AnalysisResult`], and passes the result to the scoring engine to generate a [`RiskAssessment`].
///
/// # Example
/// ```rust,no_run
/// use rbat::core::analyzer::analyze_batch;
///
/// let (result, assessment) = analyze_batch(b"some binary bytes", None).unwrap();
/// println!("Threat score: {}", assessment.score);
/// ```
///
/// # Errors
/// Returns `RbatError` if file reading, header parsing, or thread orchestration fails.
pub fn analyze_batch(
    buffer: &[u8],
    custom_flirt: Option<crate::core::flirt::FlirtMatcher>,
) -> Result<(AnalysisResult, RiskAssessment)> {
    let (tx, rx) = std::sync::mpsc::channel();

    analyze_streaming(buffer, custom_flirt, move |event| {
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
                analysis_result.string_values = string_values;
            }
            AnalysisProgress::PackerSigs(packer_signatures) => {
                analysis_result.packer_signatures = packer_signatures;
            }
            AnalysisProgress::Entropy(section_entropy) => {
                analysis_result.section_entropy = section_entropy;
            }
            AnalysisProgress::ApiHooking(api_hooking) => {
                analysis_result.api_hooking = api_hooking;
            }
            AnalysisProgress::ProcessInjection(process_injection) => {
                analysis_result.process_injection = process_injection;
            }
            AnalysisProgress::BinaryMetadata(metadata) => {
                analysis_result.metadata = metadata;
            }
            AnalysisProgress::CFG(cfg) => {
                analysis_result.cfg = Some(cfg);
            }
            AnalysisProgress::LibraryFunctions(library_functions) => {
                analysis_result.library_functions = library_functions;
            }
        }
    }

    // Evaluate declarative semantic rules
    let features = crate::core::features::FeatureSet::from_analysis_result(&analysis_result);
    let rules = crate::core::Rule::load_embedded();
    let matched_rules = crate::core::Rule::evaluate(&features, &rules);

    let score = calculate_risk(&matched_rules);

    Ok((analysis_result, score))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_helpers::test_helpers;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_analyze_batch_elf() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("mock_elf");
        test_helpers::generate_elf(&path);
        let buffer = fs::read(&path).unwrap();

        let result = analyze_batch(&buffer, None);
        assert!(result.is_ok());
        let (analysis, assessment) = result.unwrap();

        assert_eq!(analysis.metadata.binary_type, "Linux ELF");
        assert!(assessment.score <= 100);
    }

    #[test]
    fn test_analyze_streaming_err() {
        let buffer = b"invalid_binary_data_format".to_vec();
        let result = analyze_streaming(&buffer, None, |_| {});
        assert!(result.is_err());
    }
}
