//! # Parallel Static Analysis Orchestrator
//!
//! This module coordinates the concurrent execution of static analysis plugins against
//! a target binary. It exposes both a streaming API (which pushes progress updates to a callback)
//! and a blocking batch API (which waits for all plugins to complete and calculates a risk score).

use object::File;
use rayon;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::core::parser::ParsedBinaryContext;
use crate::core::types::AnalysisContext;
use crate::core::{
    disassembler::{DisassemblerImpl, InstructionInfo},
    features::FeatureSet,
    flirt::FlirtMatcher,
    parser::Parser,
    rule::Rule,
    scoring::RiskAssessment,
    scoring::SeverityClassifier,
    traits::{Disassembler, HeuristicPlugin},
    types::{AnalysisProgress, AnalysisResult, NeedleIndex, RbatError, RbatResult, SectionRange},
};

/// High-level static binary analyzer.
///
/// Holds pre-built indices for rules and FLIRT signatures, allowing efficient reuse
/// across multiple binary analyses.
pub struct Analyzer {
    rules: Arc<Vec<Rule>>,
    needle: Arc<NeedleIndex>,
    custom_flirt: Option<FlirtMatcher>,
    classifier: SeverityClassifier,
}

impl Analyzer {
    /// Creates a new builder for configuring an [`Analyzer`].
    pub fn builder() -> AnalyzerBuilder {
        AnalyzerBuilder::new()
    }

    /// Starts the parallel static analysis pipeline in streaming mode.
    ///
    /// Spawns analysis plugins concurrently in a Rayon thread pool scope. Progress events are sent
    /// to the `on_progress` callback. If any plugin fails, the remaining plugins are cancelled
    /// and the first encountered error is returned.
    ///
    /// FLIRT matching with bundled signatures runs automatically if no custom matcher is provided.
    /// To add custom signatures, load them at the call site and pass a merged `FlirtMatcher`.
    ///
    /// # Errors
    /// Returns `RbatError` if file operations, binary parsing, or plugin scanning fails.
    pub fn streaming<'buf, F>(&self, buffer: &'buf [u8], on_progress: F) -> RbatResult<()>
    where
        F: Fn(AnalysisProgress<'buf>) + Send + Sync,
    {
        let error_state = Mutex::new(None);
        let cancel_flag = AtomicBool::new(false);

        let binary_object = File::parse(buffer)?;
        let section_ranges = SectionRange::build_map(&binary_object)?;
        let parsed = Parser::new(&binary_object);
        let binary_data = parsed.parse_buffer()?;

        let ParsedBinaryContext {
            os,
            arch,
            entry_addr,
            text_bytes,
            iat_map,
        } = binary_data;

        let factory = DisassemblerImpl::new(arch);
        let instructions: Arc<[InstructionInfo]> = factory
            .disassemble(&text_bytes, entry_addr, &iat_map)?
            .into();
        let entry_points =
            FlirtMatcher::collect_entry_points(&binary_object, &instructions, &arch, entry_addr);

        let ctx = AnalysisContext {
            buffer,
            binary_object: &binary_object,
            section_ranges: &section_ranges,
            entry_points,
            custom_flirt: &self.custom_flirt,
            os,
            arch,
            text_bytes: &text_bytes,
            entry_addr,
            instructions,
            needle: Arc::clone(&self.needle),
        };

        let plugins: Vec<Box<dyn HeuristicPlugin>> = vec![
            Box::new(crate::core::plugins::HashingPlugin),
            Box::new(crate::core::plugins::DisassemblyPlugin),
            Box::new(crate::core::plugins::StringCheckPlugin),
            Box::new(crate::core::plugins::PackerSigCheckPlugin),
            Box::new(crate::core::plugins::EntropyPlugin),
            Box::new(crate::core::plugins::ImportsPlugin),
            Box::new(crate::core::plugins::ExportsPlugin),
            Box::new(crate::core::plugins::MetadataPlugin),
            Box::new(crate::core::plugins::CfgPlugin),
            Box::new(crate::core::plugins::LibraryFunctionsPlugin),
        ];

        rayon::scope(|s| {
            for plugin in &plugins {
                s.spawn(|_| {
                    if cancel_flag.load(Ordering::Relaxed) {
                        return;
                    }
                    match plugin.run(&ctx) {
                        Ok(progress) => on_progress(progress),
                        Err(e) => Self::capture_error_and_cancel(&error_state, e, &cancel_flag),
                    }
                });
            }
        });

        if let Some(err) = error_state
            .into_inner()
            .expect("error_state Mutex was poisoned")
        {
            return Err(err);
        }

        Ok(())
    }

    /// Performs a blocking batch analysis of the specified binary file.
    ///
    /// Runs the parallel heuristic plugins under the hood, aggregates all findings into
    /// an [`AnalysisResult`], and passes the result to the scoring engine to generate a [`RiskAssessment`].
    ///
    /// # Errors
    /// Returns `RbatError` if file reading, header parsing, or thread orchestration fails.
    pub fn batch<'buf>(
        &self,
        buffer: &'buf [u8],
    ) -> RbatResult<(AnalysisResult<'buf>, RiskAssessment)> {
        let start_time = std::time::Instant::now();
        let (tx, rx) = std::sync::mpsc::channel();

        Self::streaming(self, buffer, move |event| {
            let _ = tx.send(event);
        })?;

        let mut analysis_result = AnalysisResult::default();

        for event in rx {
            match event {
                AnalysisProgress::Hashes(hashes) => {
                    analysis_result.hashes = hashes;
                }
                AnalysisProgress::Disassembly(code_cave) => {
                    analysis_result.code_cave = code_cave;
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
                AnalysisProgress::Imports(imports) => {
                    analysis_result.imports = imports;
                }
                AnalysisProgress::Exports(exports) => {
                    analysis_result.exports = exports;
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

        // Evaluate the rules
        if let Some(ref mut cfg) = analysis_result.cfg {
            self.needle.populate_cfg(cfg);
        }
        let features = FeatureSet::from_analysis_result(&analysis_result);
        let matched_rules = Rule::evaluate(&features, &self.rules, &self.needle);
        let score = RiskAssessment::calculate_risk(&matched_rules, &self.classifier);

        analysis_result.total_analysis_time_ms = start_time.elapsed().as_millis();

        Ok((analysis_result, score))
    }

    /// Saves the first error that occurs to the shared Mutex and triggers the cancellation flag.
    /// Subsequent errors are discarded to preserve the root cause error.
    fn capture_error_and_cancel(
        state: &Mutex<Option<RbatError>>,
        err: RbatError,
        cancel_flag: &AtomicBool,
    ) {
        if matches!(err, RbatError::ErrorAnalysisCancelled) {
            return;
        }

        let mut guard = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if guard.is_none() {
            *guard = Some(err);
            cancel_flag.store(true, Ordering::Relaxed);
        }
    }
}

/// Configuration options for binary analysis.
#[derive(Debug, Clone, Default)]
pub(crate) struct AnalysisConfig {
    /// Optional custom FLIRT matcher.
    custom_flirt: Option<FlirtMatcher>,
    /// Optional custom capa rules (defaults to embedded rules if not provided).
    custom_rules: Option<Vec<Rule>>,
    /// Optional custom severity classifier (defaults to embedded table).
    classifier: Option<SeverityClassifier>,
}

/// Builder for constructing an [`Analyzer`] instance.
#[derive(Default)]
pub struct AnalyzerBuilder {
    config: AnalysisConfig,
}

impl AnalyzerBuilder {
    /// Creates a new builder with default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets a custom FLIRT matcher.
    pub fn with_flirt(mut self, path: &Option<PathBuf>) -> Self {
        let flirt = FlirtMatcher::extend(path);
        self.config.custom_flirt = Some(flirt);
        self
    }

    /// Sets custom capa rules.
    pub fn with_rules(mut self, path: &Option<PathBuf>) -> Self {
        let ext_rules = Rule::extend(path);
        self.config.custom_rules = Some(ext_rules);
        self
    }

    /// Sets a custom severity classifier.
    pub fn with_classifier(mut self, path: &Option<PathBuf>) -> RbatResult<Self> {
        let classifier = SeverityClassifier::extend(path)?;
        self.config.classifier = Some(classifier);
        Ok(self)
    }

    /// Constructs the [`Analyzer`] instance, pre-building rule indices.
    pub fn build(self) -> RbatResult<Analyzer> {
        let rules = match self.config.custom_rules {
            Some(r) => Arc::new(r),
            None => Arc::new(Rule::load_embedded()),
        };
        let classifier = match self.config.classifier {
            Some(s) => s,
            None => SeverityClassifier::embedded(),
        };
        let needle = Arc::new(NeedleIndex::build_from_rules(&rules));
        Ok(Analyzer {
            rules,
            needle,
            custom_flirt: self.config.custom_flirt,
            classifier,
        })
    }
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

        let builder = AnalyzerBuilder::new();
        let analyzer = builder.build().unwrap();

        let result = analyzer.batch(&buffer);
        assert!(result.is_ok());
        let (analysis, assessment) = result.unwrap();

        assert_eq!(analysis.metadata.binary_type, "Linux ELF");
        assert!(assessment.score <= 100);
    }

    #[test]
    fn test_analyzer_builder() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("mock_elf");
        test_helpers::generate_elf(&path);
        let buffer = fs::read(&path).unwrap();

        let analyzer = Analyzer::builder().build().unwrap();
        let result = analyzer.batch(&buffer);
        assert!(result.is_ok());
    }

    #[test]
    fn test_analyze_streaming_err() {
        let buffer = b"invalid_binary_data_format".to_vec();
        let analyzer = Analyzer::builder().build().unwrap();

        let result = analyzer.streaming(&buffer, |_p| {});
        assert!(result.is_err());
    }

    /// Regression: capstone backend must surface AES-NI capability rules (parity with iced).
    /// The AES rules previously failed silently because generated rule data carried inline
    /// ` = description` suffixes on mnemonic values; `RuleCondition::sanitize` now strips them.
    #[test]
    fn test_aes_capability_parity() {
        let path = "tests/capa-testfiles/a6594d9550d56ddeaac8b3140821e698eefb7163ba29f0119c2ef19beb6040b0.exe_";
        let buffer = fs::read(path).unwrap();

        let analyzer = Analyzer::builder().build().unwrap();
        let (_, assessment) = analyzer.batch(&buffer).unwrap();

        let names: Vec<&[u8]> = assessment
            .findings
            .iter()
            .map(|f| f.indicator.as_bytes())
            .collect();

        assert!(
            names.contains(&"encrypt data using AES via x86 extensions".as_bytes()),
            "expected AES encrypt rule to match; matched={:?}",
            names
        );
        assert!(
            names.contains(&"decrypt data using AES via x86 extensions".as_bytes()),
            "expected AES decrypt rule to match; matched={:?}",
            names
        );
    }
}
