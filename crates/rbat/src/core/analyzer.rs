//! # Parallel Analysis Orchestrator
//!
//! Coordinates the concurrent execution of binary analysis plugins against
//! a target binary buffer.
//!
//! ## Core Types
//!
//! - [`Analyzer`]: The primary analysis engine holding pre-compiled rule indices and classification models.
//! - [`AnalyzerBuilder`]: Fluent builder for configuring and instantiating an [`Analyzer`].
//!
//! ## Overview
//!
//! The [`Analyzer`] provides two operational modes for inspecting binaries:
//! - **Streaming Mode** ([`streaming`]): Emits granular progress updates ([`AnalysisProgress`]) in real time
//!   as individual heuristic plugins finish their workloads.
//! - **Batch Mode** ([`batch`]): A blocking pipeline that runs all plugins concurrently, aggregates results
//!   into an [`AnalysisResult`], matches capability rules, and computes a [`RiskAssessment`].
//!
//! ## Examples
//!
//! ### Streaming Analysis
//!
//! ```rust,no_run
//! use rbat::core::{analyzer::Analyzer, types::analysis::AnalysisProgress};
//! use std::fs;
//! use std::sync::mpsc;
//!
//! # fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let buffer = fs::read("path/to/binary")?;
//! let analyzer = Analyzer::builder().build();
//!
//! let (tx, rx) = mpsc::channel();
//! analyzer.streaming(&buffer, move |event| {
//!     let _ = tx.send(event);
//! })?;
//!
//! for event in rx {
//!     match event {
//!         AnalysisProgress::BinaryMetadata(meta) => println!("Format: {}", meta.binary_type),
//!         AnalysisProgress::Hashes(hashes) => println!("SHA-256: {}", hashes.sha256),
//!         _ => {} // Remaining progress variants documented on AnalysisProgress
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ### Batch Analysis
//!
//! ```rust,no_run
//! use rbat::core::analyzer::Analyzer;
//! use std::fs;
//!
//! # fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let buffer = fs::read("path/to/binary")?;
//! let analyzer = Analyzer::builder().build();
//!
//! let (analysis, assessment) = analyzer.batch(&buffer)?;
//! println!("Scored {} with severity {}", assessment.score, assessment.severity);
//! # Ok(())
//! # }
//! ```
//!
//! [`streaming`]: Analyzer::streaming
//! [`batch`]: Analyzer::batch

use object::File;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};

use crate::core::{
    disassembler::{DisassemblerImpl, InstructionInfo},
    features::FeatureSet,
    flirt::FlirtMatcher,
    needle::NeedleIndex,
    parser::{ParsedBinaryContext, Parser},
    rule::Rule,
    scoring::{classifier::SeverityClassifier, risk::RiskAssessment},
    traits::HeuristicPlugin,
    types::{
        analysis::{AnalysisContext, AnalysisProgress, AnalysisResult, SectionRange},
        result::{RbatError, RbatResult},
    },
};

/// Binary analysis orchestrator.
///
/// `Analyzer` encapsulates pre-compiled capa behavioral [`Rules`], an Aho-Corasick pattern
/// [`search index`], a [`FLIRT signature matcher`], and a rule [`severity classifier`].
///
/// Parsing capa YAML rules, building finite-state pattern matching automata, and loading FLIRT
/// signature sets are computationally expensive operations. `Analyzer` compiles these data
/// structures once during initialization so that multiple binaries can be analyzed repeatedly
/// with zero index-rebuild overhead.
///
/// Raw binary analysis requires coordinating several disparate components: binary parsing,
/// linear disassembly, control-flow-graph (CFG) reconstruction, heuristic scanning, and threat
/// scoring. `Analyzer` unifies these stages behind a thread-safe interface and orchestrates
/// plugin execution concurrently via a Rayon thread pool, with automatic error propagation
/// and early cancellation.
///
/// `Analyzer` serves as the central entry point of the `rbat` library:
/// 1. Takes raw binary bytes as input.
/// 2. Disassembles text sections and extracts CFGs.
/// 3. Concurrently runs all registered heuristic plugins.
/// 4. Matches extracted features against capa rule trees using the pre-built [`NeedleIndex`].
/// 5. Aggregates findings into a [`RiskAssessment`] via noisy-OR scoring.
///
/// # Examples
///
/// Constructing an `Analyzer` with default embedded rules and classifiers:
///
/// ```rust,no_run
/// use rbat::core::analyzer::Analyzer;
///
/// # fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let analyzer = Analyzer::builder().build();
/// # Ok(())
/// # }
/// ```
///
/// [`Rules`]: Rule
/// [`severity classifier`]: SeverityClassifier
/// [`FLIRT signature matcher`]: FlirtMatcher
/// [`search Index`]: NeedleIndex
#[derive(Debug)]
pub struct Analyzer {
    rules: Arc<Vec<Rule>>,
    needle: Arc<NeedleIndex>,
    flirt: FlirtMatcher,
    classifier: SeverityClassifier,
    error_state: Mutex<Option<RbatError>>,
    cancel_flag: AtomicBool,
}

impl Analyzer {
    /// Creates a new [`AnalyzerBuilder`] for configuring and instantiating an [`Analyzer`].
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rbat::core::analyzer::Analyzer;
    ///
    /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let analyzer = Analyzer::builder()
    ///     .with_rules("path/to/custom_rules")
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn builder() -> AnalyzerBuilder {
        AnalyzerBuilder::new()
    }

    /// Runs the analysis pipeline in streaming mode.
    ///
    /// Spawns all analysis plugins concurrently within a Rayon thread pool scope.
    /// As each plugin completes, an [`AnalysisProgress`] event is pushed to the `on_progress`
    /// callback closure. If any plugin encounters an error, the cancellation flag is triggered,
    /// remaining tasks terminate early, and the root-cause error is returned.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rbat::core::{analyzer::Analyzer, types::analysis::AnalysisProgress};
    /// use std::sync::mpsc;
    ///
    /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let buffer = std::fs::read("sample.bin")?;
    /// let analyzer = Analyzer::builder().build();
    /// let (tx, rx) = mpsc::channel();
    ///
    /// analyzer.streaming(&buffer, move |event| {
    ///     let _ = tx.send(event);
    /// })?;
    ///
    /// for event in rx {
    ///     match event {
    ///         AnalysisProgress::Hashes(h) => println!("MD5: {}", h.md5),
    ///         AnalysisProgress::Entropy(e) => println!("Entropy sections: {}", e.len()),
    ///         _ => {}
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an [`RbatError`] if:
    /// - Binary format identification or header parsing fails ([`RbatError::ValidateBinaryFormatError`], [`RbatError::ParseBinaryError`]).
    /// - Machine code disassembly fails ([`RbatError::DisassembleInstructionError`]).
    /// - An individual heuristic plugin fails during execution (e.g. [`RbatError::ScanYaraPayloadError`], [`RbatError::ParseBinaryError`]).
    pub fn streaming<'buf, F>(&self, buffer: &'buf [u8], on_progress: F) -> RbatResult<()>
    where
        F: Fn(AnalysisProgress<'buf>) + Send + Sync,
    {
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

        let disasn = DisassemblerImpl::new(arch);
        let instructions: Arc<[InstructionInfo]> =
            disasn.disassemble(&text_bytes, entry_addr, &iat_map)?;
        let entry_points =
            FlirtMatcher::collect_entry_points(&binary_object, &instructions, &arch, entry_addr);

        let ctx = AnalysisContext {
            buffer,
            binary_object: &binary_object,
            section_ranges: &section_ranges,
            entry_points,
            custom_flirt: &self.flirt,
            os,
            arch,
            text_bytes: &text_bytes,
            entry_addr,
            instructions,
            needle: Arc::clone(&self.needle),
        };

        // register plugins
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

        // Reset execution state
        self.cancel_flag.store(false, Ordering::Relaxed);
        *self.error_state.lock().unwrap_or_else(|e| e.into_inner()) = None;

        rayon::scope(|s| {
            for plugin in &plugins {
                s.spawn(|_| {
                    if self.cancel_flag.load(Ordering::Relaxed) {
                        return;
                    }
                    match plugin.run(&ctx) {
                        Ok(progress) => on_progress(progress),
                        Err(e) => self.capture_error_and_cancel(e),
                    }
                });
            }
        });

        if let Some(err) = self
            .error_state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            return Err(err);
        }

        Ok(())
    }

    /// Performs a blocking batch analysis of the specified binary buffer.
    ///
    /// Executes all analysis plugins concurrently using the [`streaming`] method internally.
    /// It then collects emitted [`AnalysisProgress`] events into an aggregate [`AnalysisResult`],
    /// evaluates behavioral capa rules against the resulting [`FeatureSet`], and computes the
    /// final [`RiskAssessment`].
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rbat::core::analyzer::Analyzer;
    ///
    /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let buffer = std::fs::read("sample.bin")?;
    /// let analyzer = Analyzer::builder().build();
    ///
    /// let (analysis, assessment) = analyzer.batch(&buffer)?;
    /// println!("Detected: {}", analysis.metadata.binary_type);
    /// println!("Score: {} (Verdict: {})", assessment.score, assessment.severity);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an [`RbatError`] if:
    /// - Binary parsing or section discovery fails ([`RbatError::ValidateBinaryFormatError`], [`RbatError::ParseBinaryError`]).
    /// - Machine instruction disassembly fails ([`RbatError::DisassembleInstructionError`]).
    /// - Any heuristic analysis plugin fails during parallel execution (e.g. [`RbatError::ScanYaraPayloadError`]).
    ///
    /// [`streaming`]: Analyzer::streaming
    pub fn batch<'buf>(
        &self,
        buffer: &'buf [u8],
    ) -> RbatResult<(AnalysisResult<'buf>, RiskAssessment)> {
        let start_time = std::time::Instant::now();
        let mut analysis_result = AnalysisResult::default();
        let (tx, rx) = mpsc::channel();

        self.streaming(buffer, move |event| {
            let _ = tx.send(event);
        })?;

        // collect emitted events
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
        let features = FeatureSet::new(&analysis_result, buffer);
        let matched_rules = Rule::evaluate(&features, &self.rules, &self.needle);
        let score = RiskAssessment::calculate_risk(&matched_rules, &self.classifier);

        analysis_result.total_analysis_time_ms = start_time.elapsed().as_millis();

        Ok((analysis_result, score))
    }

    /// Saves the first error that occurs to the shared Mutex and triggers the cancellation flag.
    /// Subsequent errors are discarded to preserve the root cause error.
    fn capture_error_and_cancel(&self, err: RbatError) {
        if matches!(err, RbatError::CancelAnalysisError) {
            return;
        }
        let mut guard = self
            .error_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if guard.is_none() {
            *guard = Some(err);
            self.cancel_flag.store(true, Ordering::Relaxed);
        }
    }

    /// Returns a reference to the loaded Capa behavioral rules.
    #[inline]
    pub fn rules(&self) -> &Arc<Vec<Rule>> {
        &self.rules
    }

    /// Returns a reference to the shared [`NeedleIndex`] automaton.
    #[inline]
    pub fn needle(&self) -> &Arc<NeedleIndex> {
        &self.needle
    }

    /// Returns a reference to the configured [`SeverityClassifier`].
    #[inline]
    pub fn classifier(&self) -> &SeverityClassifier {
        &self.classifier
    }
}

/// Configuration options for binary analysis.
#[derive(Debug, Clone, Default)]
struct AnalysisConfig {
    /// Optional custom FLIRT matcher.
    custom_flirt: Option<FlirtMatcher>,
    /// Optional custom capa rules (defaults to embedded rules if not provided).
    custom_rules: Option<Vec<Rule>>,
    /// Optional custom severity classifier (defaults to embedded table).
    custom_classifier: Option<SeverityClassifier>,
}

/// Fluent builder for constructing and configuring an [`Analyzer`].
///
/// Allows configuring custom FLIRT signature directories, external capa rule directories,
/// and severity override TOML files. If no custom configuration is provided, the builder
/// defaults to embedded rules, embedded signatures, and the default classification table.
///
/// # Examples
///
/// ```rust,no_run
/// use rbat::core::analyzer::AnalyzerBuilder;
///
/// # fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let analyzer = AnalyzerBuilder::new()
///     .with_rules("custom/rules/dir")
///     .with_classifier("custom/overrides.toml")?
///     .build();
/// # Ok(())
/// # }
/// ```
#[derive(Default)]
pub struct AnalyzerBuilder {
    config: AnalysisConfig,
}

impl AnalyzerBuilder {
    /// Creates a new builder with default configuration.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rbat::core::analyzer::AnalyzerBuilder;
    ///
    /// let builder = AnalyzerBuilder::new();
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets a path to a directory containing custom FLIRT signature files (`.sig` / `.pat`).
    ///
    /// External signatures are loaded and merged on top of the bundled signature database.
    ///
    /// # Errors
    ///
    /// Returns [`RbatError::MatchFlirtSignatureError`] if the directory cannot be read or contains
    /// malformed signature files.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rbat::core::analyzer::AnalyzerBuilder;
    ///
    /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let builder = AnalyzerBuilder::new().with_flirt("path/to/flirt_signatures")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_flirt<P: AsRef<Path>>(mut self, path: P) -> RbatResult<Self> {
        let flirt = FlirtMatcher::extend(path)?;
        self.config.custom_flirt = Some(flirt);
        Ok(self)
    }

    /// Sets a path to a directory containing custom capa YAML/JSON rule files.
    ///
    /// External rules are loaded and merged with the embedded rule set.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rbat::core::analyzer::AnalyzerBuilder;
    ///
    /// let builder = AnalyzerBuilder::new().with_rules("path/to/custom_rules");
    /// ```
    pub fn with_rules<P: AsRef<Path>>(mut self, path: P) -> Self {
        let ext_rules = Rule::extend(path);
        self.config.custom_rules = Some(ext_rules);
        self
    }

    /// Sets a path to a TOML severity override configuration file.
    ///
    /// Override entries are merged on top of the embedded classification table,
    /// allowing user files to retune both built-in and custom severity mappings.
    ///
    /// # Errors
    ///
    /// Returns [`RbatError::LoadConfigurationError`] if the file cannot be read or contains invalid TOML.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rbat::core::analyzer::AnalyzerBuilder;
    ///
    /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let builder = AnalyzerBuilder::new().with_classifier("overrides.toml")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_classifier<P: AsRef<Path>>(mut self, path: P) -> RbatResult<Self> {
        let classifier = SeverityClassifier::extend(path)?;
        self.config.custom_classifier = Some(classifier);
        Ok(self)
    }

    /// Builds and returns the configured [`Analyzer`] instance, pre-compiling rule search indices.
    ///
    /// If no custom configuration methods (`with_rules`, `with_flirt`, `with_classifier`) were called,
    /// the [`Analyzer`] is initialized entirely with default embedded assets (embedded capa rules,
    /// bundled FLIRT signatures, and the default severity classification table).
    ///
    /// # Errors
    ///
    /// Returns an [`RbatError`] if any rule compilation or index construction step fails.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rbat::core::analyzer::AnalyzerBuilder;
    ///
    /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let analyzer = AnalyzerBuilder::new().build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn build(self) -> Analyzer {
        let rules = match self.config.custom_rules {
            Some(r) => Arc::new(r),
            None => Arc::new(Rule::load_embedded()),
        };
        let classifier = match self.config.custom_classifier {
            Some(s) => s,
            None => SeverityClassifier::embedded(),
        };
        let flirt = match self.config.custom_flirt {
            Some(f) => f,
            None => FlirtMatcher::load_embedded(),
        };
        let needle = Arc::new(NeedleIndex::new(&rules));
        Analyzer {
            rules,
            needle,
            flirt,
            classifier,
            error_state: Mutex::new(None),
            cancel_flag: AtomicBool::new(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_helpers;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_analyze_batch_elf() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("mock_elf");
        test_helpers::generate_elf(&path);
        let buffer = fs::read(&path).unwrap();

        let builder = AnalyzerBuilder::new();
        let analyzer = builder.build();

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

        let analyzer = Analyzer::builder().build();
        let result = analyzer.batch(&buffer);
        assert!(result.is_ok());
    }

    #[test]
    fn test_analyze_streaming_err() {
        let buffer = b"invalid_binary_data_format".to_vec();
        let analyzer = Analyzer::builder().build();

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

        let analyzer = Analyzer::builder().build();
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

    #[test]
    fn test_error_state_mutex_poison_recovery() {
        let analyzer = Analyzer::builder().build();

        // 1. Deliberately poison the error_state mutex by panicking while holding its lock
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = analyzer.error_state.lock().unwrap();
            panic!("force poison error_state mutex");
        }));

        assert!(
            analyzer.error_state.is_poisoned(),
            "mutex must be poisoned for this test"
        );

        // 2. capture_error_and_cancel must recover from the poisoned mutex instead of panicking
        analyzer.capture_error_and_cancel(RbatError::ValidateBinaryFormatError(
            "captured error".to_string(),
        ));

        // 3. Verify the error was successfully stored despite the poisoned state
        let recovered_err = analyzer
            .error_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        assert!(matches!(
            recovered_err,
            Some(RbatError::ValidateBinaryFormatError(_))
        ));

        // 4. streaming must also recover when initializing with a poisoned mutex
        let dir = tempdir().unwrap();
        let path = dir.path().join("mock_elf");
        test_helpers::generate_elf(&path);
        let buffer = fs::read(&path).unwrap();

        // Re-poison the mutex to test streaming's reset & take recovery
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = analyzer.error_state.lock().unwrap();
            panic!("force poison error_state mutex again");
        }));
        assert!(analyzer.error_state.is_poisoned());

        let result = analyzer.streaming(&buffer, |_| {});
        assert!(
            result.is_ok(),
            "streaming should successfully reset and complete despite poisoned mutex"
        );
    }

    #[test]
    fn test_analyzer_reuse_after_error_reset() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("mock_elf");
        test_helpers::generate_elf(&path);
        let valid_buffer = fs::read(&path).unwrap();

        let analyzer = Analyzer::builder().build();

        // 1. Simulate a previous failed run that triggered early cancellation
        analyzer.capture_error_and_cancel(RbatError::ValidateBinaryFormatError(
            "prior failure".to_string(),
        ));
        assert!(
            analyzer.cancel_flag.load(Ordering::Relaxed),
            "cancel flag should be set"
        );

        // 2. Next run on the same analyzer: must reset state so plugins actually execute
        let events_received = std::sync::atomic::AtomicUsize::new(0);
        let result = analyzer.streaming(&valid_buffer, |_progress| {
            events_received.fetch_add(1, Ordering::Relaxed);
        });

        assert!(result.is_ok(), "second run should succeed");
        assert!(
            events_received.load(Ordering::Relaxed) > 0,
            "plugins should execute and emit progress events"
        );
    }
}
