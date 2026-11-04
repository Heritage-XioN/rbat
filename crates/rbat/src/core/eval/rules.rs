//! # Capa Rule Entity and Evaluation Engine
//!
//! Encapsulates rule metadata, embedded MessagePack rule archives, YAML/JSON deserialization,
//! and the two-tier parallel/fixpoint rule evaluation engine.
//!
//! ## Core Types
//!
//! - [`Rule`]: Top-level security rule entity encapsulating metadata and evaluation conditions.
//! - [`RuleInner`]: Inner structure containing rule metadata and condition trees.
//! - [`RuleMeta`]: Comprehensive metadata describing a security rule aligned with the Mandiant `capa` specification.
//!
//! ## Two-Tier Evaluation Architecture
//!
//! To achieve optimal evaluation throughput and satisfy inter-rule capability dependencies:
//! 1. **Pass 1 (Parallel Evaluation)**: Independent rules without `match:` dependencies are evaluated
//!    concurrently across worker threads via [`rayon`].
//! 2. **Pass 2..N (Dependent Fixpoint)**: Rules with `match:` directives are evaluated iteratively against
//!    the accumulating set of satisfied rules until a fixpoint is reached.

use super::{
    Candidates, CapaCharacteristic, RuleScope, StringOrVec, rules_condition::RuleCondition,
};
use crate::core::{
    features::FeatureSet,
    needle::NeedleIndex,
    types::result::{RbatError, RbatResult},
};
use ahash::{AHashMap, AHashSet};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::path::Path;
use walkdir::WalkDir;

/// Embedded capa rules message pack bytes
const CAPA_RULES_MP: &[u8] = include_bytes!("../../../assets/embedded_rules.mp");

/// Top-level declarative security rule entity adhering to the Mandiant `capa` specification.
///
/// Encapsulates metadata, classification tags, and conditional boolean expressions
/// used to detect malicious or suspicious software capabilities within analyzed binaries.
/// Rules can be parsed from YAML/JSON definitions, loaded from disk directories, or decoded
/// from the embedded MessagePack bundle.
///
/// # Examples
///
/// ```rust
/// use rbat::core::eval::Rule;
///
/// let rule_yaml = r#"
/// rule:
///   meta:
///     name: test capability
///     severity: High
///   features:
///     - string: "cmd.exe"
/// "#;
///
/// let rule = Rule::from_slice(rule_yaml.as_bytes()).unwrap();
/// assert_eq!(rule.rule.meta.name, "test capability");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// The inner rule structure containing metadata and evaluation conditions.
    pub rule: RuleInner,
}

impl Rule {
    /// Parses a rule from raw bytes, supporting both YAML and JSON Capa rule definitions.
    ///
    /// The parser attempts YAML deserialization first, falling back to JSON. Upon successful
    /// deserialization, the condition tree is sanitized to remove inline descriptions and
    /// prune empty boolean expressions.
    ///
    /// # Parameters
    ///
    /// - `bytes`: Raw UTF-8 byte slice of the rule document.
    ///
    /// # Returns
    ///
    /// Returns the parsed and sanitized [`Rule`].
    ///
    /// # Errors
    ///
    /// Returns [`RbatError::ParseRuleError`] if deserialization fails for both YAML and JSON parsers.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rbat::core::eval::Rule;
    ///
    /// let yaml = b"rule:\n  meta:\n    name: test rule\n  features:\n    - string: evil\n";
    /// let rule = Rule::from_slice(yaml).unwrap();
    /// assert_eq!(rule.rule.meta.name, "test rule");
    /// ```
    pub fn from_slice(bytes: &[u8]) -> RbatResult<Self> {
        let mut rule_var = if let Ok(rule) = yaml_serde::from_slice::<Rule>(bytes) {
            rule
        } else {
            serde_json::from_slice::<Rule>(bytes)
                .map_err(|e| RbatError::ParseRuleError(e.to_string()))?
        };
        rule_var.rule.features = rule_var
            .rule
            .features
            .into_iter()
            .filter_map(|c| c.sanitize())
            .collect();
        Ok(rule_var)
    }

    /// Returns the static evaluation scope for this rule.
    ///
    /// Inspects `rule.meta.scopes["static"]` if specified; defaults to [`RuleScope::File`]
    /// when no scope annotation is present to preserve backwards compatibility.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rbat::core::eval::{Rule, RuleScope};
    ///
    /// let yaml = b"rule:\n  meta:\n    name: test\n    scopes:\n      static: function\n  features:\n    - api: CreateFileA\n";
    /// let rule = Rule::from_slice(yaml).unwrap();
    /// assert_eq!(rule.static_scope(), RuleScope::Function);
    /// ```
    #[inline]
    pub fn static_scope(&self) -> RuleScope {
        match self
            .rule
            .meta
            .scopes
            .as_ref()
            .and_then(|s| s.get("static"))
            .map(|s| s.trim())
        {
            Some("function") => RuleScope::Function,
            Some("basic block") => RuleScope::BasicBlock,
            Some("instruction") => RuleScope::Instruction,
            Some("file") => RuleScope::File,
            Some("unsupported") => RuleScope::Unsupported,
            _ => RuleScope::File,
        }
    }

    /// Evaluates if the extracted features satisfy this rule's conditions given previously matched rules.
    ///
    /// Dispatches condition evaluation according to the rule's static scope ([`Rule::static_scope`]):
    /// - [`RuleScope::File`]: Evaluated globally against whole-binary metrics and aggregated symbols.
    /// - [`RuleScope::Function`]: Iterates over non-library functions, matching if $\ge 1$ function
    ///   satisfies all top-level conditions within its local scope.
    /// - [`RuleScope::BasicBlock`]: Iterates over non-library basic blocks, matching if $\ge 1$ block
    ///   satisfies all top-level conditions.
    /// - [`RuleScope::Instruction`]: Iterates over machine instructions, matching if $\ge 1$ instruction
    ///   satisfies all top-level conditions.
    /// - [`RuleScope::Unsupported`]: Evaluates to `false`.
    ///
    /// Rules are pruned in $O(1)$ time via [`NeedleIndex`] before any scope iterations occur.
    ///
    /// # Parameters
    ///
    /// - [`features`]: Extracted binary features from disassembler and structural analyzers.
    /// - [`needle`]: Precomputed literal substring search index.
    /// - `matched_rules`: Set of previously matched rule names used to resolve `match:` conditions.
    ///
    /// # Returns
    ///
    /// `true` if all top-level conditions in this rule are satisfied; otherwise `false`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rbat::core::{
    ///   eval::Rule,
    ///   features::FeatureSet,
    ///   types::analysis::{AnalysisResult,SectionRange},
    ///   needle::NeedleIndex,
    /// };
    /// use ahash::AHashSet;
    ///
    /// let rule_yaml = r#"
    /// rule:
    ///   meta:
    ///     name: basic rule
    ///   features:
    ///     - string: "evil_function"
    /// "#;
    /// let rule = Rule::from_slice(rule_yaml.as_bytes()).unwrap();
    /// let rules = vec![rule.clone()];
    /// let result = AnalysisResult::default();
    /// let features = FeatureSet::new(&result, &[]);
    /// let needle = NeedleIndex::new(&rules);
    /// let matched_rules = AHashSet::new();
    ///
    /// assert!(!rule.matches(&features, &needle, &matched_rules));
    /// ```
    ///
    /// [`features`]: FeatureSet
    /// [`needle`]: NeedleIndex
    #[inline]
    pub fn matches(
        &self,
        features: &FeatureSet,
        needle: &NeedleIndex,
        matched_rules: &AHashSet<&str>,
    ) -> bool {
        if !self
            .rule
            .features
            .iter()
            .all(|c| c.is_present(needle, features, matched_rules))
        {
            return false;
        }

        match self.static_scope() {
            RuleScope::Unsupported => false,
            RuleScope::File => self
                .rule
                .features
                .iter()
                .all(|c| c.matches_file_scope(features, needle, matched_rules)),
            RuleScope::Function => {
                let candidates = Self::candidates_for(
                    &self.rule.features,
                    features,
                    needle,
                    matched_rules,
                    RuleScope::Function,
                );
                if candidates.is_empty() {
                    return false;
                }
                if let Some(slice) = candidates.as_slice() {
                    slice.iter().any(|&idx| {
                        let func = &features.function_scope[idx as usize];
                        self.rule.features.iter().all(|c| {
                            c.matches_function_scope(func, features, needle, matched_rules)
                        })
                    })
                } else {
                    features.function_scope.iter().any(|func| {
                        self.rule.features.iter().all(|c| {
                            c.matches_function_scope(func, features, needle, matched_rules)
                        })
                    })
                }
            }
            RuleScope::BasicBlock => {
                let candidates = Self::candidates_for(
                    &self.rule.features,
                    features,
                    needle,
                    matched_rules,
                    RuleScope::BasicBlock,
                );
                if candidates.is_empty() {
                    return false;
                }
                if let Some(slice) = candidates.as_slice() {
                    slice.iter().any(|&idx| {
                        let block = &features.basic_block_scope[idx as usize];
                        self.rule.features.iter().all(|c| {
                            c.matches_basic_block_scope(block, features, needle, matched_rules)
                        })
                    })
                } else {
                    features.basic_block_scope.iter().any(|block| {
                        self.rule.features.iter().all(|c| {
                            c.matches_basic_block_scope(block, features, needle, matched_rules)
                        })
                    })
                }
            }
            RuleScope::Instruction => {
                let candidates = Self::candidates_for(
                    &self.rule.features,
                    features,
                    needle,
                    matched_rules,
                    RuleScope::Instruction,
                );
                if candidates.is_empty() {
                    return false;
                }
                if let Some(slice) = candidates.as_slice() {
                    slice
                        .iter()
                        .flat_map(|&idx| {
                            features.basic_block_scope[idx as usize].instructions.iter()
                        })
                        .any(|insn| {
                            self.rule.features.iter().all(|c| {
                                c.matches_instruction_scope(insn, features, needle, matched_rules)
                            })
                        })
                } else {
                    features
                        .basic_block_scope
                        .iter()
                        .flat_map(|b| b.instructions.iter())
                        .any(|insn| {
                            self.rule.features.iter().all(|c| {
                                c.matches_instruction_scope(insn, features, needle, matched_rules)
                            })
                        })
                }
            }
        }
    }

    /// Determines candidate indices for an arbitrary condition under the specified target scope.
    #[inline]
    fn candidate_indices_for_condition<'a>(
        cond: &RuleCondition,
        features: &'a FeatureSet,
        needle: &NeedleIndex,
        matched_rules: &AHashSet<&str>,
        scope: RuleScope,
    ) -> Candidates<'a> {
        match scope {
            RuleScope::BasicBlock | RuleScope::Instruction => {
                if features.indices.pattern_to_blocks.is_empty()
                    && features.indices.pattern_counts.is_empty()
                    && !features.basic_block_scope.is_empty()
                {
                    return Candidates::None;
                }
            }
            RuleScope::Function => {
                if features.indices.pattern_to_functions.is_empty()
                    && !features.function_scope.is_empty()
                {
                    return Candidates::None;
                }
            }
            _ => return Candidates::None,
        }

        match cond {
            RuleCondition::Api { api }
            | RuleCondition::Import { import: api }
            | RuleCondition::Export { export: api } => {
                if let Some(&id) = needle.lookup.get(api) {
                    let map = match scope {
                        RuleScope::BasicBlock | RuleScope::Instruction => {
                            &features.indices.pattern_to_blocks
                        }
                        RuleScope::Function => &features.indices.pattern_to_functions,
                        _ => return Candidates::None,
                    };
                    map.get(&id)
                        .map(|b| Candidates::Slice(b.as_slice()))
                        .unwrap_or(Candidates::Slice(&[]))
                } else {
                    Candidates::Slice(&[])
                }
            }
            RuleCondition::String { string } => {
                if RuleCondition::parse_capa_regex(string).is_some() {
                    Candidates::None
                } else if let Some(&id) = needle.lookup.get(string) {
                    let map = match scope {
                        RuleScope::BasicBlock | RuleScope::Instruction => {
                            &features.indices.pattern_to_blocks
                        }
                        RuleScope::Function => &features.indices.pattern_to_functions,
                        _ => return Candidates::None,
                    };
                    map.get(&id)
                        .map(|b| Candidates::Slice(b.as_slice()))
                        .unwrap_or(Candidates::Slice(&[]))
                } else {
                    Candidates::Slice(&[])
                }
            }
            RuleCondition::Mnemonic { mnemonic } => {
                if let Some(&id) = needle.lookup.get(mnemonic) {
                    let map = match scope {
                        RuleScope::BasicBlock | RuleScope::Instruction => {
                            &features.indices.pattern_to_blocks
                        }
                        RuleScope::Function => &features.indices.pattern_to_functions,
                        _ => return Candidates::None,
                    };
                    map.get(&id)
                        .map(|b| Candidates::Slice(b.as_slice()))
                        .unwrap_or(Candidates::Slice(&[]))
                } else {
                    Candidates::Slice(&[])
                }
            }
            RuleCondition::Number { number } | RuleCondition::Offset { offset: number } => {
                if let Some(&id) = needle.lookup.get(number) {
                    let map = match scope {
                        RuleScope::BasicBlock | RuleScope::Instruction => {
                            &features.indices.pattern_to_blocks
                        }
                        RuleScope::Function => &features.indices.pattern_to_functions,
                        _ => return Candidates::None,
                    };
                    map.get(&id)
                        .map(|b| Candidates::Slice(b.as_slice()))
                        .unwrap_or(Candidates::Slice(&[]))
                } else {
                    Candidates::Slice(&[])
                }
            }
            RuleCondition::Characteristic { characteristic } => match scope {
                RuleScope::BasicBlock => match characteristic {
                    CapaCharacteristic::TightLoop
                    | CapaCharacteristic::Nzxor
                    | CapaCharacteristic::PebAccess
                    | CapaCharacteristic::FsAccess
                    | CapaCharacteristic::GsAccess => {
                        Candidates::Slice(features.indices.characteristic_blocks(*characteristic))
                    }
                    _ => Candidates::None,
                },
                RuleScope::Instruction => match characteristic {
                    CapaCharacteristic::Nzxor
                    | CapaCharacteristic::PebAccess
                    | CapaCharacteristic::FsAccess
                    | CapaCharacteristic::GsAccess => {
                        Candidates::Slice(features.indices.characteristic_blocks(*characteristic))
                    }
                    _ => Candidates::None,
                },
                RuleScope::Function => match characteristic {
                    CapaCharacteristic::TightLoop
                    | CapaCharacteristic::Loop
                    | CapaCharacteristic::RecursiveCall
                    | CapaCharacteristic::Nzxor
                    | CapaCharacteristic::PebAccess
                    | CapaCharacteristic::FsAccess
                    | CapaCharacteristic::GsAccess => Candidates::Slice(
                        features.indices.characteristic_functions(*characteristic),
                    ),
                    _ => Candidates::None,
                },
                _ => Candidates::None,
            },
            RuleCondition::Match { match_name } => {
                if !matched_rules.contains(match_name.as_str()) {
                    Candidates::Slice(&[])
                } else {
                    Candidates::None
                }
            }
            RuleCondition::BasicBlockScope { conditions } => match scope {
                RuleScope::BasicBlock | RuleScope::Instruction => {
                    let mut best: Candidates<'a> = Candidates::None;
                    let mut min_len = usize::MAX;

                    for c in conditions {
                        let cand = Self::candidate_indices_for_condition(
                            c,
                            features,
                            needle,
                            matched_rules,
                            RuleScope::BasicBlock,
                        );
                        if cand.is_empty() {
                            return Candidates::Slice(&[]);
                        }
                        if let Some(slice) = cand.as_slice()
                            && slice.len() < min_len
                        {
                            min_len = slice.len();
                            best = cand;
                            if min_len == 0 {
                                return Candidates::Slice(&[]);
                            }
                        }
                    }

                    best
                }
                RuleScope::Function => {
                    let mut req_patterns = Vec::new();
                    for c in conditions {
                        c.collect_required_patterns(needle, &mut req_patterns);
                    }
                    if !req_patterns.is_empty() {
                        let mut min_len = usize::MAX;
                        let mut best: Candidates<'a> = Candidates::None;
                        for pat in req_patterns {
                            if let Some(funcs) = features.indices.pattern_to_functions.get(&pat) {
                                if funcs.len() < min_len {
                                    min_len = funcs.len();
                                    best = Candidates::Slice(funcs.as_slice());
                                    if min_len == 0 {
                                        return Candidates::Slice(&[]);
                                    }
                                }
                            } else {
                                return Candidates::Slice(&[]);
                            }
                        }
                        best
                    } else {
                        Candidates::None
                    }
                }
                _ => Candidates::None,
            },
            RuleCondition::CallScope { conditions }
            | RuleCondition::InstructionScope { conditions } => match scope {
                RuleScope::BasicBlock | RuleScope::Instruction => {
                    let mut best: Candidates<'a> = Candidates::None;
                    let mut min_len = usize::MAX;

                    for c in conditions {
                        let cand = Self::candidate_indices_for_condition(
                            c,
                            features,
                            needle,
                            matched_rules,
                            RuleScope::Instruction,
                        );
                        if cand.is_empty() {
                            return Candidates::Slice(&[]);
                        }
                        if let Some(slice) = cand.as_slice()
                            && slice.len() < min_len
                        {
                            min_len = slice.len();
                            best = cand;
                            if min_len == 0 {
                                return Candidates::Slice(&[]);
                            }
                        }
                    }

                    best
                }
                RuleScope::Function => {
                    let mut req_patterns = Vec::new();
                    for c in conditions {
                        c.collect_required_patterns(needle, &mut req_patterns);
                    }
                    if !req_patterns.is_empty() {
                        let mut min_len = usize::MAX;
                        let mut best: Candidates<'a> = Candidates::None;
                        for pat in req_patterns {
                            if let Some(funcs) = features.indices.pattern_to_functions.get(&pat) {
                                if funcs.len() < min_len {
                                    min_len = funcs.len();
                                    best = Candidates::Slice(funcs.as_slice());
                                    if min_len == 0 {
                                        return Candidates::Slice(&[]);
                                    }
                                }
                            } else {
                                return Candidates::Slice(&[]);
                            }
                        }
                        best
                    } else {
                        Candidates::None
                    }
                }
                _ => Candidates::None,
            },
            RuleCondition::And { and } => {
                let mut best: Candidates<'a> = Candidates::None;
                let mut min_len = usize::MAX;

                for c in and {
                    let cand = Self::candidate_indices_for_condition(
                        c,
                        features,
                        needle,
                        matched_rules,
                        scope,
                    );
                    if cand.is_empty() {
                        return Candidates::Slice(&[]);
                    }
                    if let Some(slice) = cand.as_slice()
                        && slice.len() < min_len
                    {
                        min_len = slice.len();
                        best = cand;
                        if min_len == 0 {
                            return Candidates::Slice(&[]);
                        }
                    }
                }

                best
            }
            RuleCondition::Or { or } => {
                let mut union = Vec::new();
                for c in or {
                    let cand = Self::candidate_indices_for_condition(
                        c,
                        features,
                        needle,
                        matched_rules,
                        scope,
                    );
                    if let Some(slice) = cand.as_slice() {
                        union.extend_from_slice(slice);
                    } else {
                        return Candidates::None;
                    }
                }
                union.sort_unstable();
                union.dedup();
                Candidates::Vec(union)
            }
            RuleCondition::Count { condition, count } => {
                if *count == 0 {
                    Candidates::None
                } else {
                    Self::candidate_indices_for_condition(
                        condition,
                        features,
                        needle,
                        matched_rules,
                        scope,
                    )
                }
            }
            _ => Candidates::None,
        }
    }

    /// Determines candidate indices for an arbitrary slice of conditions under the specified target scope.
    #[inline]
    pub(crate) fn candidates_for<'a>(
        conditions: &[RuleCondition],
        features: &'a FeatureSet,
        needle: &NeedleIndex,
        matched_rules: &AHashSet<&str>,
        scope: RuleScope,
    ) -> Candidates<'a> {
        let mut best: Candidates<'a> = Candidates::None;
        let mut min_len = usize::MAX;
        for cond in conditions {
            let cand =
                Self::candidate_indices_for_condition(cond, features, needle, matched_rules, scope);
            if cand.is_empty() {
                return Candidates::Slice(&[]);
            }
            if let Some(slice) = cand.as_slice()
                && slice.len() < min_len
            {
                min_len = slice.len();
                best = cand;
                if min_len == 0 {
                    return Candidates::Slice(&[]);
                }
            }
        }
        best
    }

    /// Returns `true` if this rule directly or recursively contains a `match:` rule dependency.
    ///
    /// Used by [`Rule::evaluate`] to partition rules into independent rules (evaluated in parallel
    /// during Pass 1) and dependent rules (evaluated iteratively during Pass 2..N).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rbat::core::eval::Rule;
    ///
    /// let rule_yaml = r#"
    /// rule:
    ///   meta:
    ///     name: dependent rule
    ///   features:
    ///     - match: host-interaction/process/create
    /// "#;
    /// let rule = Rule::from_slice(rule_yaml.as_bytes()).unwrap();
    /// assert!(rule.has_match_dependency());
    /// ```
    pub fn has_match_dependency(&self) -> bool {
        self.rule.features.iter().any(|c| c.has_match_dependency())
    }

    /// Loads all embedded Capa rules from the pre-compiled MessagePack bundle.
    ///
    /// # Errors
    ///
    /// Returns [`RbatError::LoadEmbeddedAssetError`] if decoding the compile-time MessagePack
    /// bundle fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rbat::core::eval::Rule;
    ///
    /// let rules = Rule::try_load_embedded().unwrap();
    /// assert!(!rules.is_empty());
    /// ```
    pub fn try_load_embedded() -> RbatResult<Vec<Self>> {
        rmp_serde::from_slice::<Vec<Rule>>(CAPA_RULES_MP).map_err(|e| {
            RbatError::LoadEmbeddedAssetError(format!("failed to decode pre-compiled rules: {e}"))
        })
    }

    /// Loads all embedded Capa rules from the pre-compiled MessagePack bundle.
    ///
    /// # Panics
    ///
    /// Panics if the compile-time embedded MessagePack rule bundle is corrupted.
    /// For a fallible alternative, use [`Rule::try_load_embedded`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rbat::core::eval::Rule;
    ///
    /// let rules = Rule::load_embedded();
    /// assert!(!rules.is_empty());
    /// ```
    pub fn load_embedded() -> Vec<Self> {
        Self::try_load_embedded().expect("embedded capa rules asset is valid MessagePack")
    }

    /// Loads the embedded Capa rules and merges additional custom rules from a directory.
    ///
    /// Reads and deserializes all custom YAML and JSON rules from `path` recursively,
    /// appending them to the embedded rule set.
    ///
    /// # Parameters
    ///
    /// - `path`: Path to a filesystem directory containing custom `.json`, `.yaml`, or `.yml` rules.
    ///
    /// # Returns
    ///
    /// A vector containing both embedded and custom [`Rule`] instances.
    ///
    /// Loads and merges custom capa rules from an external directory on top of the embedded rule set.
    ///
    /// # Parameters
    ///
    /// - `path`: Directory path containing custom `.yaml`, `.yml`, or `.json` rule definitions.
    ///
    /// # Returns
    ///
    /// A vector containing both embedded and external [`Rule`] definitions.
    ///
    /// # Errors
    ///
    /// Returns [`RbatError`] if directory traversal fails.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rbat::core::eval::Rule;
    ///
    /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let rules = Rule::extend("path/to/custom/rules")?;
    /// assert!(!rules.is_empty());
    /// # Ok(())
    /// # }
    /// ```
    pub fn extend<P: AsRef<Path>>(path: P) -> RbatResult<Vec<Self>> {
        let mut rules = Self::load_embedded();
        let custom_rules = Rule::from_dir(path)?;
        rules.extend(custom_rules);
        Ok(rules)
    }

    /// Loads custom JSON and YAML rules recursively from a directory on the local filesystem.
    ///
    /// Recursively scans `path`, skipping hidden files/directories (names beginning with `.`),
    /// and deserializes all files ending with `.json`, `.yaml`, or `.yml`.
    ///
    /// # Parameters
    ///
    /// - `path`: Directory path to inspect for rule definitions.
    ///
    /// # Returns
    ///
    /// A vector of parsed [`Rule`] instances.
    ///
    /// # Errors
    ///
    /// Returns [`RbatError`] if filesystem traversal fails.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use std::path::Path;
    /// use rbat::core::eval::Rule;
    ///
    /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let rules = Rule::from_dir(Path::new("path/to/rules"))?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_dir<P: AsRef<Path>>(path: P) -> RbatResult<Vec<Self>> {
        let mut rules = Vec::new();
        let walker = WalkDir::new(path).into_iter();
        for entry in walker.filter_entry(|d| {
            d.depth() == 0
                || d.file_name()
                    .to_str()
                    .map(|s| !s.starts_with('.'))
                    .unwrap_or(false)
        }) {
            let entry = entry?;
            let is_rules_file = entry.file_type().is_file()
                && entry
                    .path()
                    .extension()
                    .is_some_and(|ext| ext == "json" || ext == "yaml" || ext == "yml");
            if is_rules_file
                && let Ok(data) = std::fs::read(entry.path())
                && let Ok(rule) = Self::from_slice(&data)
            {
                rules.push(rule);
            }
        }
        Ok(rules)
    }

    /// Evaluates candidate rules against extracted binary features using two-tier partitioned fixpoint iteration.
    ///
    /// # Evaluation Strategy
    ///
    /// 1. **Pass 1 (Parallel Independent Evaluation)**: Rules without `match:` dependencies are evaluated
    ///    concurrently in parallel via [`rayon`]. Satisfied rule names are gathered into a matched set.
    /// 2. **Pass 2..N (Iterative Dependent Fixpoint)**: Remaining rules containing `match:` dependencies
    ///    are evaluated against the accumulated matched set. The loop continues until no new rules match.
    /// 3. **Library Filtering**: Any rule marked with `lib: true` is treated strictly as an intermediate
    ///    dependency and excluded from the returned metadata.
    ///
    /// # Parameters
    ///
    /// - [`features`]: Extracted binary features from control-flow graphs, imports, and metadata.
    /// - [`rules`]: Slice of candidate security rules to evaluate.
    /// - [`needle`]: Precomputed literal search index for fast substring/mnemonic filtering.
    ///
    /// # Returns
    ///
    /// A vector of references to [`RuleMeta`] for all matching standalone rules.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rbat::core::{
    ///   eval::Rule,
    ///   features::FeatureSet,
    ///   types::analysis::{AnalysisResult,SectionRange},
    ///   needle::NeedleIndex,
    /// };
    ///
    /// let rule_yaml = r#"
    /// rule:
    ///   meta:
    ///     name: sample rule
    ///   features:
    ///     - string: "target_string"
    /// "#;
    /// let rule = Rule::from_slice(rule_yaml.as_bytes()).unwrap();
    /// let rules = vec![rule];
    /// let result = AnalysisResult::default();
    /// let features = FeatureSet::new(&result, &[]);
    /// let needle = NeedleIndex::new(&rules);
    ///
    /// let matches = Rule::evaluate(&features, &rules, &needle);
    /// assert!(matches.is_empty());
    /// ```
    ///
    /// [`features`]: FeatureSet
    /// [`needle`]: NeedleIndex
    /// [`rules`]: Rule
    pub fn evaluate<'rule>(
        features: &FeatureSet,
        rules: &'rule [Self],
        needle: &NeedleIndex,
    ) -> Vec<&'rule RuleMeta> {
        let mut matched_names: ahash::AHashSet<&str> = ahash::AHashSet::new();
        let mut matched_indices: rustc_hash::FxHashSet<usize> = rustc_hash::FxHashSet::default();

        // Partition rules into dependent (containing match:) vs independent rules
        let (dep_rules, indep_rules): (Vec<_>, Vec<_>) = rules
            .iter()
            .enumerate()
            .partition(|(_, r)| r.has_match_dependency());

        // Pass 1: Evaluate all independent rules in parallel
        let initial_matches: Vec<(usize, &'rule str)> = indep_rules
            .into_par_iter()
            .filter(|(_, rule)| rule.matches(features, needle, &matched_names))
            .map(|(i, rule)| (i, rule.rule.meta.name.as_str()))
            .collect();

        for (idx, name) in initial_matches {
            matched_indices.insert(idx);
            matched_names.insert(name);
        }

        // Pass 2..N: Iteratively evaluate only remaining dependent rules until fixpoint
        let mut pending_deps = dep_rules;
        while !pending_deps.is_empty() {
            let (newly_matched, mut still_pending): (Vec<_>, Vec<_>) = pending_deps
                .into_par_iter()
                .partition(|(_, rule)| rule.matches(features, needle, &matched_names));

            if newly_matched.is_empty() {
                break;
            }

            for (idx, rule) in newly_matched {
                matched_indices.insert(idx);
                matched_names.insert(rule.rule.meta.name.as_str());
            }
            // Restore deterministic ordering after Rayon's unordered partition
            still_pending.sort_unstable_by_key(|(i, _)| *i);
            pending_deps = still_pending;
        }

        rules
            .iter()
            .enumerate()
            .filter(|(i, rule)| matched_indices.contains(i) && !rule.rule.meta.lib.unwrap_or(false))
            .map(|(_, rule)| &rule.rule.meta)
            .collect()
    }
}

/// Core contents of a security rule encapsulating metadata and condition trees.
///
/// Corresponds to the mapping under the root `rule:` key in a capa YAML or JSON rule definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleInner {
    /// Associated rule metadata, scope annotations, and technique mappings.
    pub meta: RuleMeta,
    /// Boolean condition tree of feature assertions that determine a match.
    pub features: Vec<RuleCondition>,
}

/// Metadata describing a security rule aligned with the Mandiant `capa` specification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct RuleMeta {
    /// The unique rule identifier name.
    pub name: String,
    /// Rule namespace path (e.g. `"communication/c2/shell"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Authors list or author attribution string.
    #[serde(default, alias = "author", skip_serializing_if = "Option::is_none")]
    pub authors: Option<StringOrVec>,
    /// Rule evaluation scopes (e.g. `{ "static": "function" }`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<AHashMap<String, String>>,
    /// Mapped MITRE ATT&CK technique list or ID (e.g. `["Execution::Windows Command Shell [T1059.003]"]` or `"T1055"`).
    #[serde(
        default,
        alias = "att&ck",
        alias = "attack",
        alias = "mitre_attack",
        skip_serializing_if = "Option::is_none"
    )]
    pub mitre_attack: Option<StringOrVec>,
    /// Malware Behavior Catalog (MBC) technique mappings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mbc: Option<StringOrVec>,
    /// Example binary hash offsets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub examples: Option<Vec<String>>,
    /// Detailed behavior explanation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Threat severity rating (`"Low"`, `"Medium"`, `"High"`, `"Critical"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// Reference URLs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub references: Option<Vec<String>>,
    /// Tag labels.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    /// Whether this is a library rule (referenced by other rules but not standalone).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lib: Option<bool>,
    /// MAEC malware category mapping.
    #[serde(
        default,
        rename = "maec/malware-category",
        skip_serializing_if = "Option::is_none"
    )]
    pub maec_malware_category: Option<String>,
    /// MAEC malware family mapping.
    #[serde(
        default,
        rename = "maec/malware-family",
        skip_serializing_if = "Option::is_none"
    )]
    pub maec_malware_family: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::eval::test_helpers::*;
    use crate::core::features::GlobalScopeFeatures;
    use crate::core::{
        cfg::{BasicBlock, ControlFlowGraph},
        disassembler::InstructionInfo,
        needle::NeedleIndex,
    };
    use ahash::AHashMap;
    use rustc_hash::FxHashSet;
    use std::sync::Arc;

    #[test]
    fn test_rule_evaluation() {
        let mut section_entropies = AHashMap::new();
        section_entropies.insert(".text", 7.8);

        let features = make_test_feature_set(
            make_test_file_scope(
                FxHashSet::from_iter([aho_corasick::PatternID::must(0)]),
                &section_entropies,
                0,
                false,
                0,
            ),
            Vec::new(),
            Vec::new(),
            GlobalScopeFeatures {
                os: "linux".to_string(),
                arch: "x86_64".to_string(),
                binary_format: "elf".to_string(),
            },
            Arc::from([]),
        );

        // Simple API Match Rule
        let rule_api = Rule {
            rule: RuleInner {
                meta: RuleMeta {
                    name: "ApiMatch".to_owned(),
                    description: Some("".to_owned()),
                    mitre_attack: Some(StringOrVec::Single("".to_owned())),
                    severity: Some("".to_owned()),
                    ..Default::default()
                },
                features: vec![RuleCondition::Api {
                    api: "VirtualAlloc".to_owned(),
                }],
            },
        };

        // Entropy Match Rule
        let rule_entropy = Rule {
            rule: RuleInner {
                meta: RuleMeta {
                    name: "EntropyMatch".to_owned(),
                    description: Some("".to_owned()),
                    mitre_attack: Some(StringOrVec::Single("".to_owned())),
                    severity: Some("".to_owned()),
                    ..Default::default()
                },
                features: vec![RuleCondition::Entropy {
                    section: ".text".to_owned(),
                    min: 7.0,
                }],
            },
        };

        let rules = vec![rule_api, rule_entropy];
        let needle = NeedleIndex::new(&rules);
        let matches = Rule::evaluate(&features, &rules, &needle);

        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].name, "ApiMatch");
        assert_eq!(matches[1].name, "EntropyMatch");
    }

    #[test]
    fn test_cfg_rules_matching() {
        // Create instructions & block representing:
        // SetHandleInformation (call)
        // SetHandleInformation (call)
        // arg: 1 = HANDLE_FLAG_INHERIT (mov/push parameter)
        let mut insns = vec![
            InstructionInfo {
                address: 0x1000,
                mnemonic: "mov".into(),
                op_str: "1 = HANDLE_FLAG_INHERIT".into(),
                api_resolution: None,
                matched: smallvec::SmallVec::new(),
                inst_class: Default::default(),
            },
            InstructionInfo {
                address: 0x1005,
                mnemonic: "call".into(),
                op_str: "SetHandleInformation".into(),
                api_resolution: None,
                matched: smallvec::SmallVec::new(),
                inst_class: Default::default(),
            },
            InstructionInfo {
                address: 0x1010,
                mnemonic: "call".into(),
                op_str: "SetHandleInformation".into(),
                api_resolution: None,
                matched: smallvec::SmallVec::new(),
                inst_class: Default::default(),
            },
        ];

        let block1 = BasicBlock {
            start_address: 0x1000,
            end_address: 0x1010,
            start_idx: 0,
            end_idx: insns.len(),
        };

        // Rule checking Loop presence & Cyclomatic Complexity
        let rule_cfg = Rule {
            rule: RuleInner {
                meta: RuleMeta {
                    name: "CfgRule".to_owned(),
                    severity: Some("High".to_owned()),
                    ..Default::default()
                },
                features: vec![
                    RuleCondition::Characteristic {
                        characteristic: CapaCharacteristic::Loop,
                    },
                    RuleCondition::CyclomaticComplexity { min: 4 },
                ],
            },
        };

        // Complex Rule checking local basic block scope & dynamic count(api(...))
        let rule_scope = Rule {
            rule: RuleInner {
                meta: RuleMeta {
                    name: "ScopeRule".to_owned(),
                    severity: Some("Critical".to_owned()),
                    ..Default::default()
                },
                features: vec![RuleCondition::BasicBlockScope {
                    conditions: vec![RuleCondition::And {
                        and: vec![
                            // count(api(SetHandleInformation)) >= 2
                            RuleCondition::Count {
                                condition: Box::new(RuleCondition::Api {
                                    api: "sethandleinformation".to_string(),
                                }),
                                count: 2,
                            },
                            RuleCondition::Number {
                                number: "1 = handle_flag_inherit".to_string(),
                            },
                        ],
                    }],
                }],
            },
        };

        let rules = vec![rule_cfg, rule_scope];
        let needle = NeedleIndex::new(&rules);

        // Manually populate matched sets since we bypass CFG in this test
        for insn in insns.iter_mut() {
            let haystack = format!("{} {}", insn.format_mnemonic(), insn.format_operands());
            for mat in needle.automaton.find_iter(&haystack) {
                let p = mat.pattern();
                needle.present[p.as_usize()].store(true, std::sync::atomic::Ordering::Relaxed);
                if !insn.matched.contains(&p) {
                    insn.matched.push(p);
                }
            }
        }

        let empty_entropy = AHashMap::new();
        let cfg_instructions: Arc<[InstructionInfo]> = insns.clone().into();
        let block_scope = make_test_block(block1.start_address, block1.end_address, &insns, false);
        let features = make_test_feature_set(
            make_test_file_scope(FxHashSet::default(), &empty_entropy, 1, true, 5),
            Vec::new(),
            vec![block_scope],
            GlobalScopeFeatures {
                os: "Windows".to_owned(),
                arch: "x86_64".to_owned(),
                binary_format: "pe".to_owned(),
            },
            cfg_instructions,
        );

        let matches = Rule::evaluate(&features, &rules, &needle);

        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].name, "CfgRule");
        assert_eq!(matches[1].name, "ScopeRule");
    }

    #[test]
    fn test_rule_dependency_chaining_with_match() {
        // Lib rule that matches on VirtualAlloc API
        let lib_rule = Rule {
            rule: RuleInner {
                meta: RuleMeta {
                    name: "allocate memory".to_owned(),
                    lib: Some(true),
                    ..Default::default()
                },
                features: vec![RuleCondition::Api {
                    api: "VirtualAlloc".to_owned(),
                }],
            },
        };

        // Consumer rule that matches on the lib rule dependency via match:
        let consumer_rule = Rule {
            rule: RuleInner {
                meta: RuleMeta {
                    name: "allocate executable memory".to_owned(),
                    ..Default::default()
                },
                features: vec![
                    RuleCondition::Match {
                        match_name: "allocate memory".to_owned(),
                    },
                    RuleCondition::Format {
                        format: "pe".to_owned(),
                    },
                ],
            },
        };

        let rules = vec![consumer_rule, lib_rule];
        let needle = NeedleIndex::new(&rules);

        let empty_entropy = AHashMap::new();
        let mut api_pattern = None;
        if let Some(&id) = needle.lookup.get("VirtualAlloc") {
            api_pattern = Some(id);
        }

        let mut apis = FxHashSet::default();
        if let Some(id) = api_pattern {
            apis.insert(id);
        }

        let features = make_test_feature_set(
            make_test_file_scope(apis, &empty_entropy, 0, false, 0),
            Vec::new(),
            Vec::new(),
            GlobalScopeFeatures {
                os: "windows pe".to_owned(),
                arch: "x86_64".to_owned(),
                binary_format: "pe".to_owned(),
            },
            Arc::from([]),
        );

        let matched = Rule::evaluate(&features, &rules, &needle);
        // Only the consumer rule should be returned (lib rules are filtered from final results)
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].name, "allocate executable memory");
    }

    #[test]
    fn test_overlapping_needle_matching() {
        let rule_short = Rule {
            rule: RuleInner {
                meta: RuleMeta {
                    name: "AllocRule".to_owned(),
                    ..Default::default()
                },
                features: vec![RuleCondition::Api {
                    api: "alloc".to_owned(),
                }],
            },
        };

        let rule_long = Rule {
            rule: RuleInner {
                meta: RuleMeta {
                    name: "VirtualAllocRule".to_owned(),
                    ..Default::default()
                },
                features: vec![RuleCondition::Api {
                    api: "virtualalloc".to_owned(),
                }],
            },
        };

        let rules = vec![rule_short, rule_long];
        let needle = NeedleIndex::new(&rules);

        let insn = InstructionInfo {
            address: 0x1000,
            mnemonic: "call".into(),
            op_str: "0x4010".into(),
            api_resolution: Some("VirtualAlloc".into()),
            matched: smallvec::SmallVec::new(),
            inst_class: Default::default(),
        };

        let block = BasicBlock {
            start_address: 0x1000,
            end_address: 0x1005,
            start_idx: 0,
            end_idx: 1,
        };

        let mut cfg = ControlFlowGraph {
            instructions: vec![insn].into(),
            blocks: [(0x1000, block)].into_iter().collect(),
            edges: vec![],
            functions: Default::default(),
        };

        needle.populate_cfg(&mut cfg);

        let insn_matched = &cfg.instructions[0].matched;
        // Both overlapping patterns ("alloc" and "virtualalloc") must match
        assert_eq!(
            insn_matched.len(),
            2,
            "Both overlapping patterns must be present in matched"
        );
    }

    #[test]
    fn test_load_embedded_rules() {
        let rules = Rule::load_embedded();
        assert_eq!(rules.len(), 1052, "Expected 1,052 embedded Capa rules");
        assert!(
            rules
                .iter()
                .any(|r| r.rule.meta.name.contains("encrypt data using RC4 PRGA"))
        );
    }

    #[test]
    fn test_rule_from_dir_capa_rules_asset() {
        use std::path::PathBuf;

        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let capa_rules_dir = manifest_dir.join("assets/capa-rules");

        if !capa_rules_dir.exists() {
            println!(
                "Skipping test_rule_from_dir_capa_rules_asset: submodule not found at {:?}",
                capa_rules_dir
            );
            return;
        }

        let rules = Rule::from_dir(&capa_rules_dir)
            .expect("Rule::from_dir failed on assets/capa-rules directory");

        assert!(
            rules.len() >= 1000,
            "Expected at least 1000 rules in assets/capa-rules, found {}",
            rules.len()
        );

        // Verify that every parsed rule contains a valid, non-empty identifier
        for rule in &rules {
            assert!(
                !rule.rule.meta.name.trim().is_empty(),
                "Found rule with empty meta name"
            );
        }

        // Verify known rules are present in the loaded set
        let rule_names: ahash::AHashSet<&str> =
            rules.iter().map(|r| r.rule.meta.name.as_str()).collect();
        assert!(
            rule_names.contains("compiled with ps2exe"),
            "Expected 'compiled with ps2exe' rule in loaded rules"
        );
        assert!(
            rule_names.contains("execute command"),
            "Expected 'execute command' rule in loaded rules"
        );
    }

    #[test]
    fn test_rule_from_dir_filtering_and_errors() {
        let temp_dir = tempfile::tempdir().expect("Failed to create tempdir");
        let root = temp_dir.path();

        // 1. Empty directory returns empty vector
        let empty_rules = Rule::from_dir(root).expect("Empty dir should succeed");
        assert!(empty_rules.is_empty());

        // 2. Valid rule in a subdirectory
        let sub = root.join("subfolder");
        std::fs::create_dir_all(&sub).unwrap();
        let valid_rule = r#"
rule:
  meta:
    name: test valid rule
  features:
    - string: "malicious"
"#;
        std::fs::write(sub.join("rule.yaml"), valid_rule).unwrap();

        // 3. Hidden directory rule (should be skipped)
        let hidden_dir = root.join(".hidden");
        std::fs::create_dir_all(&hidden_dir).unwrap();
        std::fs::write(hidden_dir.join("hidden.yaml"), valid_rule).unwrap();

        // 4. Hidden file (should be skipped)
        std::fs::write(sub.join(".dotfile.yaml"), valid_rule).unwrap();

        // 5. Non-rule extension (should be skipped)
        std::fs::write(sub.join("notes.txt"), valid_rule).unwrap();

        let loaded = Rule::from_dir(root).expect("from_dir should succeed on populated tempdir");
        assert_eq!(
            loaded.len(),
            1,
            "Only the 1 non-hidden valid rule file should be loaded"
        );
        assert_eq!(loaded[0].rule.meta.name, "test valid rule");

        // 6. Non-existent path returns an error
        let nonexistent = root.join("does_not_exist");
        let err = Rule::from_dir(&nonexistent);
        assert!(err.is_err(), "Non-existent path must return an Err");
    }

    #[test]
    fn test_rule_extend_with_capa_rules_asset() {
        use std::path::PathBuf;

        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let capa_rules_dir = manifest_dir.join("assets/capa-rules");

        if !capa_rules_dir.exists() {
            return;
        }

        let embedded_count = Rule::load_embedded().len();
        let extended_rules =
            Rule::extend(&capa_rules_dir).expect("Rule::extend failed on assets/capa-rules");

        assert!(
            extended_rules.len() >= embedded_count,
            "Extended rules ({}) should be >= embedded rules ({})",
            extended_rules.len(),
            embedded_count
        );
    }
}
