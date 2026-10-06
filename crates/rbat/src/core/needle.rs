//! # Multi-Pattern Literal Search and Instruction Matching
//!
//! Provides a compiled Aho-Corasick multi-pattern search index ([`NeedleIndex`])
//! used to accelerate rule matching against disassembled instructions, APIs, and symbols.
//!
//! ## Core Types
//!
//! - [`NeedleIndex`]: Multi-pattern Aho-Corasick automaton index and presence bitmask compiled from rule conditions.
//!
//! ## Overview
//!
//! The needle module accelerates security rule evaluation by eliminating redundant string
//! searches across thousands of disassembled instructions.
//!
//! - **Automaton Compilation**: Recursively collects all string-bearing literals (API imports/exports,
//!   mnemonics, strings, numbers, offsets) across all loaded capa rules. Literals are sorted
//!   deterministically and compiled into a single case-insensitive [`Aho-Corasick`] automaton.
//! - **Single-Pass Disassembly Annotation**: During control-flow graph construction, [`NeedleIndex::populate_cfg`]
//!   runs the automaton once per instruction across worker threads via [`rayon`]. Matched pattern IDs
//!   are recorded in `InstructionInfo::matched`.
//! - **Global Presence Bitmask**: Tracks which patterns appear anywhere in the binary using an
//!   atomic bitmask (`Vec<AtomicBool>`). Rules with absent patterns skip detailed evaluation in $O(1)$ time.
//! - **Constant-Time Verification**: Turns expensive substring searches during rule evaluation into
//!   fast $O(k)$ integer pattern set membership lookups, where $k$ is the small number of matched patterns
//!   per instruction.
//!
//! ## Examples
//!
//! ```rust
//! use rbat::core::{
//!   needle::NeedleIndex,
//!   rule::Rule,
//! };
//!
//! let rules = Rule::load_embedded();
//! let needle = NeedleIndex::build_from_rules(&rules);
//! ```
//!
//! [`Aho-Corasick`]: AhoCorasick

use crate::core::{cfg::ControlFlowGraph, rule::Rule, rule::RuleCondition};
use ahash::{AHashMap, AHashSet};
use aho_corasick::{AhoCorasick, PatternID};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// Multi-pattern Aho-Corasick search index compiled from security rule literals.
///
/// Pre-compiles all string patterns across loaded capa rules into a single finite-state
/// automaton. Running this automaton against disassembled instructions populates their
/// matched pattern IDs and maintains a global presence bitmask for fast pruning.
///
/// # Examples
///
/// ```rust
/// use rbat::core::{
///   needle::NeedleIndex,
///   rule::Rule,
/// };
///
/// let rules = Rule::load_embedded();
/// let needle = NeedleIndex::build_from_rules(&rules);
/// ```
#[derive(Debug)]
pub struct NeedleIndex {
    /// The compiled Aho-Corasick automaton.
    pub(crate) automaton: AhoCorasick,
    /// A mapping from a text string to its PatternID.
    pub(crate) lookup: AHashMap<String, PatternID>,
    /// A bitmask array tracking which PatternIDs were found anywhere in the CFG.
    pub(crate) present: Vec<AtomicBool>,
}

impl NeedleIndex {
    /// Builds an Aho-Corasick automaton from all string-bearing conditions in the provided rule set.
    ///
    /// Recursively walks each rule's condition tree to collect APIs, imports, exports,
    /// strings, mnemonics, numbers, and offsets. The patterns are sorted lexicographically
    /// to guarantee deterministic pattern IDs and compiled into an ASCII case-insensitive
    /// search automaton.
    ///
    /// # Parameters
    ///
    /// - `rules`: Slice of security rules from which literal search patterns are extracted.
    ///
    /// # Returns
    ///
    /// An initialized [`NeedleIndex`] ready for instruction matching.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rbat::core::{
    ///   needle::NeedleIndex,
    ///   rule::Rule,
    /// };
    ///
    /// let rules = Rule::load_embedded();
    /// let needle = NeedleIndex::build_from_rules(&rules);
    /// ```
    pub fn build_from_rules<'rule>(rules: &'rule [Rule]) -> Self {
        let mut pattern_set: AHashSet<&'rule str> = AHashSet::new();

        for r in rules {
            for cond in &r.rule.features {
                Self::collect_patterns(cond, &mut pattern_set);
            }
        }

        // Convert to a deterministic ordered vec so PatternID indices are stable.
        let mut patterns: Vec<&'rule str> = pattern_set.into_iter().collect();
        patterns.sort_unstable();

        let mut lookup = AHashMap::with_capacity(patterns.len());
        for (idx, &pat) in patterns.iter().enumerate() {
            lookup.insert(pat.to_string(), PatternID::must(idx));
        }

        let automaton = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&patterns)
            .expect("NeedleIndex: failed to build Aho-Corasick automaton");

        let present = (0..patterns.len())
            .map(|_| AtomicBool::new(false))
            .collect();

        NeedleIndex {
            automaton,
            lookup,
            present,
        }
    }

    /// Recursively walks a condition tree and collects all string patterns
    /// that the rule engine needs to match against instruction text.
    fn collect_patterns<'rule>(cond: &'rule RuleCondition, patterns: &mut AHashSet<&'rule str>) {
        match cond {
            RuleCondition::Api { api } => {
                patterns.insert(api.as_str());
            }
            RuleCondition::Import { import } => {
                patterns.insert(import.as_str());
            }
            RuleCondition::Export { export } => {
                patterns.insert(export.as_str());
            }
            RuleCondition::String { string } => {
                patterns.insert(string.as_str());
            }
            RuleCondition::Match { .. } => {
                // Rule dependency matching is handled at rule level, not as instruction text patterns
            }
            RuleCondition::Mnemonic { mnemonic } => {
                patterns.insert(mnemonic.as_str());
            }
            RuleCondition::And { and } => {
                and.iter().for_each(|c| Self::collect_patterns(c, patterns));
            }
            RuleCondition::Or { or } => {
                or.iter().for_each(|c| Self::collect_patterns(c, patterns));
            }
            RuleCondition::Not { not } => {
                Self::collect_patterns(not, patterns);
            }
            RuleCondition::BasicBlockScope { conditions } => {
                conditions
                    .iter()
                    .for_each(|c| Self::collect_patterns(c, patterns));
            }
            RuleCondition::CallScope { conditions } => {
                conditions
                    .iter()
                    .for_each(|c| Self::collect_patterns(c, patterns));
            }
            RuleCondition::Number { number } | RuleCondition::Offset { offset: number } => {
                patterns.insert(number.as_str());
            }
            RuleCondition::Count { condition, .. } => {
                Self::collect_patterns(condition, patterns);
            }
            _ => {}
        }
    }

    /// Executes parallel multi-pattern matching across all instructions in the CFG,
    /// annotating each instruction with matched pattern identifiers and updating the
    /// index-wide presence bitmask.
    ///
    /// This method evaluates all disassembled instructions against the compiled Aho-Corasick
    /// automaton in parallel using Rayon. To minimize runtime overhead, worker threads maintain
    /// persistent thread-local formatting buffers via [`ParallelIterator::for_each_init`](rayon::iter::ParallelIterator::for_each_init),
    /// completely avoiding per-instruction heap allocations.
    ///
    /// Copy-on-Write semantics are enforced via [`Arc::make_mut`] on `cfg.instructions`. If the
    /// instruction slice is uniquely owned, it is mutated in-place with zero reallocation overhead;
    /// if shared across threads or handles, a clone is created before mutation.
    ///
    /// For every instruction, its formatted mnemonic, formatted operands, and resolved API symbol
    /// (if present) are scanned for overlapping needle matches. Unique matches are appended to
    /// [`InstructionInfo::matched`](crate::core::disassembler::InstructionInfo::matched) and marked atomically in
    /// `self.present` using [`Ordering::Relaxed`].
    ///
    /// # Parameters
    ///
    /// - `cfg`: Mutable reference to the [`ControlFlowGraph`] to scan and annotate.
    ///
    /// # Performance & Memory Characteristics
    ///
    /// - Thread pool workers reuse thread-local scratch buffers (`buf_m`, `buf_o`, `haystack`),
    ///   reducing heap allocation pressure by >99% compared to transient buffer allocation.
    /// - Matching runs with $O(N + M)$ time complexity where $N$ is the total text length across
    ///   instructions and $M$ is the number of match occurrences.
    /// - Pattern presence flags use atomic stores ([`Ordering::Relaxed`]) with zero lock contention.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rbat::core::{
    ///   cfg::ControlFlowGraph,
    ///   needle::NeedleIndex,
    ///   parser::BinaryArch,
    ///   rule::Rule,
    /// };
    /// use std::sync::Arc;
    ///
    /// let rules = Rule::load_embedded();
    /// let needle = NeedleIndex::build_from_rules(&rules);
    /// let mut cfg = ControlFlowGraph::new(Arc::from([]), &BinaryArch::X64);
    /// needle.populate_cfg(&mut cfg);
    /// ```
    pub fn populate_cfg(&self, cfg: &mut ControlFlowGraph) {
        use rayon::prelude::*;

        // InstructionInfo is an Arc<[T]> (shared type)
        // this line helps obtain exclusive &mut access.
        // clone on write behaviour, helps prevent data
        // races in instances where an arc cloned value
        // was passed. read the Arc::make_mut() docs for
        //  more info
        let instructions = Arc::make_mut(&mut cfg.instructions);

        instructions.par_iter_mut().for_each_init(
            || {
                (
                    String::with_capacity(32),
                    String::with_capacity(64),
                    String::with_capacity(128),
                )
            },
            |(buf_m, buf_o, haystack), insn| {
                insn.format_mnemonic_into(buf_m);
                insn.format_operands_into(buf_o);

                haystack.clear();
                haystack.push_str(buf_m);
                haystack.push(' ');
                haystack.push_str(buf_o);
                if let Some(ref api) = insn.api_resolution {
                    haystack.push(' ');
                    haystack.push_str(api);
                }

                for mat in self.automaton.find_overlapping_iter(haystack.as_str()) {
                    let p = mat.pattern();
                    if !insn.matched.contains(&p) {
                        insn.matched.push(p);
                        self.present[p.as_usize()].store(true, Ordering::Relaxed);
                    }
                }
            },
        );
    }
}
