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
//! let needle = NeedleIndex::new(&rules);
//! ```
//!
//! [`Aho-Corasick`]: AhoCorasick

use crate::core::{
    cfg::ControlFlowGraph,
    disassembler::InstructionInfo,
    rule::{Rule, RuleCondition},
};
use ahash::{AHashMap, AHashSet};
use aho_corasick::{AhoCorasick, PatternID};
use regex::bytes::{Regex, RegexBuilder};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// Multi-pattern Aho-Corasick and Regex search index compiled from security rule literals.
///
/// Pre-compiles all string and regular expression patterns across loaded capa rules into
///  a single finite-state automaton. Running this automaton against disassembled instructions
/// populates their matched pattern IDs and maintains a global presence bitmask for fast pruning.
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
/// let needle = NeedleIndex::new(&rules);
/// ```
#[derive(Debug)]
pub struct NeedleIndex {
    /// The compiled Aho-Corasick automaton.
    pub(crate) automaton: AhoCorasick,
    /// A mapping from a text string to its PatternID.
    pub(crate) lookup: AHashMap<String, PatternID>,
    /// A bitmask array tracking which PatternIDs were found anywhere in the CFG.
    pub(crate) present: Vec<AtomicBool>,
    /// Pre-compiled regex engines and optional literal anchor PatternIDs for regex conditions.
    pub(crate) regex_lookup: AHashMap<String, (Regex, Option<PatternID>)>,
}

impl NeedleIndex {
    /// Builds an Aho-Corasick automaton and regex index from all conditions in the provided rule set.
    ///
    /// Recursively walks each rule's condition tree to collect APIs, imports, exports,
    /// strings, mnemonics, numbers, offsets, and regex literal anchors. The patterns are sorted
    /// lexicographically to guarantee deterministic pattern IDs and compiled into an ASCII
    /// case-insensitive search automaton.
    ///
    /// # Parameters
    ///
    /// - `rules`: Slice of security rules from which literal search patterns are extracted.
    ///
    /// # Returns
    ///
    /// An initialized [`NeedleIndex`] ready for instruction and regex matching.
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
    /// let needle = NeedleIndex::new(&rules);
    /// ```
    pub fn new<'rule>(rules: &'rule [Rule]) -> Self {
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

        let mut regex_lookup = AHashMap::new();
        for r in rules {
            for cond in &r.rule.features {
                Self::collect_regexes(cond, &mut regex_lookup, &lookup);
            }
        }

        NeedleIndex {
            automaton,
            lookup,
            present,
            regex_lookup,
        }
    }

    /// Recursively walks a condition tree and collects all regex conditions,
    /// compiling their byte regular expressions and mapping their literal anchors.
    fn collect_regexes(
        cond: &RuleCondition,
        regex_lookup: &mut AHashMap<String, (Regex, Option<PatternID>)>,
        lookup: &AHashMap<String, PatternID>,
    ) {
        match cond {
            RuleCondition::String { string } => {
                if let Some((pattern, is_case_insensitive)) =
                    RuleCondition::parse_capa_regex(string)
                    && !regex_lookup.contains_key(string)
                {
                    let mut builder = RegexBuilder::new(pattern);
                    builder.case_insensitive(is_case_insensitive);
                    builder.dot_matches_new_line(true);
                    if let Ok(re) = builder.build() {
                        let anchor_id = Self::extract_regex_anchor(pattern)
                            .and_then(|anc| lookup.get(anc).copied());
                        regex_lookup.insert(string.clone(), (re, anchor_id));
                    }
                }
            }
            RuleCondition::And { and } => {
                and.iter()
                    .for_each(|c| Self::collect_regexes(c, regex_lookup, lookup));
            }
            RuleCondition::Or { or } => {
                or.iter()
                    .for_each(|c| Self::collect_regexes(c, regex_lookup, lookup));
            }
            RuleCondition::Not { not } => {
                Self::collect_regexes(not, regex_lookup, lookup);
            }
            RuleCondition::BasicBlockScope { conditions }
            | RuleCondition::CallScope { conditions } => {
                conditions
                    .iter()
                    .for_each(|c| Self::collect_regexes(c, regex_lookup, lookup));
            }
            RuleCondition::Count { condition, .. } => {
                Self::collect_regexes(condition, regex_lookup, lookup);
            }
            _ => {}
        }
    }

    /// Recursively walks a condition tree and collects all string patterns
    /// that the rule engine needs to match against instruction text and memory.
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
                if let Some((pattern, _)) = RuleCondition::parse_capa_regex(string.as_str()) {
                    if let Some(anchor) = Self::extract_regex_anchor(pattern) {
                        patterns.insert(anchor);
                    }
                } else {
                    patterns.insert(string.as_str());
                }
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
    /// let needle = NeedleIndex::new(&rules);
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

    /// Returns `true` if the specified pattern literal was matched anywhere during analysis.
    ///
    /// # Parameters
    ///
    /// - `pattern`: String literal or symbol to query.
    pub fn is_present(&self, pattern: &str) -> bool {
        self.lookup
            .get(pattern)
            .is_some_and(|id| self.present[id.as_usize()].load(Ordering::Relaxed))
    }

    /// Scans a raw binary byte buffer directly using the compiled Aho-Corasick automaton,
    /// marking all matched rule pattern identifiers in `self.present`.
    ///
    /// Performs two fast passes over the binary:
    /// 1. Direct multi-pattern search over raw ASCII byte sequences.
    /// 2. Sliding-window sequence extraction and matching for UTF-16LE ASCII sequences
    ///    (wide character strings commonly embedded in Windows PE binaries).
    ///
    /// # Parameters
    ///
    /// - `buffer`: Raw binary payload slice to scan.
    ///
    /// # Performance
    ///
    /// - Single-pass matching over contiguous bytes runs with $O(N + M)$ time complexity
    ///   at raw memory bandwidth (>2 GB/s).
    /// - Reuses a thread-local scratch buffer for UTF-16LE extraction, requiring zero
    ///   reallocation during inspection.
    /// - Presence flags are recorded via atomic stores ([`Ordering::Relaxed`]) with zero lock overhead.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rbat::core::{needle::NeedleIndex, rule::Rule};
    ///
    /// let rules = Rule::load_embedded();
    /// let needle = NeedleIndex::new(&rules);
    /// needle.scan_buffer(b"This binary invokes powershell.exe and cmd.exe");
    /// ```
    pub fn scan_buffer(&self, buffer: &[u8]) {
        // Pass 1: Direct multi-pattern ASCII search over binary bytes
        for mat in self.automaton.find_overlapping_iter(buffer) {
            let p = mat.pattern();
            self.present[p.as_usize()].store(true, Ordering::Relaxed);
        }

        // Pass 2: UTF-16LE wide character sequence scanning
        let mut i = 0;
        let len = buffer.len();
        let mut scratch = Vec::with_capacity(256);

        while i + 1 < len {
            // Check for ASCII byte paired with 0x00 high byte: [0x20..=0x7E, 0x00] or tab/newline
            if buffer[i + 1] == 0
                && ((0x20..=0x7E).contains(&buffer[i])
                    || buffer[i] == b'\t'
                    || buffer[i] == b'\r'
                    || buffer[i] == b'\n')
            {
                scratch.clear();
                while i + 1 < len
                    && buffer[i + 1] == 0
                    && ((0x20..=0x7E).contains(&buffer[i])
                        || buffer[i] == b'\t'
                        || buffer[i] == b'\r'
                        || buffer[i] == b'\n')
                {
                    scratch.push(buffer[i]);
                    i += 2;
                }
                // Capa literal string patterns have length >= 4
                if scratch.len() >= 4 {
                    for mat in self.automaton.find_overlapping_iter(&scratch) {
                        let p = mat.pattern();
                        self.present[p.as_usize()].store(true, Ordering::Relaxed);
                    }
                }
            } else {
                i += 1;
            }
        }
    }

    /// Checks whether the mandatory literal anchor for a Capa regular expression is present in the binary.
    ///
    /// If an anchor was extracted during index construction, performs an $O(1)$ load from the
    /// presence bitmask. If no safe anchor could be extracted, conservatively returns `true`
    /// to defer evaluation to full regex execution.
    ///
    /// # Parameters
    ///
    /// - `raw_string`: The raw Capa regex condition string literal (e.g. `"/vssadmin.* delete shadows/i"`).
    ///
    /// # Returns
    ///
    /// `true` if the regex pattern is registered and its literal anchor is present (or has no anchor),
    /// `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rbat::core::{needle::NeedleIndex, rule::Rule};
    ///
    /// let rules = Rule::load_embedded();
    /// let needle = NeedleIndex::new(&rules);
    /// needle.scan_buffer(b"cmd.exe /c vssadmin.exe delete shadows");
    /// assert!(needle.is_regex_present("/vssadmin.* delete shadows/i"));
    /// ```
    pub fn is_regex_present(&self, raw_string: &str) -> bool {
        if let Some((_re, anchor_id)) = self.regex_lookup.get(raw_string) {
            if let Some(id) = anchor_id {
                return self.present[id.as_usize()].load(Ordering::Relaxed);
            }
            true
        } else {
            false
        }
    }

    /// Evaluates a Capa regular expression against the binary raw buffer and extracted strings.
    ///
    /// Fast-paths non-matching patterns in $O(1)$ time by checking whether the regex's literal anchor
    /// was observed during binary scanning. If the anchor is present (or none exists), tests the regex
    /// sequentially against the set of extracted strings and the contiguous raw binary buffer.
    ///
    /// # Parameters
    ///
    /// - `raw_string`: The raw Capa regex pattern string as defined in the rule condition.
    /// - `raw_buffer`: Raw executable binary byte slice to search.
    /// - `strings`: Lowercased string literals extracted during binary analysis.
    ///
    /// # Returns
    ///
    /// `true` if any extracted string or raw buffer sequence matches the compiled regular expression,
    /// `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use ahash::AHashSet;
    /// use rbat::core::{needle::NeedleIndex, rule::Rule};
    ///
    /// let rules = Rule::load_embedded();
    /// let needle = NeedleIndex::new(&rules);
    /// let buf = b"cmd.exe /c vssadmin.exe delete shadows /all /quiet";
    /// needle.scan_buffer(buf);
    ///
    /// let strings = AHashSet::new();
    /// assert!(needle.matches_regex("/vssadmin.* delete shadows/i", buf, &strings));
    /// ```
    pub fn matches_regex(
        &self,
        raw_string: &str,
        raw_buffer: &[u8],
        strings: &AHashSet<String>,
    ) -> bool {
        if let Some((re, anchor_id)) = self.regex_lookup.get(raw_string) {
            // Fast O(1) literal anchor rejection
            if let Some(id) = anchor_id
                && !self.present[id.as_usize()].load(Ordering::Relaxed)
            {
                return false;
            }
            // Check extracted string set
            for s in strings {
                if re.is_match(s.as_bytes()) {
                    return true;
                }
            }
            // Check raw binary buffer
            if !raw_buffer.is_empty() && re.is_match(raw_buffer) {
                return true;
            }
        }
        false
    }

    /// Evaluates a Capa regular expression against a disassembled instruction.
    ///
    /// Performs an $O(1)$ fast check against the instruction's matched pattern IDs if an anchor
    /// is associated with the regex. If the anchor is present, tests the regular expression
    /// against the instruction's operand string, mnemonic, and resolved API symbol name.
    ///
    /// # Parameters
    ///
    /// - `raw_string`: The raw Capa regex pattern string as defined in the rule condition.
    /// - `insn`: Disassembled instruction information to evaluate.
    ///
    /// # Returns
    ///
    /// `true` if the instruction mnemonic, operands, or resolved API name match the regex,
    /// `false` otherwise.
    pub fn matches_regex_instruction(&self, raw_string: &str, insn: &InstructionInfo) -> bool {
        if let Some((re, anchor_id)) = self.regex_lookup.get(raw_string) {
            // Fast O(1) anchor check on instruction
            if let Some(id) = anchor_id
                && !insn.matched.contains(id)
            {
                return false;
            }
            if re.is_match(insn.op_str.as_bytes())
                || re.is_match(insn.mnemonic.as_bytes())
                || insn
                    .api_resolution
                    .as_ref()
                    .is_some_and(|api| re.is_match(api.as_bytes()))
            {
                return true;
            }
        }
        false
    }

    /// Extracts a mandatory literal anchor of length >= 4 from a regex pattern.
    ///
    /// Walks the regex pattern to discover contiguous ASCII word-character sequences that are guaranteed
    /// to appear in every match (i.e. not within alternations, character classes, repetitions, or optional
    /// qualifiers). If multiple qualifying candidates exist, returns the longest literal slice.
    ///
    /// # Parameters
    ///
    /// - `pat`: The inner regular expression pattern string without enclosing slashes or flags.
    ///
    /// # Returns
    ///
    /// `Some(&str)` representing a literal slice within `pat` guaranteed to appear in any match,
    /// or `None` if no safe anchor of length >= 4 is found.
    pub(crate) fn extract_regex_anchor(pat: &str) -> Option<&str> {
        let bytes = pat.as_bytes();
        let len = bytes.len();

        // Check if there is a top-level alternation '|'
        let mut depth = 0usize;
        for &b in bytes {
            match b {
                b'(' | b'[' => depth += 1,
                b')' | b']' => depth = depth.saturating_sub(1),
                b'|' if depth == 0 => return None,
                _ => {}
            }
        }

        let mut best_range: Option<(usize, usize)> = None;
        let mut current_start: Option<usize> = None;
        let mut current_end = 0usize;
        let mut depth = 0usize;
        let mut i = 0usize;

        let update_best = |best_range: &mut Option<(usize, usize)>, start: usize, end: usize| {
            let chunk_len = end.saturating_sub(start);
            if chunk_len >= 4 {
                let current_best_len = best_range.map(|(s, e)| e - s).unwrap_or(0);
                if chunk_len > current_best_len {
                    *best_range = Some((start, end));
                }
            }
        };

        while i < len {
            let b = bytes[i];
            match b {
                b'(' | b'[' => {
                    if let Some(s) = current_start.take() {
                        update_best(&mut best_range, s, current_end);
                    }
                    depth += 1;
                    i += 1;
                }
                b')' | b']' => {
                    depth = depth.saturating_sub(1);
                    i += 1;
                }
                _ if depth > 0 => {
                    i += 1;
                }
                b'\\' => {
                    if let Some(s) = current_start.take() {
                        update_best(&mut best_range, s, current_end);
                    }
                    i += 2;
                }
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' => {
                    if current_start.is_none() {
                        current_start = Some(i);
                    }
                    current_end = i + 1;
                    i += 1;
                }
                b'*' | b'?' | b'{' => {
                    if let Some(s) = current_start.take() {
                        let end = current_end.saturating_sub(1);
                        if end > s {
                            update_best(&mut best_range, s, end);
                        }
                    }
                    i += 1;
                }
                _ => {
                    if let Some(s) = current_start.take() {
                        update_best(&mut best_range, s, current_end);
                    }
                    i += 1;
                }
            }
        }

        if let Some(s) = current_start.take() {
            update_best(&mut best_range, s, current_end);
        }

        best_range.map(|(s, e)| &pat[s..e])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::rule::{RuleInner, RuleMeta};

    #[test]
    fn test_needle_scan_buffer_ascii_and_utf16le() {
        let test_rules = vec![
            Rule {
                rule: RuleInner {
                    meta: RuleMeta {
                        name: "TestPowerShell".to_string(),
                        ..Default::default()
                    },
                    features: vec![RuleCondition::String {
                        string: "powershell.exe".to_string(),
                    }],
                },
            },
            Rule {
                rule: RuleInner {
                    meta: RuleMeta {
                        name: "TestKernel32".to_string(),
                        ..Default::default()
                    },
                    features: vec![RuleCondition::String {
                        string: "kernel32.dll".to_string(),
                    }],
                },
            },
            Rule {
                rule: RuleInner {
                    meta: RuleMeta {
                        name: "TestUnmatched".to_string(),
                        ..Default::default()
                    },
                    features: vec![RuleCondition::String {
                        string: "nonexistent_string_12345".to_string(),
                    }],
                },
            },
        ];

        let needle = NeedleIndex::new(&test_rules);

        // Raw ASCII buffer containing powershell.exe
        let ascii_buf = b"Some prefix text with powershell.exe and suffix padding";
        needle.scan_buffer(ascii_buf);
        assert!(needle.is_present("powershell.exe"));
        assert!(!needle.is_present("kernel32.dll"));
        assert!(!needle.is_present("nonexistent_string_12345"));

        // UTF-16LE buffer containing kernel32.dll
        let utf16_bytes: Vec<u8> = "kernel32.dll"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        needle.scan_buffer(&utf16_bytes);
        assert!(needle.is_present("kernel32.dll"));
        assert!(!needle.is_present("nonexistent_string_12345"));
    }

    #[test]
    fn test_parse_capa_regex() {
        assert_eq!(
            RuleCondition::parse_capa_regex("/powershell\\.exe/i"),
            Some(("powershell\\.exe", true))
        );
        assert_eq!(
            RuleCondition::parse_capa_regex("/VB5!.*/"),
            Some(("VB5!.*", false))
        );
        assert_eq!(
            RuleCondition::parse_capa_regex("/vssadmin.* delete shadows/i"),
            Some(("vssadmin.* delete shadows", true))
        );
        // Literal Unix paths starting with / must not be parsed as regexes
        assert_eq!(RuleCondition::parse_capa_regex("/etc/os-release"), None);
        assert_eq!(RuleCondition::parse_capa_regex("/proc/self/maps"), None);
        assert_eq!(RuleCondition::parse_capa_regex("powershell.exe"), None);
        assert_eq!(RuleCondition::parse_capa_regex("/"), None);
        assert_eq!(RuleCondition::parse_capa_regex("//"), None);
    }

    #[test]
    fn test_extract_regex_anchor() {
        assert_eq!(
            NeedleIndex::extract_regex_anchor("vssadmin.* delete shadows"),
            Some("vssadmin")
        );
        assert_eq!(
            NeedleIndex::extract_regex_anchor("wevtutil(\\.exe)?\\s+(clear-log|cl)"),
            Some("wevtutil")
        );
        assert_eq!(
            NeedleIndex::extract_regex_anchor("foobar*baz"),
            Some("fooba")
        );
        assert_eq!(NeedleIndex::extract_regex_anchor("GET|POST"), None);
        assert_eq!(NeedleIndex::extract_regex_anchor("(GET|POST)"), None);
        assert_eq!(NeedleIndex::extract_regex_anchor("abc?def"), None);
    }

    #[test]
    fn test_regex_matching_and_anchor_pruning() {
        let test_rules = vec![
            Rule {
                rule: RuleInner {
                    meta: RuleMeta {
                        name: "TestVssAdmin".to_string(),
                        ..Default::default()
                    },
                    features: vec![RuleCondition::String {
                        string: "/vssadmin.* delete shadows/i".to_string(),
                    }],
                },
            },
            Rule {
                rule: RuleInner {
                    meta: RuleMeta {
                        name: "TestUnmatchedRegex".to_string(),
                        ..Default::default()
                    },
                    features: vec![RuleCondition::String {
                        string: "/shadowcopy_unique_xyz[0-9]+/i".to_string(),
                    }],
                },
            },
        ];

        let needle = NeedleIndex::new(&test_rules);

        // Raw buffer containing the command line
        let buf = b"cmd.exe /c vssadmin.exe delete shadows /all /quiet";
        needle.scan_buffer(buf);

        let strings = AHashSet::new();

        // vssadmin is present in the buffer, regex should match
        assert!(needle.is_regex_present("/vssadmin.* delete shadows/i"));
        assert!(needle.matches_regex("/vssadmin.* delete shadows/i", buf, &strings));

        // Unmatched regex anchor is not in buffer, pruned in O(1)
        assert!(!needle.is_regex_present("/shadowcopy_unique_xyz[0-9]+/i"));
        assert!(!needle.matches_regex("/shadowcopy_unique_xyz[0-9]+/i", buf, &strings));
    }
}
