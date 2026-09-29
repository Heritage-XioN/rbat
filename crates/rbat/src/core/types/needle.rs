//! Aho-Corasick needle index for instruction/feature matching.

use crate::core::{cfg::ControlFlowGraph, rule::Rule, rule::RuleCondition};
use ahash::{AHashMap, AHashSet};
use aho_corasick::{AhoCorasick, PatternID};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Aho-Corasick based multi-pattern index for fast rule condition matching.
///
/// Built once from all loaded rules, this pre-compiles every string pattern
/// (api names, imports, exports, strings, mnemonics, match targets) into a
/// single finite-state automaton. The automaton is then run once per instruction
/// to populate `InstructionInfo::matched`, turning subsequent rule evaluation
/// lookups into O(1) `HashSet::contains` checks.
pub struct NeedleIndex {
    /// The compiled Aho-Corasick automaton.
    pub automaton: AhoCorasick,
    /// A mapping from a text string to its PatternID.
    pub lookup: AHashMap<String, PatternID>,
    /// A bitmask array tracking which PatternIDs were found anywhere in the CFG.
    pub present: Vec<AtomicBool>,
}

impl NeedleIndex {
    /// Builds an Aho-Corasick automaton from all string-bearing conditions
    /// found recursively inside the loaded rule set.
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
            RuleCondition::Other(_) => {}
            _ => {}
        }
    }

    /// Runs the automaton once per instruction across all basic blocks in the CFG,
    /// populating each `InstructionInfo::matched` with the set of matched `PatternID`s.
    pub fn populate_cfg(&self, cfg: &mut ControlFlowGraph) {
        use rayon::prelude::*;

        // InstructionInfo is an Arc<[T]> (shared type)
        // this line helps upload exclusive &mut access.
        // clone on write behaviour, helps prevent data
        // races in instances where an arc cloned value
        // was passed. read the Arc::make_mut() docs for
        //  more info
        let instructions = Arc::make_mut(&mut cfg.instructions);

        instructions.par_iter_mut().for_each(|insn| {
            let mut buf_m = String::new();
            let mut buf_o = String::new();
            let mut haystack = String::new();

            insn.format_mnemonic_into(&mut buf_m);
            insn.format_operands_into(&mut buf_o);

            haystack.push_str(&buf_m);
            haystack.push(' ');
            haystack.push_str(&buf_o);
            if let Some(ref api) = insn.api_resolution {
                haystack.push(' ');
                haystack.push_str(api);
            }

            for mat in self.automaton.find_overlapping_iter(&haystack) {
                let p = mat.pattern();
                if !insn.matched.contains(&p) {
                    insn.matched.push(p);
                    self.present[p.as_usize()].store(true, Ordering::Relaxed);
                }
            }
        });
    }
}
