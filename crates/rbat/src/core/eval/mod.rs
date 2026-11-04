//! # Threat Detection Rule Evaluation Engine
//!
//! Provides declarative security rule definition, nested boolean logic conditions,
//! two-tier fixpoint rule evaluation, and embedded asset loading compatible with the
//! Mandiant `capa` rule specification.
//!
//! ## Submodules
//!
//! - [`rules`]: Top-level security rule entity ([`Rule`]), metadata ([`RuleMeta`]), and the fixpoint evaluation engine.
//! - [`rules_condition`]: Untagged AST condition nodes ([`RuleCondition`]) implementing nested boolean logic and scope assertions.
//!
//! ## Core Types
//!
//! - [`Rule`]: Top-level security rule entity encapsulating metadata and evaluation conditions
//! - [`RuleInner`]: Inner structure containing rule metadata ([`RuleMeta`]) and condition trees ([`RuleCondition`])
//! - [`RuleMeta`]: Rule metadata including namespace, authors, MITRE ATT&CK techniques, and severity
//! - [`RuleScope`]: Canonical static evaluation tier assigned to a rule (`file`, `function`, `basic block`, `instruction`)
//! - [`RuleCondition`]: Untagged AST node representing boolean logic, feature assertions, and localized scopes
//! - [`CapaCharacteristic`]: Strongly-typed enumeration of Mandiant Capa and binary heuristics characteristics
//! - [`StringOrVec`]: Deserialization helper accepting either a scalar string or a string vector
//!
//! ## Overview
//!
//! Declarative rules allow analysts and automated pipelines to express malware capability
//! signatures without hardcoding disassembly checks.
//!
//! - **Capa Specification Alignment**: Implements the Mandiant `capa` format across YAML,
//!   JSON, and compiled MessagePack representations. Supports standard logic operators
//!   (`and`, `or`, `not`), feature checks (`api`, `string`, `mnemonic`, `number`, `offset`),
//!   and contextual scopes (`basic block`, `call`).
//! - **Hierarchical Scope-Based Evaluation**: Rules declare an evaluation tier via `meta.scopes.static` ([`RuleScope`]).
//! - **Two-Tier Partitioned Evaluation**: Independent rules are evaluated concurrently across threads in Pass 1,
//!   and dependent rules are resolved iteratively in Pass 2..N until fixpoint is achieved.
//!
//! ## Examples
//!
//! ```rust
//! use rbat::core::{
//!   eval::Rule,
//!   features::FeatureSet,
//!   types::analysis::AnalysisResult,
//!   needle::NeedleIndex,
//! };
//!
//! let rule_yaml = r#"
//! rule:
//!   meta:
//!     name: sample capability
//!     severity: Medium
//!   features:
//!     - api: CreateProcessA
//! "#;
//!
//! let rule = Rule::from_slice(rule_yaml.as_bytes()).unwrap();
//! assert_eq!(rule.rule.meta.name, "sample capability");
//!
//! let rules = vec![rule];
//! let result = AnalysisResult::default();
//! let features = FeatureSet::new(&result, &[]);
//! let needle = NeedleIndex::new(&rules);
//!
//! let matches = Rule::evaluate(&features, &rules, &needle);
//! ```

pub mod rules;
pub mod rules_condition;

pub use rules::{Rule, RuleInner, RuleMeta};
pub use rules_condition::RuleCondition;

use serde::{Deserialize, Serialize};

/// Inverted index query results
#[derive(Debug)]
pub(crate) enum Candidates<'a> {
    /// Zero-copy borrow of a pre-indexed slice of block or function indices.
    Slice(&'a [u32]),
    /// Allocated vector used when merging unions of candidate sets (Or conditions).
    Vec(Vec<u32>),
    /// Indicates that the condition does not restrict candidates (all elements must be considered).
    None,
}

impl<'a> Candidates<'a> {
    #[inline]
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Slice(s) => s.is_empty(),
            Self::Vec(v) => v.is_empty(),
            Self::None => false,
        }
    }

    #[inline]
    pub fn as_slice(&self) -> Option<&[u32]> {
        match self {
            Self::Slice(s) => Some(s),
            Self::Vec(v) => Some(v.as_slice()),
            Self::None => None,
        }
    }
}

/// Canonical characteristic flags supported by Mandiant Capa and binary heuristics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CapaCharacteristic {
    /// Graph cycle in function CFG.
    Loop,
    /// Basic block self-loop or cycle within a single basic block.
    TightLoop,
    /// Function directly or indirectly calling itself.
    RecursiveCall,
    /// Function makes external calls.
    CallsFrom,
    /// Non-zeroing XOR operation (`xor reg1, reg2` with `reg1 != reg2`).
    Nzxor,
    /// Packed executable / packer signature detected.
    Packed,
    /// Code cave / NOP sled / trap padding detected.
    CodeCave,
    /// Access to Process Environment Block (`fs:[0x30]` on x86, `gs:[0x60]` on x64).
    PebAccess,
    /// Direct segment register access (`fs:` segment).
    FsAccess,
    /// Direct segment register access (`gs:` segment).
    GsAccess,
    /// Control flow crossing binary section boundaries.
    CrossSectionFlow,
    /// Indirect function call (`call reg` / `call [mem]`).
    IndirectCall,
    /// Native unmanaged call transition.
    UnmanagedCall,
    /// Unsupported or unrecognized characteristic.
    Unsupported,
}

impl CapaCharacteristic {
    /// Parses a characteristic string into its canonical enumeration.
    ///
    /// Handles case insensitivity, underscores, hyphens, and common Capa/rbat aliases.
    pub fn parse(s: &str) -> Self {
        let norm = s.trim().to_ascii_lowercase().replace(['_', '-'], " ");
        match norm.as_str() {
            "loop" => Self::Loop,
            "tight loop" => Self::TightLoop,
            "recursive call" | "recursive" => Self::RecursiveCall,
            "calls from" => Self::CallsFrom,
            "nzxor" => Self::Nzxor,
            "packed" | "packer" | "packer sig" | "packer signature" | "embedded pe" => Self::Packed,
            "code cave" | "codecave" => Self::CodeCave,
            "peb access" | "peb" => Self::PebAccess,
            "fs access" | "fs" => Self::FsAccess,
            "gs access" | "gs" => Self::GsAccess,
            "cross section flow" => Self::CrossSectionFlow,
            "indirect call" => Self::IndirectCall,
            "unmanaged call" => Self::UnmanagedCall,
            _ => Self::Unsupported,
        }
    }

    /// Returns the canonical Capa specification string for this characteristic.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Loop => "loop",
            Self::TightLoop => "tight loop",
            Self::RecursiveCall => "recursive call",
            Self::CallsFrom => "calls from",
            Self::Nzxor => "nzxor",
            Self::Packed => "packed",
            Self::CodeCave => "code cave",
            Self::PebAccess => "peb access",
            Self::FsAccess => "fs access",
            Self::GsAccess => "gs access",
            Self::CrossSectionFlow => "cross section flow",
            Self::IndirectCall => "indirect call",
            Self::UnmanagedCall => "unmanaged call",
            Self::Unsupported => "unsupported",
        }
    }
}

impl<'de> Deserialize<'de> for CapaCharacteristic {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Self::parse(&s))
    }
}

impl Serialize for CapaCharacteristic {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

/// Canonical static evaluation scope assigned to a security rule.
///
/// In Mandiant Capa, rules declare their operational scope via `meta.scopes.static`
/// (or default to [`RuleScope::File`] when unspecified). Scopes determine the granular level
/// of abstraction at which rule condition trees are matched against binary features:
///
/// - [`RuleScope::File`]: Evaluated once across the whole binary. Conditions match against
///   global APIs, section Shannon entropies, extracted YARA strings, and aggregate structural metrics.
/// - [`RuleScope::Function`]: Evaluated independently per non-library function. The rule matches
///   if at least one function in the binary satisfies all top-level conditions within its local scope
///   (e.g., local cyclomatic complexity, tight loops, internal call sites, or APIs invoked inside the function).
/// - [`RuleScope::BasicBlock`]: Evaluated independently per basic block. Matches if at least one basic
///   block satisfies all conditions (e.g., specific instruction sequences, mnemonics, operands, or tight loops).
/// - [`RuleScope::Instruction`]: Evaluated across individual machine instructions. Matches if at least one
///   instruction satisfies the condition.
/// - [`RuleScope::Unsupported`]: Designated for dynamic-only or unsupported rule scopes. Evaluates to `false`.
///
/// # Examples
///
/// ```rust
/// use rbat::core::eval::RuleScope;
///
/// let default_scope = RuleScope::default();
/// assert_eq!(default_scope, RuleScope::File);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, Hash)]
pub enum RuleScope {
    /// File scope: evaluated over whole-binary structures and aggregate symbols (default).
    #[default]
    #[serde(alias = "file")]
    File,
    /// Function scope: evaluated across individual recovered functions.
    #[serde(alias = "function")]
    Function,
    /// Basic block scope: evaluated across individual basic blocks.
    #[serde(alias = "basic block", alias = "basic_block", alias = "bb")]
    BasicBlock,
    /// Instruction scope: evaluated across individual machine instructions.
    #[serde(alias = "instruction")]
    Instruction,
    /// Unsupported static scope (e.g. dynamic-only rule).
    Unsupported,
}

/// Helper enum to deserialize either a single string scalar or a list of strings from Serde.
///
/// Many capa metadata fields (such as `authors`, `att&ck`, or `mbc`) permit either a single
/// string value (e.g. `author: "mandiant"`) or an array of strings (e.g. `author: ["mandiant", "analyst"]`).
/// `StringOrVec` transparently deserializes both forms into a unified representation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum StringOrVec {
    /// Single string scalar.
    Single(String),
    /// Vector of strings.
    List(Vec<String>),
}

impl StringOrVec {
    /// Returns the wrapped values as a `Vec<String>`.
    ///
    /// If `self` is [`StringOrVec::Single`], wraps the scalar in a single-element vector.
    /// If `self` is [`StringOrVec::List`], clones the inner vector.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rbat::core::eval::StringOrVec;
    ///
    /// let single = StringOrVec::Single("persistence".into());
    /// assert_eq!(single.to_vec(), vec!["persistence"]);
    ///
    /// let list = StringOrVec::List(vec!["discovery".into(), "lateral-movement".into()]);
    /// assert_eq!(list.to_vec(), vec!["discovery", "lateral-movement"]);
    /// ```
    pub fn to_vec(&self) -> Vec<String> {
        match self {
            Self::Single(s) => vec![s.clone()],
            Self::List(v) => v.clone(),
        }
    }

    /// Extracts a MITRE ATT&CK technique ID from a single formatted string such as
    /// `"Execution::Command Shell [T1059.003]"` or raw `"T1059.003"`.
    pub(crate) fn extract_mitre_id_from(entry: &str) -> String {
        if let Some(start) = entry.find('[')
            && let Some(end) = entry[start..].find(']')
        {
            return entry[start + 1..start + end].to_string();
        }
        entry.to_string()
    }

    /// Parses threshold count values (e.g. `"2 or more"`, `3`, or raw integers) from rule condition properties.
    fn parse_count_threshold(val: &serde_json::Value) -> usize {
        if let Some(n) = val.as_u64() {
            return n as usize;
        }
        if let Some(s) = val.as_str() {
            let s = s.trim();
            if let Some(pos) = s.find(" or more")
                && let Ok(n) = s[..pos].trim().parse::<usize>()
            {
                return n;
            }
            if let Ok(n) = s.parse::<usize>() {
                return n;
            }
        }
        1
    }

    /// Parses number constraints (e.g. `"1 = HANDLE_FLAG_INHERIT"`, `-1`, or raw integers) from rule condition constants.
    fn parse_number_constant(val: &serde_json::Value) -> String {
        if let Some(n) = val.as_u64() {
            return n.to_string();
        }
        if let Some(n) = val.as_i64() {
            return n.to_string();
        }
        if let Some(s) = val.as_str() {
            let parts: Vec<&str> = s.split('=').collect();
            if !parts.is_empty() {
                return parts[0].trim().to_string();
            }
        }
        String::new()
    }
}

impl Default for StringOrVec {
    fn default() -> Self {
        Self::List(Vec::new())
    }
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use crate::core::{
        disassembler::InstructionInfo,
        features::{
            BlockScopeFeatures, FeatureIndices, FeatureSet, FileScopeFeatures,
            FunctionScopeFeatures, GlobalScopeFeatures,
        },
    };
    use ahash::{AHashMap, AHashSet};
    use aho_corasick::PatternID;
    use rustc_hash::FxHashSet;
    use std::sync::Arc;

    pub(crate) fn make_test_insn(
        address: u64,
        mnemonic: &str,
        op_str: &str,
        matched: &[aho_corasick::PatternID],
    ) -> InstructionInfo {
        InstructionInfo {
            address,
            mnemonic: mnemonic.into(),
            op_str: op_str.into(),
            api_resolution: None,
            matched: smallvec::SmallVec::from_slice(matched),
            inst_class: Default::default(),
        }
    }

    pub(crate) fn make_test_block<'buf>(
        start_address: u64,
        end_address: u64,
        instructions: &'buf [InstructionInfo],
        is_tight_loop: bool,
    ) -> BlockScopeFeatures<'buf> {
        let mut nzxor_count = 0;
        let mut peb_access_count = 0;
        let mut fs_access_count = 0;
        let mut gs_access_count = 0;
        for insn in instructions {
            if FeatureSet::is_nzxor(insn) {
                nzxor_count += 1;
            }
            if FeatureSet::is_peb_access(insn) {
                peb_access_count += 1;
            }
            if FeatureSet::is_fs_access(insn) {
                fs_access_count += 1;
            }
            if FeatureSet::is_gs_access(insn) {
                gs_access_count += 1;
            }
        }
        BlockScopeFeatures {
            start_address,
            end_address,
            instructions,
            is_tight_loop,
            nzxor_count,
            peb_access_count,
            fs_access_count,
            gs_access_count,
        }
    }

    pub(crate) fn make_test_function<'buf>(
        start_address: u64,
        end_address: u64,
        block_indices: Vec<usize>,
        blocks: &[BlockScopeFeatures<'buf>],
        has_loop: bool,
        is_recursive: bool,
        calls_from: usize,
    ) -> FunctionScopeFeatures {
        let mut patterns = FxHashSet::default();
        let mut apis = FxHashSet::default();
        let mut nzxor_count = 0;
        let mut peb_access_count = 0;
        let mut fs_access_count = 0;
        let mut gs_access_count = 0;
        let mut tight_loop_count = 0;
        for &idx in &block_indices {
            let b = &blocks[idx];
            nzxor_count += b.nzxor_count;
            peb_access_count += b.peb_access_count;
            fs_access_count += b.fs_access_count;
            gs_access_count += b.gs_access_count;
            if b.is_tight_loop {
                tight_loop_count += 1;
            }
            for insn in b.instructions {
                for &p in &insn.matched {
                    patterns.insert(p);
                    apis.insert(p);
                }
            }
        }
        FunctionScopeFeatures {
            start_address,
            end_address,
            basic_blocks_count: block_indices.len(),
            block_indices,
            patterns,
            apis,
            has_loop,
            cyclomatic_complexity: 1,
            is_recursive,
            calls_from,
            name: None,
            nzxor_count,
            peb_access_count,
            fs_access_count,
            gs_access_count,
            tight_loop_count,
        }
    }

    pub(crate) fn make_test_file_scope<'buf>(
        apis: FxHashSet<PatternID>,
        section_entropies: &'buf AHashMap<&'buf str, f64>,
        basic_blocks_count: usize,
        has_loop: bool,
        max_cyclomatic_complexity: usize,
    ) -> FileScopeFeatures<'buf> {
        FileScopeFeatures {
            apis,
            strings: AHashSet::new(),
            section_entropies,
            has_code_cave: false,
            has_packer_sig: false,
            basic_blocks_count,
            has_loop,
            max_cyclomatic_complexity,
            raw_buffer: &[],
            nzxor_count: 0,
            peb_access_count: 0,
            fs_access_count: 0,
            gs_access_count: 0,
            tight_loop_count: 0,
        }
    }

    pub(crate) fn make_test_feature_set<'buf>(
        mut file_scope: FileScopeFeatures<'buf>,
        function_scope: Vec<FunctionScopeFeatures>,
        basic_block_scope: Vec<BlockScopeFeatures<'buf>>,
        global_scope: GlobalScopeFeatures,
        cfg_instructions: Arc<[InstructionInfo]>,
    ) -> FeatureSet<'buf> {
        let mut nzxor_count = 0;
        let mut peb_access_count = 0;
        let mut fs_access_count = 0;
        let mut gs_access_count = 0;
        let mut tight_loop_count = 0;
        for b in &basic_block_scope {
            nzxor_count += b.nzxor_count;
            peb_access_count += b.peb_access_count;
            fs_access_count += b.fs_access_count;
            gs_access_count += b.gs_access_count;
            if b.is_tight_loop {
                tight_loop_count += 1;
            }
        }
        file_scope.nzxor_count = nzxor_count;
        file_scope.peb_access_count = peb_access_count;
        file_scope.fs_access_count = fs_access_count;
        file_scope.gs_access_count = gs_access_count;
        file_scope.tight_loop_count = tight_loop_count;

        let mut fs = FeatureSet {
            file_scope,
            function_scope,
            basic_block_scope,
            global_scope,
            cfg_instructions,
            indices: FeatureIndices::default(),
        };
        fs.build_indices();
        fs
    }
}

#[cfg(test)]
mod tests {
    use super::test_helpers::*;
    use super::*;
    use crate::core::features::GlobalScopeFeatures;
    use crate::core::needle::NeedleIndex;
    use ahash::{AHashMap, AHashSet};
    use rustc_hash::FxHashSet;
    use std::sync::Arc;

    #[test]
    fn test_unsupported_scope() {
        let yaml = br#"
rule:
  meta:
    name: dynamic only
    scopes:
      static: unsupported
  features:
    - string: "evil"
"#;
        let rule = Rule::from_slice(yaml).unwrap();
        assert_eq!(rule.static_scope(), RuleScope::Unsupported);

        let needle = NeedleIndex::new(std::slice::from_ref(&rule));
        let empty_entropy = AHashMap::new();
        let mut file_scope =
            make_test_file_scope(FxHashSet::default(), &empty_entropy, 0, false, 0);
        file_scope.strings = AHashSet::from_iter(["evil".to_string()]);
        let features = make_test_feature_set(
            file_scope,
            Vec::new(),
            Vec::new(),
            GlobalScopeFeatures::default(),
            Arc::from([]),
        );

        let empty_matched = AHashSet::new();
        assert!(!rule.matches(&features, &needle, &empty_matched));
    }

    #[test]
    fn test_capa_characteristics_and_counting_scopes() {
        let yaml_peb = br#"
rule:
  meta:
    name: peb access instruction
    scopes:
      static: instruction
  features:
    - characteristic: peb access
"#;
        let rule_peb = Rule::from_slice(yaml_peb).unwrap();
        assert_eq!(
            rule_peb.rule.features[0],
            RuleCondition::Characteristic {
                characteristic: CapaCharacteristic::PebAccess
            }
        );
        let needle_peb = NeedleIndex::new(std::slice::from_ref(&rule_peb));

        let insn_peb = make_test_insn(0x1000, "mov", "eax, fs:[0x30]", &[]);
        let insns = vec![insn_peb];
        let blocks = vec![make_test_block(0x1000, 0x1005, &insns, false)];
        let empty_entropy = AHashMap::new();
        let mut file_scope =
            make_test_file_scope(FxHashSet::default(), &empty_entropy, 1, false, 1);
        file_scope.has_code_cave = true;
        file_scope.has_packer_sig = true;
        let features = make_test_feature_set(
            file_scope,
            Vec::new(),
            blocks,
            GlobalScopeFeatures::default(),
            Arc::from([]),
        );
        let empty_matched = AHashSet::new();
        assert!(rule_peb.matches(&features, &needle_peb, &empty_matched));

        // Test CodeCave and Packed characteristics
        let yaml_heuristics = br#"
rule:
  meta:
    name: codecave and packed
    scopes:
      static: file
  features:
    - and:
      - characteristic: code cave
      - characteristic: packed
"#;
        let rule_heur = Rule::from_slice(yaml_heuristics).unwrap();
        let needle_heur = NeedleIndex::new(std::slice::from_ref(&rule_heur));
        assert!(rule_heur.matches(&features, &needle_heur, &empty_matched));

        // Test counting basic blocks in file scope and function scope
        let yaml_count_bb = br#"
rule:
  meta:
    name: multiple basic blocks
    scopes:
      static: file
  features:
    - count(basic block): 2
"#;
        let rule_count_bb = Rule::from_slice(yaml_count_bb).unwrap();
        let needle_count_bb = NeedleIndex::new(std::slice::from_ref(&rule_count_bb));

        let insns1 = vec![make_test_insn(0x1000, "nop", "", &[])];
        let insns2 = vec![make_test_insn(0x1010, "nop", "", &[])];
        let blocks2 = vec![
            make_test_block(0x1000, 0x1005, &insns1, false),
            make_test_block(0x1010, 0x1015, &insns2, false),
        ];
        let func = make_test_function(0x1000, 0x1015, vec![0, 1], &blocks2, false, false, 0);

        let file_scope_multi =
            make_test_file_scope(FxHashSet::default(), &empty_entropy, 2, false, 1);
        let features_multi_bb = make_test_feature_set(
            file_scope_multi,
            vec![func],
            blocks2,
            GlobalScopeFeatures::default(),
            Arc::from([]),
        );

        assert!(rule_count_bb.matches(&features_multi_bb, &needle_count_bb, &empty_matched));

        // Test count(basic block) in function scope
        let yaml_count_fn_bb = br#"
rule:
  meta:
    name: function multiple blocks
    scopes:
      static: function
  features:
    - count(basic block): 2
"#;
        let rule_count_fn_bb = Rule::from_slice(yaml_count_fn_bb).unwrap();
        let needle_count_fn_bb = NeedleIndex::new(std::slice::from_ref(&rule_count_fn_bb));
        assert!(rule_count_fn_bb.matches(&features_multi_bb, &needle_count_fn_bb, &empty_matched));
    }

    #[test]
    fn test_string_or_vec_helpers() {
        let single = StringOrVec::Single("T1059".to_string());
        assert_eq!(single.to_vec(), vec!["T1059".to_string()]);

        let list = StringOrVec::List(vec!["T1059".to_string(), "T1055".to_string()]);
        assert_eq!(
            list.to_vec(),
            vec!["T1059".to_string(), "T1055".to_string()]
        );

        assert_eq!(
            StringOrVec::extract_mitre_id_from("Command Shell [T1059.003]"),
            "T1059.003"
        );
        assert_eq!(StringOrVec::extract_mitre_id_from("T1059"), "T1059");
    }
}
