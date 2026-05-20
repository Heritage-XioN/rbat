use std::collections::{HashMap, HashSet};

use crate::core::{BinaryMetadata, YaraMatches};

pub enum AnalysisProgress {
    Disassembly((HashMap<String, Vec<u64>>, HashMap<String, u64>)),
    Strings(HashMap<String, Vec<YaraMatches>>),
    PackerSigs(HashMap<String, Vec<YaraMatches>>),
    Entropy(HashMap<String, f64>),
    ApiHooking(HashMap<String, u64>),
    ProcessInjection(HashSet<String>),
    BinaryMetadata(BinaryMetadata),
}
