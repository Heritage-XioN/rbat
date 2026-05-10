pub mod cli;
mod disassembler;
pub mod error;
pub mod parser;
pub mod traits;
pub mod tui;
pub mod yarahandler;

pub use crate::rbat::disassembler::{DisasmType, Factory};
pub use crate::rbat::error::RbatError;
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

pub type Result<T> = core::result::Result<T, RbatError>;

#[derive(RustEmbed)]
#[folder = "assets/"]
pub struct Asset;

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct YaraMatches {
    pub offset: usize,
    pub section: String,
    pub length: usize,
    pub data: String,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct AnalysisResult {
    pub metadata: BinaryMetadata,
    pub code_cave: HashMap<String, Vec<u64>>,
    pub blacklisted_mnemonics: HashMap<String, u64>,
    pub api_hooking: HashMap<String, u64>,
    pub process_injection: HashSet<String>,
    pub section_entropy: HashMap<String, f64>,
    pub string_values: HashMap<String, Vec<YaraMatches>>,
    pub packer_signatures: HashMap<String, Vec<YaraMatches>>,
}

pub enum MapValue {
    Bytes(Vec<u8>),
    Word(u64),
    OS(DisasmType),
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub enum Confidence {
    #[default]
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Finding {
    pub indicator: String,
    pub description: String,
    pub confidence: Confidence,
    pub weight: u32,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct RiskAssessment {
    pub score: u32,       // 0 to 100
    pub severity: String, // "Safe", "Suspicious", "Malicious"
    pub findings: Vec<Finding>,
    pub recommendations: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct BinaryMetadata {
    pub binary_type: String,
    pub entry_point: u64,
    pub architecture: u16,
}
