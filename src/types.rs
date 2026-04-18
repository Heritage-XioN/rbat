use crate::prelude::*;
use crate::utils::get_txt::get_txt_from_file;
use crate::utils::section_offset::get_section_for_offset;
use clap::Parser as CliParser;
use goblin::elf::sym::{STT_FUNC, STT_OBJECT};
use goblin::{Object, error};
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use std::cmp;
use std::collections::btree_map::Values;
use std::collections::{HashMap, HashSet, binary_heap};
use std::fs;
use std::path::{Path, PathBuf};
use yara::{Compiler, Rules};

/// a rust based static binary analysis tool (This comment becomes the app's description)
#[derive(CliParser, Debug)]
#[command(version, about, long_about = None)]
pub struct Cli {
    /// The path to the binary
    pub path: PathBuf,

    /// Turn on debugging information
    #[arg(short, long)]
    pub debug: bool,

    /// PDF output
    #[arg(short, long)]
    pub pdf: bool,
}

#[derive(Debug)]
pub struct Parser {
    path: PathBuf,
}

#[derive(Debug)]
struct WinDisasm;

#[derive(Debug)]
struct LinuxDisam;

#[derive(Debug)]
struct MacDisasm;

#[derive(Debug)]
pub struct Factory;

#[derive(RustEmbed)]
#[folder = "assets/"]
pub struct Asset;

#[derive(Debug)]
pub struct YaraHandler {
    path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct YaraMatches {
    offset: usize,
    section: String,
    length: usize,
    data: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub metadata: BinaryMetadata,
    pub code_cave: HashMap<String, Vec<u64>>,
    pub blacklisted_mnemonics: HashMap<String, u64>,
    pub api_hooking: HashMap<String, u64>,
    pub process_injection: HashSet<String>,
    pub entropy: f64,
    pub string_values: HashMap<String, Vec<YaraMatches>>,
}

pub enum DisasmType {
    WinDisasm,
    LinuxDisam,
    MacDisasm,
}

pub enum MapValue {
    Bytes(Vec<u8>),
    Word(u64),
    OS(DisasmType),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Confidence {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Finding {
    pub indicator: String,
    pub description: String,
    pub confidence: Confidence,
    pub weight: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RiskAssessment {
    pub score: u32,       // 0 to 100
    pub severity: String, // "Safe", "Suspicious", "Malicious"
    pub findings: Vec<Finding>,
    pub recommendations: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BinaryMetadata {
    pub binary_type: String,
    pub entry_point: u64,
    pub architecture: u16,
}

impl Parser {
    pub fn new(path: PathBuf) -> Self {
        Parser { path: path }
    }

    pub fn parse_buffer(&self) -> Result<HashMap<String, MapValue>> {
        let buffer = fs::read(&self.path)?;

        match Object::parse(&buffer)? {
            Object::Elf(elf) => {
                let mut binary_data: HashMap<String, MapValue> = HashMap::new();
                binary_data.insert("os".to_string(), MapValue::OS(DisasmType::LinuxDisam));
                binary_data.insert("entry_addr".to_string(), MapValue::Word(elf.entry));

                for ph in &elf.program_headers {
                    if ph.p_type == goblin::elf::program_header::PT_LOAD
                        && ph.p_flags & goblin::elf::program_header::PF_X != 0
                    {
                        // TODO: add Safety check to prevent panics on corrupted binaries

                        let text_bytes = &buffer[ph.p_offset as usize..][..ph.p_filesz as usize];
                        binary_data.insert(
                            "text_bytes".to_string(),
                            MapValue::Bytes(text_bytes.to_vec()),
                        );
                    }
                }
                Ok(binary_data)
            }
            Object::PE(pe) => {
                let text_bytes: &[u8] = &[];
                println!("--- Detected Windows PE Binary ---");
                println!("Entry Point: {:#x}", pe.entry);

                println!("\nSections:");
                for ph in &pe.sections {
                    println!("{:#?}", ph);
                }

                println!("\nImports:");
                for import in &pe.imports {
                    println!("  DLL: {}, Function: {}", import.dll, import.name);
                }
                // Ok(text_bytes.to_vec());
                unimplemented!()
            }
            Object::Mach(_mach) => {
                println!("--- Detected macOS Mach-O Binary ---");
                // Mach-O specific logic here
                unimplemented!()
            }
            Object::Archive(_archive) => {
                println!("--- Detected Archive (Static Library) ---");
                unimplemented!()
            }
            Object::Unknown(magic) => {
                println!("Unknown format! Magic bytes: {:#x}", magic);
                unimplemented!()
            }
            _ => {
                println!("other file types");
                unimplemented!()
            }
        }
    }

    pub fn check_process_injec(&self) -> Result<HashSet<String>> {
        let buffer = fs::read(&self.path)?;
        let blacklist = get_txt_from_file("blacklisted_process_injec.txt");
        let mut sus_func: HashSet<String> = HashSet::new();

        match Object::parse(&buffer)? {
            Object::Elf(elf) => {
                for dy in &elf.dynsyms {
                    if dy.st_shndx == 0
                        && let Some(name) = elf.dynstrtab.get_at(dy.st_name)
                    {
                        let dy_type = match dy.st_type() {
                            STT_FUNC => "FUNCTION",
                            STT_OBJECT => "OBJECT",
                            _ => "OTHER",
                        };

                        let dy_binding = match dy.st_bind() {
                            1 => "GLOBAL",
                            2 => "WEAK",
                            _ => "OTHER",
                        };

                        if blacklist.contains(&name.to_string()) {
                            sus_func.insert(name.to_owned());
                        }
                    }
                }
                Ok(sus_func)
            }
            _ => {
                println!("other file types");
                unimplemented!()
            }
        }
    }

    pub fn detect_api_hooking(&self) -> Result<HashMap<String, u64>> {
        let mut api_hooking_func: HashMap<String, u64> = HashMap::new();
        let buffer = fs::read(&self.path)?;
        match Object::parse(&buffer)? {
            Object::Elf(elf) => {
                for dy in &elf.dynsyms {
                    if dy.st_shndx > 0
                        && let Some(name) = elf.dynstrtab.get_at(dy.st_name)
                    {
                        api_hooking_func.insert(name.to_owned(), dy.st_value);
                    }
                }
                Ok(api_hooking_func)
            }
            _ => {
                println!("other file types");
                unimplemented!()
            }
        }
    }
}

impl YaraHandler {
    pub fn new(path: String) -> Self {
        YaraHandler { path }
    }

    /// Compiles YARA rules from the embedded assets
    /// and returns a compiled `Rules` object that can be used for scanning.
    pub fn compile_yara_rule(&self) -> Result<Rules> {
        let file = Asset::get(&self.path).expect("File not found");
        let rules = String::from_utf8(file.data.to_vec()).expect("Invalid UTF-8 in data");
        let mut compiler = Compiler::new()?.add_rules_str(&rules)?;
        let compiled_rule_file = compiler.compile_rules()?;
        Ok(compiled_rule_file)
    }

    /// Scans a file using the provided compiled YARA rules and returns a structured result
    /// with offsets, sections, length and matched data.
    pub fn scan_file(
        &self,
        compiled_rules: Result<Rules>,
        scan_file: &PathBuf,
    ) -> Result<HashMap<String, Vec<YaraMatches>>> {
        let rule = compiled_rules?;
        let mut scanner = rule.scanner().unwrap();
        let results = scanner.scan_file(scan_file).unwrap();
        let mut yara_result: HashMap<String, Vec<YaraMatches>> = HashMap::new();

        if !results.is_empty() {
            for rule in results {
                for yr_string in rule.strings {
                    if yr_string.matches.is_empty() {
                        continue;
                    }

                    for m in yr_string.matches {
                        let buffer = fs::read(&scan_file).unwrap();
                        let section_name = get_section_for_offset(m.offset, &buffer).unwrap();
                        let decoded_string = String::from_utf8_lossy(&m.data).to_string();

                        yara_result
                            .entry(yr_string.identifier.to_string())
                            .or_insert_with(Vec::new)
                            .push(YaraMatches {
                                offset: m.offset,
                                section: section_name,
                                length: m.length,
                                data: decoded_string,
                            });
                    }
                }
            }
            Ok(yara_result)
        } else {
            Ok(yara_result)
        }
    }
}

impl Disassembler for WinDisasm {
    fn disassemble(&self) -> Result<Capstone> {
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build()
            .unwrap();

        Ok(cs)
    }
}

impl Disassembler for LinuxDisam {
    fn disassemble(&self) -> Result<Capstone> {
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Att)
            .detail(true)
            .build()
            .unwrap();

        Ok(cs)
    }
}

impl Disassembler for MacDisasm {
    fn disassemble(&self) -> Result<Capstone> {
        let cs = Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .detail(true)
            .build()
            .unwrap();

        Ok(cs)
    }
}

impl Factory {
    pub fn disasm(disasm_type: DisasmType) -> Box<dyn Disassembler> {
        match disasm_type {
            DisasmType::WinDisasm => Box::new(WinDisasm),
            DisasmType::LinuxDisam => Box::new(LinuxDisam),
            DisasmType::MacDisasm => Box::new(MacDisasm),
        }
    }
}
