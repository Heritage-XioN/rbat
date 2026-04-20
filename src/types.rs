use crate::prelude::*;
use crate::utils::get_txt::get_txt_from_file;
use crate::utils::section_offset::get_section_for_offset;
use clap::Parser as CliParser;
use goblin::Object;
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
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

/// a struct to hold the parsed binary data and provide methods for analysis.
#[derive(Debug)]
pub struct Parser {
    path: PathBuf,
}

/// windows disassembler struct
#[derive(Debug)]
struct WinDisasm;

/// linux disassembler struct
#[derive(Debug)]
struct LinuxDisasm;

/// mac disassembler struct
#[derive(Debug)]
struct MacDisasm;

/// capstone factory implementation.
/// returns the appropriate disassembler based on the binary's OS type.
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
    LinuxDisasm,
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
        Parser { path }
    }

    pub fn parse_buffer(&self) -> Result<HashMap<String, MapValue>> {
        let buffer = fs::read(&self.path)?;

        match Object::parse(&buffer)? {
            Object::Elf(elf) => {
                let mut binary_data: HashMap<String, MapValue> = HashMap::new();
                binary_data.insert("os".to_string(), MapValue::OS(DisasmType::LinuxDisasm));
                binary_data.insert("entry_addr".to_string(), MapValue::Word(elf.entry));

                for ph in &elf.program_headers {
                    if ph.p_type == goblin::elf::program_header::PT_LOAD
                        && ph.p_flags & goblin::elf::program_header::PF_X != 0
                    {
                        let start = ph.p_offset as usize;
                        let size = ph.p_filesz as usize;
                        let end = start.checked_add(size).ok_or_else(|| {
                            RbatError::InvalidBinaryLayout(
                                "Executable segment offset overflowed file bounds".to_string(),
                            )
                        })?;
                        let text_bytes = buffer.get(start..end).ok_or_else(|| {
                            RbatError::InvalidBinaryLayout(format!(
                                "Executable segment range {start}..{end} is outside file bounds"
                            ))
                        })?;
                        binary_data.insert(
                            "text_bytes".to_string(),
                            MapValue::Bytes(text_bytes.to_vec()),
                        );
                        break;
                    }
                }

                if !binary_data.contains_key("text_bytes") {
                    return Err(RbatError::MissingExecutableSection);
                }
                Ok(binary_data)
            }
            Object::PE(pe) => {
                let mut binary_data: HashMap<String, MapValue> = HashMap::new();
                binary_data.insert("os".to_string(), MapValue::OS(DisasmType::WinDisasm));
                binary_data.insert(
                    "entry_addr".to_string(),
                    MapValue::Word(pe.image_base + pe.entry as u64),
                );

                const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
                let entry_rva = pe.entry as u32;
                let executable_section = pe
                    .sections
                    .iter()
                    .find(|section| {
                        let start = section.virtual_address;
                        let size = section.virtual_size.max(section.size_of_raw_data);
                        let end = start.saturating_add(size);
                        section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
                            && entry_rva >= start
                            && entry_rva < end
                    })
                    .or_else(|| {
                        pe.sections
                            .iter()
                            .find(|section| section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0)
                    });

                if let Some(section) = executable_section {
                    let start = section.pointer_to_raw_data as usize;
                    let size = section.size_of_raw_data as usize;
                    let end = start.checked_add(size).ok_or_else(|| {
                        RbatError::InvalidBinaryLayout(
                            "PE executable section offset overflowed file bounds".to_string(),
                        )
                    })?;
                    let text_bytes = buffer.get(start..end).ok_or_else(|| {
                        RbatError::InvalidBinaryLayout(format!(
                            "PE executable section range {start}..{end} is outside file bounds"
                        ))
                    })?;
                    binary_data.insert(
                        "text_bytes".to_string(),
                        MapValue::Bytes(text_bytes.to_vec()),
                    );
                }

                if !binary_data.contains_key("text_bytes") {
                    return Err(RbatError::MissingExecutableSection);
                }
                Ok(binary_data)
            }
            Object::Mach(mach) => {
                let mut binary_data: HashMap<String, MapValue> = HashMap::new();
                binary_data.insert("os".to_string(), MapValue::OS(DisasmType::MacDisasm));

                match mach {
                    goblin::mach::Mach::Binary(macho) => {
                        binary_data.insert("entry_addr".to_string(), MapValue::Word(macho.entry));

                        for segment in &macho.segments {
                            for (section, section_data) in segment.into_iter().flatten() {
                                let section_name = section.name().unwrap_or("");
                                let segment_name = section.segname().unwrap_or("");
                                if segment_name == "__TEXT" && section_name == "__text" {
                                    binary_data.insert(
                                        "text_bytes".to_string(),
                                        MapValue::Bytes(section_data.to_vec()),
                                    );
                                    break;
                                }
                            }
                            if binary_data.contains_key("text_bytes") {
                                break;
                            }
                        }
                    }
                    goblin::mach::Mach::Fat(fat) => {
                        for arch in &fat {
                            if let Ok(goblin::mach::SingleArch::MachO(macho)) = arch {
                                binary_data
                                    .insert("entry_addr".to_string(), MapValue::Word(macho.entry));

                                for segment in &macho.segments {
                                    for (section, section_data) in segment.into_iter().flatten() {
                                        let section_name = section.name().unwrap_or("");
                                        let segment_name = section.segname().unwrap_or("");
                                        if segment_name == "__TEXT" && section_name == "__text" {
                                            binary_data.insert(
                                                "text_bytes".to_string(),
                                                MapValue::Bytes(section_data.to_vec()),
                                            );
                                            break;
                                        }
                                    }
                                    if binary_data.contains_key("text_bytes") {
                                        break;
                                    }
                                }
                                break;
                            }
                        }
                    }
                }

                if !binary_data.contains_key("entry_addr")
                    || !binary_data.contains_key("text_bytes")
                {
                    return Err(RbatError::MissingExecutableSection);
                }
                Ok(binary_data)
            }
            Object::Archive(_) => Err(RbatError::UnsupportedBinaryFormat(
                "Archive files are not supported for disassembly".to_string(),
            )),
            Object::Unknown(magic) => Err(RbatError::UnsupportedBinaryFormat(format!(
                "Unknown file format magic: {magic:#x}"
            ))),
            _ => Err(RbatError::UnsupportedBinaryFormat(
                "Unsupported file type for disassembly".to_string(),
            )),
        }
    }

    pub fn check_process_injec(&self) -> Result<HashSet<String>> {
        let buffer = fs::read(&self.path)?;
        let blacklist = get_txt_from_file("blacklisted_process_injec.txt")?;
        let mut sus_func: HashSet<String> = HashSet::new();

        match Object::parse(&buffer)? {
            Object::Elf(elf) => {
                for dy in &elf.dynsyms {
                    if dy.st_shndx == 0
                        && let Some(name) = elf.dynstrtab.get_at(dy.st_name)
                    {
                        if blacklist.contains(&name.to_string()) {
                            sus_func.insert(name.to_owned());
                        }
                    }
                }
                Ok(sus_func)
            }
            Object::Mach(mach) => {
                let matches_blacklist = |name: &str| {
                    let normalized = name.trim_start_matches('_');
                    blacklist
                        .iter()
                        .any(|item| item.eq_ignore_ascii_case(normalized))
                };

                let mut collect_from_macho = |macho: &goblin::mach::MachO<'_>| -> Result<()> {
                    if let Ok(imports) = macho.imports() {
                        for import in imports {
                            if matches_blacklist(import.name) {
                                sus_func.insert(import.name.to_string());
                            }
                        }
                    }

                    for (name, symbol) in macho.symbols().flatten() {
                        if symbol.is_undefined() && matches_blacklist(name) {
                            sus_func.insert(name.to_string());
                        }
                    }
                    Ok(())
                };

                match mach {
                    goblin::mach::Mach::Binary(macho) => collect_from_macho(&macho)?,
                    goblin::mach::Mach::Fat(fat) => {
                        for arch in &fat {
                            if let Ok(goblin::mach::SingleArch::MachO(macho)) = arch {
                                collect_from_macho(&macho)?;
                            }
                        }
                    }
                }
                Ok(sus_func)
            }
            Object::PE(pe) => {
                for import in &pe.imports {
                    let import_name = import.name.to_string();
                    if blacklist
                        .iter()
                        .any(|item| item.eq_ignore_ascii_case(&import_name))
                    {
                        sus_func.insert(import_name);
                    }
                }
                Ok(sus_func)
            }
            _ => Err(RbatError::UnsupportedBinaryFormat(
                "Process injection checks currently support ELF, PE, and Mach-O binaries only"
                    .to_string(),
            )),
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
            Object::PE(pe) => {
                for import in &pe.imports {
                    let function = import.name.to_string();
                    let dll = import.dll.to_string();
                    api_hooking_func.insert(format!("{dll}!{function}"), import.rva as u64);
                }
                Ok(api_hooking_func)
            }
            Object::Mach(mach) => {
                let mut collect_from_macho = |macho: &goblin::mach::MachO<'_>| -> Result<()> {
                    if let Ok(imports) = macho.imports() {
                        for import in imports {
                            api_hooking_func.insert(
                                format!("{}!{}", import.dylib, import.name),
                                import.address,
                            );
                        }
                    }

                    for (name, symbol) in macho.symbols().flatten() {
                        if symbol.is_global() && !symbol.is_undefined() {
                            api_hooking_func.insert(name.to_string(), symbol.n_value);
                        }
                    }
                    Ok(())
                };

                match mach {
                    goblin::mach::Mach::Binary(macho) => collect_from_macho(&macho)?,
                    goblin::mach::Mach::Fat(fat) => {
                        for arch in &fat {
                            if let Ok(goblin::mach::SingleArch::MachO(macho)) = arch {
                                collect_from_macho(&macho)?;
                            }
                        }
                    }
                }
                Ok(api_hooking_func)
            }
            _ => Err(RbatError::UnsupportedBinaryFormat(
                "API hooking detection currently supports ELF, PE, and Mach-O binaries only"
                    .to_string(),
            )),
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
        let file =
            Asset::get(&self.path).ok_or_else(|| RbatError::MissingAsset(self.path.to_string()))?;
        let rules = String::from_utf8(file.data.to_vec())?;
        let compiler = Compiler::new()?.add_rules_str(&rules)?;
        let compiled_rule_file = compiler.compile_rules()?;
        Ok(compiled_rule_file)
    }

    /// Scans a file using the provided compiled YARA rules and returns a structured result
    /// with offsets, sections, length and matched data.
    pub fn scan_file(
        &self,
        compiled_rules: Rules,
        scan_file: &PathBuf,
    ) -> Result<HashMap<String, Vec<YaraMatches>>> {
        let mut scanner = compiled_rules.scanner()?;
        let results = scanner.scan_file(scan_file)?;
        let mut yara_result: HashMap<String, Vec<YaraMatches>> = HashMap::new();
        let buffer = fs::read(scan_file)?;

        if !results.is_empty() {
            for rule in results {
                for yr_string in rule.strings {
                    if yr_string.matches.is_empty() {
                        continue;
                    }

                    for m in yr_string.matches {
                        let section_name = get_section_for_offset(m.offset, &buffer)?;
                        let decoded_string = String::from_utf8_lossy(&m.data).to_string();

                        yara_result
                            .entry(yr_string.identifier.to_string())
                            .or_default()
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
            .build()?;

        Ok(cs)
    }
}

impl Disassembler for LinuxDisasm {
    fn disassemble(&self) -> Result<Capstone> {
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Att)
            .detail(true)
            .build()?;

        Ok(cs)
    }
}

impl Disassembler for MacDisasm {
    fn disassemble(&self) -> Result<Capstone> {
        let cs = Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .detail(true)
            .build()?;

        Ok(cs)
    }
}

impl Factory {
    pub fn disasm(disasm_type: DisasmType) -> Box<dyn Disassembler> {
        match disasm_type {
            DisasmType::WinDisasm => Box::new(WinDisasm),
            DisasmType::LinuxDisasm => Box::new(LinuxDisasm),
            DisasmType::MacDisasm => Box::new(MacDisasm),
        }
    }
}
