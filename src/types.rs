use crate::prelude::*;
use goblin::elf::sym::{STT_FUNC, STT_OBJECT};
use goblin::{Object, error};
use rust_embed::RustEmbed;
use std::collections::btree_map::Values;
use std::collections::{HashMap, HashSet, binary_heap};
use std::fs;
use std::path::Path;
use yara::{Compiler, Rules};

#[derive(Debug, Clone)]
pub struct Parser {
    path: String,
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
#[folder = "assets/"] // This folder sits at your project root
pub struct Asset;

#[derive(Debug)]
pub struct YaraHandler {
    path: String,
}

#[derive(Debug)]
pub struct AnalysisResult {
    code_cave: HashMap<String, u64>,
    blacklisted_mnemonics: HashMap<String, u64>,
    api_hooking: HashMap<String, u64>,
    process_injection: HashSet<String>,
    entropy: f64,
    string_values: Vec<String>,
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

impl Parser {
    pub fn new(path: String) -> Self {
        Parser { path }
    }

    pub fn parse_buffer(&self) -> Result<HashMap<String, MapValue>> {
        let buffer = fs::read(&self.path)?;

        match Object::parse(&buffer)? {
            Object::Elf(elf) => {
                let mut binary_data: HashMap<String, MapValue> = HashMap::new();
                binary_data.insert("os".to_string(), MapValue::OS(DisasmType::LinuxDisam));
                binary_data.insert("entry_addr".to_string(), MapValue::Word(elf.entry));

                println!("--- Detected Linux ELF Binary 23 ---");
                println!("Entry Point: {:#x}", elf.entry);
                println!("Architecture: {}", elf.header.e_machine);

                println!("\nSections:");
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
        let blacklist = ["ptrace", "mmap", "mprotect"];
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

                        if blacklist.contains(&name) {
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

    pub fn detect_api_hooking(&self) -> Result<()> {
        let buffer = fs::read(&self.path)?;
        match Object::parse(&buffer)? {
            Object::Elf(elf) => {
                for dy in &elf.dynsyms {
                    if dy.st_shndx > 0
                        && let Some(name) = elf.dynstrtab.get_at(dy.st_name)
                    {
                        println!("p headers {:#?}, name: {:#?}", dy.st_value, name);
                    }
                }
            }
            _ => {
                println!("other file types");
                unimplemented!()
            }
        }
        Ok(())
    }
}

impl YaraHandler {
    pub fn new(path: String) -> Self {
        YaraHandler { path }
    }

    pub fn compile_yara_rule(&self) -> Result<Rules> {
        let file = Asset::get(&self.path);
        let rules = String::from_utf8(file.unwrap().data.to_vec()).unwrap();
        let mut compiler = Compiler::new()?.add_rules_str(&rules)?;
        let compiled_rule_file = compiler.compile_rules()?;
        Ok(compiled_rule_file)
    }

    pub fn scan_file(&self, compiled_rules: Result<Rules>, scan_file: &str) {
        match compiled_rules {
            Ok(compiled_rules) => {
                let mut scanner = compiled_rules.scanner().unwrap();
                let results = scanner.scan_file(scan_file).unwrap();

                if !results.is_empty() {
                    for yara_match in results {
                        println!("Rule match: {:#?}", yara_match.strings)
                    }
                } else {
                    println!("No YARA Matches!")
                }
            }
            Err(err) => {
                eprintln!("Error compiling YARA rule: {}", err);
            }
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
