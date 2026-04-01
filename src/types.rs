use crate::prelude::*;
use goblin::{Object, error};
use std::collections::HashMap;
use std::collections::btree_map::Values;
use std::fs;
use std::path::Path;

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

pub enum DisasmType {
    WinDisasm,
    LinuxDisam,
    MacDisasm,
}

pub enum MapSize {
    Bytes(Vec<u8>),
    Word(u64),
}

impl Parser {
    pub fn new(path: String) -> Self {
        Parser { path }
    }

    pub fn parse_buffer(&self) -> Result<HashMap<String, MapSize>> {
        let buffer = fs::read(&self.path)?;

        match Object::parse(&buffer)? {
            Object::Elf(elf) => {
                let mut binary_data: HashMap<String, MapSize> = HashMap::new();
                binary_data.insert("entry_addr".to_string(), MapSize::Word(elf.entry));

                println!("--- Detected Linux ELF Binary 23 ---");
                println!("Entry Point: {:#x}", elf.entry);
                println!("Architecture: {}", elf.header.e_machine);

                println!("\nSections:");
                for ph in &elf.program_headers {
                    if ph.p_type == goblin::elf::program_header::PT_LOAD
                        && ph.p_flags & goblin::elf::program_header::PF_X != 0
                    {
                        let text_bytes = &buffer[ph.p_offset as usize..][..ph.p_filesz as usize];
                        binary_data.insert(
                            "text_bytes".to_string(),
                            MapSize::Bytes(text_bytes.to_vec()),
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
