use crate::prelude::*;
use goblin::{Object, error};
use std::fs;
use std::path::Path;

#[derive(Debug)]
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
struct Factory;

enum DisasmType {
    WinDisasm,
    LinuxDisam,
    MacDisasm,
}

impl Parser {
    pub fn new(path: String) -> Self {
        Parser { path }
    }

    pub fn parse_buffer(&self) -> error::Result<()> {
        let buffer = fs::read(&self.path)?;

        match Object::parse(&buffer)? {
            Object::Elf(elf) => {
                println!("--- Detected Linux ELF Binary ---");
                println!("Entry Point: {:#x}", elf.entry);
                println!("Architecture: {}", elf.header.e_machine);

                println!("\nSections:");
                for section in &elf.section_headers {
                    // Goblin handles the string table lookup for you
                    let name = elf
                        .shdr_strtab
                        .get_at(section.sh_name)
                        .unwrap_or("<unnamed>");
                    println!("  Name: {}, Size: {:#x}", name, section.sh_size);
                }
            }
            Object::PE(pe) => {
                println!("--- Detected Windows PE Binary ---");
                println!("Entry Point: {:#x}", pe.entry);

                println!("\nSections:");
                for section in &pe.sections {
                    let name = String::from_utf8_lossy(&section.name);
                    println!(
                        "  Name: {}, Virtual Size: {:#x}",
                        name.trim_matches(char::from(0)),
                        section.virtual_size
                    );
                }

                println!("\nImports:");
                for import in &pe.imports {
                    println!("  DLL: {}, Function: {}", import.dll, import.name);
                }
            }
            Object::Mach(_mach) => {
                println!("--- Detected macOS Mach-O Binary ---");
                // Mach-O specific logic here
            }
            Object::Archive(_archive) => {
                println!("--- Detected Archive (Static Library) ---");
            }
            Object::Unknown(magic) => {
                println!("Unknown format! Magic bytes: {:#x}", magic);
            }
            _ => {
                println!("other file types")
            }
        }

        Ok(())
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
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build()
            .unwrap();

        Ok(cs)
    }
}

impl Disassembler for MacDisasm {
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

impl Factory {
    fn disasm(disasm_type: DisasmType) -> Box<dyn Disassembler> {
        match disasm_type {
            DisasmType::WinDisasm => Box::new(WinDisasm),
            DisasmType::LinuxDisam => Box::new(LinuxDisam),
            DisasmType::MacDisasm => Box::new(MacDisasm),
        }
    }
}
