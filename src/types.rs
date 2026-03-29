use crate::prelude::*;
use goblin::{Object, error};
use std::fs;
use std::path::Path;

#[derive(Debug)]
pub struct Parser {
    path: String,
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
