use crate::prelude::Result;
use crate::types::BinaryMetadata;
use goblin::{Object, error};
use std::{fs, path::PathBuf};

pub fn get_binary_metadata(path: &PathBuf) -> Result<BinaryMetadata> {
    let buffer = fs::read(path)?;

    match Object::parse(&buffer)? {
        Object::Elf(elf) => Ok(BinaryMetadata {
            binary_type: "Linux ELF".to_string(),
            entry_point: elf.entry,
            architecture: elf.header.e_machine,
        }),
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
