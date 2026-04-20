use crate::prelude::{RbatError, Result};
use crate::types::BinaryMetadata;
use goblin::Object;
use std::{fs, path::PathBuf};

pub fn get_binary_metadata(path: &PathBuf) -> Result<BinaryMetadata> {
    let buffer = fs::read(path)?;

    match Object::parse(&buffer)? {
        Object::Elf(elf) => Ok(BinaryMetadata {
            binary_type: "Linux ELF".to_string(),
            entry_point: elf.entry,
            architecture: elf.header.e_machine,
        }),
        Object::PE(pe) => Ok(BinaryMetadata {
            binary_type: "Windows PE".to_string(),
            entry_point: pe.entry as u64,
            architecture: pe.header.coff_header.machine,
        }),
        Object::Mach(_) => Err(RbatError::UnsupportedBinaryFormat(
            "Mach-O metadata parsing is not implemented yet".to_string(),
        )),
        Object::Archive(_) => Err(RbatError::UnsupportedBinaryFormat(
            "Archive metadata parsing is not supported".to_string(),
        )),
        Object::Unknown(magic) => Err(RbatError::UnsupportedBinaryFormat(format!(
            "Unknown file format magic: {magic:#x}"
        ))),
        _ => Err(RbatError::UnsupportedBinaryFormat(
            "Unsupported file type for metadata extraction".to_string(),
        )),
    }
}
