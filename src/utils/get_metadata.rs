use crate::rbat::{BinaryMetadata, RbatError, Result};
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
        Object::Mach(mach) => match mach {
            goblin::mach::Mach::Binary(macho) => Ok(BinaryMetadata {
                binary_type: "Mach-O".to_string(),
                entry_point: macho.entry,
                architecture: (macho.header.cputype & 0xFFFF) as u16,
            }),
            goblin::mach::Mach::Fat(fat) => {
                for arch in &fat {
                    if let Ok(goblin::mach::SingleArch::MachO(macho)) = arch {
                        return Ok(BinaryMetadata {
                            binary_type: "Mach-O (Fat)".to_string(),
                            entry_point: macho.entry,
                            architecture: (macho.header.cputype & 0xFFFF) as u16,
                        });
                    }
                }
                Err(RbatError::UnsupportedBinaryFormat(
                    "Mach-O fat binary did not contain a parseable Mach-O architecture".to_string(),
                ))
            }
        },
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
