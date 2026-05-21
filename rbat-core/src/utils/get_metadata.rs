use crate::core::{BinaryMetadata, RbatError, Result};
use goblin::Object;

pub fn get_binary_metadata(binary_object: &Object) -> Result<BinaryMetadata> {
    match &binary_object {
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
                for arch in fat {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_helpers::test_helpers;
    use tempfile::tempdir;
    use std::fs;

    #[test]
    fn test_get_binary_metadata_elf() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("mock_elf");
        test_helpers::generate_elf(&path);

        let buffer = fs::read(&path).unwrap();
        let obj = Object::parse(&buffer).unwrap();

        let meta = get_binary_metadata(&obj).unwrap();
        assert_eq!(meta.binary_type, "Linux ELF");
        assert_eq!(meta.architecture, goblin::elf::header::EM_X86_64);
    }

    #[test]
    fn test_get_binary_metadata_pe() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("mock_pe");
        test_helpers::generate_pe_stub(&path);

        let buffer = fs::read(&path).unwrap();
        let obj = Object::parse(&buffer).unwrap();

        let meta = get_binary_metadata(&obj).unwrap();
        assert_eq!(meta.binary_type, "Windows PE");
        assert_eq!(meta.architecture, 0x8664);
    }

    #[test]
    fn test_get_binary_metadata_macho() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("mock_macho");
        test_helpers::generate_macho(&path);

        let buffer = fs::read(&path).unwrap();
        let obj = Object::parse(&buffer).unwrap();

        let meta = get_binary_metadata(&obj).unwrap();
        assert_eq!(meta.binary_type, "Mach-O");
        assert_eq!(meta.architecture, (goblin::mach::constants::cputype::CPU_TYPE_X86_64 & 0xFFFF) as u16);
    }

    #[test]
    fn test_get_binary_metadata_unknown() {
        let _buffer = vec![0x41, 0x42, 0x43, 0x44];
        let obj = Object::Unknown(0x44434241);
        let result = get_binary_metadata(&obj);
        assert!(result.is_err());
        match result {
            Err(RbatError::UnsupportedBinaryFormat(_)) => {}
            _ => panic!("Expected UnsupportedBinaryFormat error"),
        }
    }
}
