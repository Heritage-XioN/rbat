//! # Binary Header Metadata Extractor
//!
//! This module extracts target platform details, machine architecture codes, and entry point
//! addresses from a parsed [`Object`] representation of ELF, PE, and Mach-O files.

use crate::core::{BinaryMetadata, RbatError, Result};
use object::{Architecture, BinaryFormat, Object};

/// Extracts high-level metadata (architecture type, entry address, name) from a parsed object.
///
/// # Errors
/// Returns `RbatError::UnsupportedBinaryFormat` if the parsed magic does not map to ELF, PE, or Mach-O.
pub fn get_binary_metadata(binary_object: &object::File) -> Result<BinaryMetadata> {
    let binary_type = match binary_object.format() {
        BinaryFormat::Elf => "Linux ELF",
        BinaryFormat::Pe | BinaryFormat::Coff => "Windows PE",
        BinaryFormat::MachO => "Mach-O",
        _ => {
            return Err(RbatError::UnsupportedBinaryFormat(
                "Unsupported format".to_string(),
            ));
        }
    }
    .to_string();

    let architecture = match binary_object.architecture() {
        Architecture::X86_64 | Architecture::X86_64_X32 => 0x3e,
        Architecture::I386 => 0x03,
        Architecture::Arm => 0x28,
        Architecture::Aarch64 | Architecture::Aarch64_Ilp32 => 0xb7,
        _ => 0,
    };

    Ok(BinaryMetadata {
        binary_type,
        entry_point: binary_object.entry(),
        architecture,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_helpers::test_helpers;
    use object::File;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_get_binary_metadata_elf() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("mock_elf");
        test_helpers::generate_elf(&path);

        let buffer = fs::read(&path).unwrap();
        let obj = File::parse(buffer.as_slice()).unwrap();

        let meta = get_binary_metadata(&obj).unwrap();
        assert_eq!(meta.binary_type, "Linux ELF");
        assert_eq!(meta.architecture, 0x3e);
    }

    #[test]
    fn test_get_binary_metadata_pe() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("mock_pe");
        test_helpers::generate_pe_stub(&path);

        let buffer = fs::read(&path).unwrap();
        let obj = File::parse(buffer.as_slice()).unwrap();

        let meta = get_binary_metadata(&obj).unwrap();
        assert_eq!(meta.binary_type, "Windows PE");
        assert_eq!(meta.architecture, 0x3e);
    }

    #[test]
    fn test_get_binary_metadata_macho() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("mock_macho");
        test_helpers::generate_macho(&path);

        let buffer = fs::read(&path).unwrap();
        let obj = File::parse(buffer.as_slice()).unwrap();

        let meta = get_binary_metadata(&obj).unwrap();
        assert_eq!(meta.binary_type, "Mach-O");
        assert_eq!(meta.architecture, 0x3e);
    }
}
