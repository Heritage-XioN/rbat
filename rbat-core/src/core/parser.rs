//! # Multi-Format Binary Parser and Metadata Extractor
//!
//! This module defines the [`Parser`] structure, which provides a unified,
//! format-agnostic abstraction for retrieving executable segments, OS target information,
//! and CPU architecture across ELF, PE, and Mach-O files.
//!
//! # Example
//! ```rust
//! use object::File;
//! use rbat::core::parser::Parser;
//!
//! # fn run(buffer: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
//! let obj = File::parse(buffer)?;
//! let parser = Parser::new(&obj);
//!
//! let metadata = parser.parse_buffer()?;
//! let entropy = parser.evaluate_section_entropy()?;
//! # Ok(())
//! # }
//! ```

use crate::{core::ParsedBinaryContext, utils::entropy::calculate_entropy};
use object::{Architecture, BinaryFormat, File, Object, ObjectSection, ObjectSymbol, SectionKind};
use std::collections::HashMap;

use super::{BinaryArch, BinaryOS, RbatError, Result};

/// A central struct for binary analysis that abstracts over ELF, PE, and Mach-O formats.
/// It holds the raw binary buffer and the parsed object from the `object` crate.
#[derive(Debug)]
pub struct Parser<'obj> {
    /// The parsed object representation.
    binary_object: &'obj File<'obj, &'obj [u8]>,
}

impl<'obj> Parser<'obj> {
    /// Creates a new `Parser` instance.
    pub fn new(binary_object: &'obj File<'obj, &'obj [u8]>) -> Self {
        Parser { binary_object }
    }

    /// Evaluates the Shannon entropy for each section of the binary.
    ///
    /// This is useful for identifying packed or encrypted sections where entropy is typically high (>= 7.5).
    pub fn evaluate_section_entropy(&self) -> Result<HashMap<String, f64>> {
        let mut section_entropy: HashMap<String, f64> = HashMap::new();

        for section in self.binary_object.sections() {
            if let Ok(name) = section.name()
                && let Ok(data) = section.uncompressed_data()
                && !data.is_empty()
            {
                section_entropy.insert(name.to_string(), calculate_entropy(&data));
            }
        }

        Ok(section_entropy)
    }

    /// Parses the binary buffer for initial mapped values.
    pub fn parse_buffer(&self) -> Result<ParsedBinaryContext> {
        let os = match self.binary_object.format() {
            BinaryFormat::Elf => BinaryOS::Linux,
            BinaryFormat::Pe => BinaryOS::Win,
            BinaryFormat::MachO => BinaryOS::Mac,
            _ => {
                return Err(RbatError::UnsupportedBinaryFormat(
                    "Unsupported OS format".into(),
                ));
            }
        };

        let arch = match self.binary_object.architecture() {
            Architecture::X86_64 | Architecture::X86_64_X32 => BinaryArch::X64,
            Architecture::I386 => BinaryArch::X86,
            Architecture::Aarch64 | Architecture::Aarch64_Ilp32 => BinaryArch::Arm64,
            Architecture::Arm => BinaryArch::Arm,
            other => {
                return Err(RbatError::UnsupportedBinaryFormat(format!(
                    "Unsupported architecture: {:?}",
                    other
                )));
            }
        };

        let entry_addr = self.binary_object.entry();

        let mut text_bytes = None;
        for section in self.binary_object.sections() {
            if section.kind() == SectionKind::Text
                && let Ok(data) = section.uncompressed_data()
            {
                text_bytes = Some(data.into_owned());
                break;
            }
        }

        let text_bytes = text_bytes.ok_or(RbatError::MissingExecutableSection)?;

        Ok(ParsedBinaryContext {
            os,
            arch,
            entry_addr,
            text_bytes,
        })
    }

    /// Extracts all dynamically imported symbols.
    pub fn extract_imports(&self) -> Result<Vec<&'obj [u8]>> {
        let mut imports_list = Vec::new();

        if let Ok(imports) = self.binary_object.imports() {
            for import in imports {
                imports_list.push(import.name());
            }
        }

        // Also extract undefined dynamic symbols which act as imports
        for symbol in self.binary_object.dynamic_symbols() {
            if let Ok(name) = symbol.name_bytes()
                && symbol.is_undefined()
            {
                imports_list.push(name);
            }
        }

        Ok(imports_list)
    }

    /// Extracts all exported symbols.
    pub fn extract_exports(&self) -> Result<Vec<&'obj [u8]>> {
        let mut exports_list = Vec::new();

        if let Ok(exports) = self.binary_object.exports() {
            for export in exports {
                exports_list.push(export.name());
            }
        }

        // Also extract defined dynamic symbols which act as exports
        for symbol in self.binary_object.dynamic_symbols() {
            if let Ok(name) = symbol.name_bytes()
                && !symbol.is_undefined()
            {
                exports_list.push(name);
            }
        }

        Ok(exports_list)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use tempfile::tempdir;

    use super::*;
    use crate::utils::test_helpers::test_helpers;

    #[test]
    fn test_evaluate_section_entropy_elf() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("dummy_elf");
        test_helpers::generate_elf(&path);

        let buffer = fs::read(&path).unwrap();
        let binary_object = object::File::parse(&buffer[..]).unwrap();
        let parser = Parser::new(&binary_object);
        let result = parser.evaluate_section_entropy();
        assert!(result.is_ok());
        let entropy = result.unwrap();
        assert!(entropy.contains_key(".text"));
    }

    #[test]
    fn test_parse_buffer_elf() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("dummy_elf");
        test_helpers::generate_elf(&path);

        let buffer = fs::read(&path).unwrap();
        let binary_object = object::File::parse(&buffer[..]).unwrap();
        let parser = Parser::new(&binary_object);
        let result = parser.parse_buffer();
        match result {
            Ok(data) => {
                assert!(!data.text_bytes.is_empty());
                assert_eq!(data.os, BinaryOS::Linux);
            }
            Err(_) => panic!("Failed to parse ELF buffer"),
        }
    }

    #[test]
    fn test_evaluate_section_entropy_macho() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("dummy_macho");
        test_helpers::generate_macho(&path);

        let buffer = fs::read(&path).unwrap();
        let binary_object = object::File::parse(&buffer[..]).unwrap();
        let parser = Parser::new(&binary_object);
        let result = parser.evaluate_section_entropy();
        assert!(result.is_ok());
        let entropy = result.unwrap();
        assert!(entropy.contains_key("__text"));
    }

    #[test]
    fn test_parse_buffer_unsupported_arch() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("unsupported_elf");
        test_helpers::generate_elf_unsupported(&path);

        let buffer = fs::read(&path).unwrap();
        let binary_object = object::File::parse(&buffer[..]).unwrap();
        let parser = Parser::new(&binary_object);
        let result = parser.parse_buffer();
        match result {
            Err(RbatError::UnsupportedBinaryFormat(msg)) => {
                assert!(msg.contains("Unsupported architecture"));
            }
            _ => panic!("Expected UnsupportedBinaryFormat error, got {:?}", result),
        }
    }
}
