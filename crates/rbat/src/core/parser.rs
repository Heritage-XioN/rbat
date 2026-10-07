//! # Multi-Format Binary Parser and Metadata Extractor
//!
//! Provides a unified, format-agnostic abstraction for parsing executable binaries
//! across ELF, PE32, PE64, and Mach-O container formats.
//!
//! ## Core Types
//!
//! - [`Parser`]: Primary metadata and section extractor wrapping an [`object::File`]
//! - [`ParsedBinaryContext`]: Extracted binary context containing OS, architecture, entry point, code bytes, and IAT
//! - [`BinaryOS`]: Target operating system classification ([`Win`], [`Linux`], [`Mac`])
//! - [`BinaryArch`]: Target CPU architecture ([`X86`], [`X64`], [`Arm`], [`Arm64`])
//! - [`IatMap`]: Map associating virtual memory addresses with imported API symbol names
//!
//! ## Overview
//!
//! The parser module serves as the primary intake stage of the analysis pipeline. It isolates
//! platform-specific binary container formats and produces normalized structures consumed by
//! disassembly, control-flow graph reconstruction, and rule matching.
//!
//! - **Format-Agnostic Abstraction**: Uses the [`object`] crate to parse PE, ELF, and Mach-O
//!   structures into a single normalized [`ParsedBinaryContext`].
//! - **Executable Code Discovery**: Identifies the primary executable text section enclosing
//!   the entry point address. If entry point resolution is indirect or unmapped, it falls back
//!   to the first non-empty [`SectionKind::Text`] section.
//! - **Import Address Table (IAT) Mapping**: Traverses PE Import Directory Tables (resolving
//!   First Thunk and Original First Thunk RVAs against the image base) and ELF dynamic relocations
//!   to associate call-site jump targets with named API functions.
//! - **Shannon Entropy Calculation**: Computes Shannon entropy $H = -\sum_{i=0}^{255} p_i \log_2(p_i)$
//!   for each named section. Sections with entropy $\ge 7.5$ typically indicate compressed or
//!   encrypted payloads indicative of packers or crypters.
//!
//! ## Examples
//!
//! ```rust
//! use object::File;
//! use rbat::core::parser::Parser;
//!
//! # fn run(buffer: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
//! let obj = File::parse(buffer)?;
//! let parser = Parser::new(&obj);
//!
//! // Extract normalized execution context
//! let metadata = parser.parse_buffer()?;
//! println!("OS: {:?}, Arch: {:?}, Entry: 0x{:x}", metadata.os, metadata.arch, metadata.entry_addr);
//!
//! // Measure section entropy to detect packers
//! let entropy = parser.evaluate_section_entropy()?;
//! for (section, score) in entropy {
//!     println!("Section {section}: {score:.2}");
//! }
//! # Ok(())
//! # }
//! ```
//!
//! [`Win`]: BinaryOS::Win
//! [`Linux`]: BinaryOS::Linux
//! [`Mac`]: BinaryOS::Mac
//! [`X86`]: BinaryArch::X86
//! [`X64`]: BinaryArch::X64
//! [`Arm`]: BinaryArch::Arm
//! [`Arm64`]: BinaryArch::Arm64

use crate::{
    core::types::result::{RbatError, RbatResult},
    utils::entropy::calculate_entropy,
};
use ahash::AHashMap;
use object::{
    Architecture, BinaryFormat, File, LittleEndian, Object, ObjectSection, ObjectSymbol,
    SectionKind,
    pe::{ImageNtHeaders32, ImageNtHeaders64},
};
use rustc_hash::FxHashMap;
use std::sync::Arc;

/// Maps virtual memory addresses of import table slots to resolved API symbol names.
pub type IatMap = FxHashMap<u64, Arc<str>>;

/// Wraps a parsed [`object::File`] reference to provide format-agnostic binary metadata extraction.
///
/// `Parser` abstracts over container format differences between ELF, PE32, PE64, and Mach-O,
/// providing high-level methods to inspect executable text sections, imported and exported
/// symbols, dynamic relocation targets, and section entropy.
///
/// # Lifetimes
///
/// - `'data`: Lifetime of the raw binary byte buffer backing the parsed object.
/// - `'obj`: Lifetime of the [`object::File`] wrapper reference.
///
/// # Examples
///
/// ```rust
/// use object::File;
/// use rbat::core::parser::Parser;
///
/// # fn run(buffer: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
/// let obj = File::parse(buffer)?;
/// let parser = Parser::new(&obj);
/// let context = parser.parse_buffer()?;
/// println!("Found {} executable bytes", context.text_bytes.len());
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct Parser<'data, 'obj> {
    /// The parsed object representation.
    binary_object: &'obj File<'data, &'data [u8]>,
}

impl<'data, 'obj> Parser<'data, 'obj> {
    /// Creates a new `Parser` instance wrapping an existing [`object::File`].
    ///
    /// # Parameters
    ///
    /// - `binary_object`: Reference to an already-parsed [`object::File`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use object::File;
    /// use rbat::core::parser::Parser;
    ///
    /// # fn run(buffer: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    /// let obj = File::parse(buffer)?;
    /// let parser = Parser::new(&obj);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(binary_object: &'obj File<'data, &'data [u8]>) -> Self {
        Parser { binary_object }
    }

    /// Evaluates the Shannon entropy for each non-empty named section of the binary.
    ///
    /// Entropy is computed according to the Shannon formula:
    /// $$H = -\sum_{i=0}^{255} p_i \log_2(p_i)$$
    /// where $p_i$ represents the empirical probability of byte value $i$. Sections
    /// exhibiting high entropy (typically $\ge 7.5$) indicate compressed or encrypted
    /// content, frequently associated with packers, crypters, or embedded payloads.
    ///
    /// # Returns
    ///
    /// Returns an [`AHashMap`] mapping section names (e.g. `".text"`, `".rsrc"`) to
    /// their Shannon entropy score within the range $[0.0, 8.0]$.
    ///
    /// # Errors
    ///
    /// Returns an [`RbatError`] if section extraction or uncompression encounters an
    /// unrecoverable failure.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use object::File;
    /// use rbat::core::parser::Parser;
    ///
    /// # fn run(buffer: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    /// let obj = File::parse(buffer)?;
    /// let parser = Parser::new(&obj);
    /// let entropy = parser.evaluate_section_entropy()?;
    /// for (section, score) in entropy {
    ///     if score >= 7.5 {
    ///         println!("High entropy in section {section}: {score:.2}");
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn evaluate_section_entropy(&self) -> RbatResult<AHashMap<&'data str, f64>> {
        let mut section_entropy: AHashMap<&'data str, f64> = AHashMap::new();

        for section in self.binary_object.sections() {
            if let Ok(name) = section.name()
                && let Ok(data) = section.uncompressed_data()
                && !data.is_empty()
            {
                section_entropy.insert(name, calculate_entropy(&data));
            }
        }

        Ok(section_entropy)
    }

    /// Parses the binary object into a normalized [`ParsedBinaryContext`].
    ///
    /// Inspects the underlying binary container format to determine:
    /// 1. **Target Operating System**: Maps ELF to [`Linux`], PE/COFF to [`Win`],
    ///    and Mach-O to [`Mac`].
    /// 2. **CPU Architecture**: Identifies [`x86`], [`x86-64`], [`Arm`], and [`AArch64`] targets.
    /// 3. **Executable Text Bytes**: Discovers the code section covering the entry point address,
    ///    or falls back to the first non-empty [`SectionKind::Text`] section.
    /// 4. **Import Address Table**: Builds an [`IatMap`] mapping virtual call targets to imported API names.
    ///
    /// # Returns
    ///
    /// A [`ParsedBinaryContext`] containing normalized execution metadata and executable code bytes.
    ///
    /// # Errors
    ///
    /// - [`RbatError::ValidateBinaryFormatError`]: If the container format or CPU architecture is unrecognized.
    /// - [`RbatError::LocateExecutableSectionError`]: If no suitable executable text section is present.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use object::File;
    /// use rbat::core::parser::Parser;
    ///
    /// # fn run(buffer: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    /// let obj = File::parse(buffer)?;
    /// let parser = Parser::new(&obj);
    /// let ctx = parser.parse_buffer()?;
    /// println!("OS: {:?}, Arch: {:?}, Entry: 0x{:x}", ctx.os, ctx.arch, ctx.entry_addr);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [`Win`]: BinaryOS::Win
    /// [`Linux`]: BinaryOS::Linux
    /// [`Mac`]: BinaryOS::Mac
    /// [`X86`]: BinaryArch::X86
    /// [`X86-64`]: BinaryArch::X64
    /// [`Arm`]: BinaryArch::Arm
    /// [`AArch64`]: BinaryArch::Arm64
    pub fn parse_buffer(&self) -> RbatResult<ParsedBinaryContext> {
        let os = match self.binary_object.format() {
            BinaryFormat::Elf => BinaryOS::Linux,
            BinaryFormat::Pe | BinaryFormat::Coff => BinaryOS::Win,
            BinaryFormat::MachO => BinaryOS::Mac,
            _ => {
                return Err(RbatError::ValidateBinaryFormatError(
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
                return Err(RbatError::ValidateBinaryFormatError(format!(
                    "Unsupported architecture: {:?}",
                    other
                )));
            }
        };

        let entry_addr = self.binary_object.entry();

        let mut text_bytes = None;
        let mut first_fallback_text = None;

        for section in self.binary_object.sections() {
            if section.kind() == SectionKind::Text
                && let Ok(data) = section.uncompressed_data()
            {
                let start = section.address();
                let end = start + section.size();
                if entry_addr != 0 && entry_addr >= start && entry_addr < end {
                    text_bytes = Some(data.into_owned());
                    break;
                } else if first_fallback_text.is_none() && !data.is_empty() {
                    first_fallback_text = Some(data.into_owned());
                }
            }
        }

        let text_bytes = text_bytes
            .or(first_fallback_text)
            .ok_or(RbatError::LocateExecutableSectionError)?;

        let iat_map = self.build_iat_map();

        Ok(ParsedBinaryContext {
            os,
            arch,
            entry_addr,
            text_bytes,
            iat_map,
        })
    }

    /// Builds a map associating absolute virtual addresses with imported API names.
    ///
    /// Resolves dynamic call thunks to enable direct identification of external API invocations
    /// during disassembly and control-flow analysis:
    /// - **PE32 / PE64**: Walks the PE Import Directory Table, following First Thunk and Original
    ///   First Thunk descriptors. Computes the virtual memory address of each IAT slot as
    ///   $\text{ImageBase} + \text{FirstThunk} + (\text{Index} \times \text{PointerSize})$ and maps it
    ///   to the imported function name.
    /// - **ELF**: Traverses dynamic relocations (e.g. `R_X86_64_JUMP_SLOT`), associating the
    ///   relocation target address with its corresponding dynamic symbol name.
    ///
    /// # Returns
    ///
    /// An [`IatMap`] mapping virtual addresses to [`Arc<str>`] API names.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use object::File;
    /// use rbat::core::parser::Parser;
    ///
    /// # fn run(buffer: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    /// let obj = File::parse(buffer)?;
    /// let parser = Parser::new(&obj);
    /// let iat = parser.build_iat_map();
    /// println!("Resolved {} dynamic call targets", iat.len());
    /// # Ok(())
    /// # }
    /// ```
    pub fn build_iat_map(&self) -> IatMap {
        let mut map = IatMap::default();

        match &self.binary_object {
            object::File::Pe32(pe) => {
                let image_base =
                    pe.nt_headers().optional_header.image_base.get(LittleEndian) as u64;
                if let Some(import_table) = pe.import_table().unwrap_or(None)
                    && let Ok(mut iter) = import_table.descriptors()
                {
                    while let Ok(Some(desc)) = iter.next() {
                        let first_thunk = desc.first_thunk.get(LittleEndian);
                        let original_first_thunk = desc.original_first_thunk.get(LittleEndian);
                        let thunk_rva = if original_first_thunk == 0 {
                            first_thunk
                        } else {
                            original_first_thunk
                        };

                        if let Ok(mut thunks) = import_table.thunks(thunk_rva) {
                            let mut thunk_index = 0u64;
                            while let Ok(Some(thunk_data)) = thunks.next::<ImageNtHeaders32>() {
                                if let Ok(object::read::pe::Import::Name(_, name)) =
                                    import_table.import::<ImageNtHeaders32>(thunk_data)
                                {
                                    let iat_addr =
                                        image_base + first_thunk as u64 + (thunk_index * 4);
                                    if let Ok(s) = std::str::from_utf8(name) {
                                        map.insert(iat_addr, s.into());
                                    }
                                }
                                thunk_index += 1;
                            }
                        }
                    }
                }
            }
            object::File::Pe64(pe) => {
                let image_base = pe.nt_headers().optional_header.image_base.get(LittleEndian);
                if let Some(import_table) = pe.import_table().unwrap_or(None)
                    && let Ok(mut iter) = import_table.descriptors()
                {
                    while let Ok(Some(desc)) = iter.next() {
                        let first_thunk = desc.first_thunk.get(LittleEndian);
                        let original_first_thunk = desc.original_first_thunk.get(LittleEndian);
                        let thunk_rva = if original_first_thunk == 0 {
                            first_thunk
                        } else {
                            original_first_thunk
                        };

                        if let Ok(mut thunks) = import_table.thunks(thunk_rva) {
                            let mut thunk_index = 0u64;
                            while let Ok(Some(thunk_data)) = thunks.next::<ImageNtHeaders64>() {
                                if let Ok(object::read::pe::Import::Name(_, name)) =
                                    import_table.import::<ImageNtHeaders64>(thunk_data)
                                {
                                    let iat_addr =
                                        image_base + first_thunk as u64 + (thunk_index * 8);
                                    if let Ok(s) = std::str::from_utf8(name) {
                                        map.insert(iat_addr, s.into());
                                    }
                                }
                                thunk_index += 1;
                            }
                        }
                    }
                }
            }
            _ => {
                // Fallback for ELF using dynamic relocations
                if let Some(relocs) = self.binary_object.dynamic_relocations() {
                    for (addr, reloc) in relocs {
                        if let object::RelocationTarget::Symbol(idx) = reloc.target()
                            && let Ok(sym) = self.binary_object.symbol_by_index(idx)
                            && let Ok(name) = sym.name()
                        {
                            map.insert(addr, name.into());
                        }
                    }
                }
            }
        }
        map
    }

    /// Extracts all dynamically imported symbol names from the binary.
    ///
    /// Gathers symbols declared in standard import tables as well as undefined dynamic symbols
    /// that are resolved by dynamic linkers at load time.
    ///
    /// # Returns
    ///
    /// A vector of raw byte slices representing imported symbol names.
    ///
    /// # Errors
    ///
    /// Returns an [`RbatError`] if the binary's import directory or dynamic symbol table cannot be read.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use object::File;
    /// use rbat::core::parser::Parser;
    ///
    /// # fn run(buffer: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    /// let obj = File::parse(buffer)?;
    /// let parser = Parser::new(&obj);
    /// let imports = parser.extract_imports()?;
    /// for name in imports {
    ///     println!("Import: {}", String::from_utf8_lossy(name));
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn extract_imports(&self) -> RbatResult<Vec<&'data [u8]>> {
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

    /// Extracts all exported symbol names from the binary.
    ///
    /// Gathers symbols declared in standard export tables as well as defined dynamic symbols
    /// exposed for dynamic linking.
    ///
    /// # Returns
    ///
    /// A vector of raw byte slices representing exported symbol names.
    ///
    /// # Errors
    ///
    /// Returns an [`RbatError`] if the binary's export directory or dynamic symbol table cannot be read.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use object::File;
    /// use rbat::core::parser::Parser;
    ///
    /// # fn run(buffer: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    /// let obj = File::parse(buffer)?;
    /// let parser = Parser::new(&obj);
    /// let exports = parser.extract_exports()?;
    /// for name in exports {
    ///     println!("Export: {}", String::from_utf8_lossy(name));
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn extract_exports(&self) -> RbatResult<Vec<&'data [u8]>> {
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

/// Supported target operating systems for assembly syntax style selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOS {
    /// Microsoft Windows operating system (PE/COFF binaries).
    Win,
    /// Linux operating system (ELF binaries).
    Linux,
    /// Apple macOS operating system (Mach-O binaries).
    Mac,
}

/// Supported CPU architectures for disassembly and instruction semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryArch {
    /// 32-bit x86 architecture (IA-32).
    X86,
    /// 64-bit x86-64 architecture (AMD64 / Intel 64).
    X64,
    /// 32-bit ARM architecture (ARMv7 / A32 / T32).
    Arm,
    /// 64-bit ARM architecture (AArch64).
    Arm64,
}

/// Contextual metadata and executable byte payload extracted from initial binary parsing.
#[derive(Debug, Clone)]
pub struct ParsedBinaryContext {
    /// Target operating system classification.
    pub os: BinaryOS,
    /// Target CPU architecture classification.
    pub arch: BinaryArch,
    /// Virtual memory address of the executable entry point.
    pub entry_addr: u64,
    /// Raw bytes of the primary executable code section (e.g. `.text` or `__text`).
    pub text_bytes: Vec<u8>,
    /// Import Address Table mapping virtual addresses to resolved API symbol names.
    pub iat_map: IatMap,
}

#[cfg(test)]
mod tests {
    use std::fs;
    use tempfile::tempdir;

    use super::*;
    use crate::utils::test_helpers;

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
            Err(RbatError::ValidateBinaryFormatError(msg)) => {
                assert!(msg.contains("Unsupported architecture"));
            }
            _ => panic!("Expected ValidateBinaryFormatError error, got {:?}", result),
        }
    }

    #[test]
    fn test_parse_buffer_pe_stub() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("dummy_pe");
        test_helpers::generate_pe_stub(&path);

        let buffer = fs::read(&path).unwrap();
        let binary_object = object::File::parse(&buffer[..]).unwrap();
        let parser = Parser::new(&binary_object);
        let result = parser.parse_buffer();
        assert!(result.is_ok());
        let ctx = result.unwrap();
        assert_eq!(ctx.os, BinaryOS::Win);
        assert!(!ctx.text_bytes.is_empty());
    }
}
