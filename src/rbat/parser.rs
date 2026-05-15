use crate::utils::entropy::calculate_entropy;
use crate::utils::get_txt::get_txt_from_file;
use goblin::Object;
use std::{
    collections::{HashMap, HashSet},
    path::Path,
};

use super::{DisasmType, MapValue, RbatError, Result};

/// a struct to hold the parsed binary data and provide methods for analysis.
#[derive(Debug)]
pub struct Parser<'bin> {
    bin_path: &'bin Path,
    buffer: Vec<u8>,
    binary_object: Object<'bin>,
}

impl<'bin> Parser<'bin> {
    pub fn new(bin_path: &'bin Path, buffer: Vec<u8>, binary_object: Object<'bin>) -> Self {
        Parser {
            bin_path,
            buffer,
            binary_object,
        }
    }

    pub fn evaluate_section_entropy(&self) -> Result<HashMap<String, f64>> {
        let mut section_entropy: HashMap<String, f64> = HashMap::new();

        match &self.binary_object {
            Object::Elf(elf) => {
                for sh in &elf.section_headers {
                    if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
                        let start = sh.sh_offset as usize;
                        let size = sh.sh_size as usize;
                        if size > 0 && start + size <= self.buffer.len() {
                            let data = &self.buffer[start..start + size];
                            section_entropy.insert(name.to_string(), calculate_entropy(data));
                        }
                    }
                }
            }
            Object::PE(pe) => {
                for section in &pe.sections {
                    if let Ok(name) = section.name() {
                        let start = section.pointer_to_raw_data as usize;
                        let size = section.size_of_raw_data as usize;
                        if size > 0 && start + size <= self.buffer.len() {
                            let data = &self.buffer[start..start + size];
                            section_entropy.insert(name.to_string(), calculate_entropy(data));
                        }
                    }
                }
            }
            Object::Mach(mach) => match mach {
                goblin::mach::Mach::Binary(macho) => {
                    for segment in &macho.segments {
                        for (section, section_data) in segment.into_iter().flatten() {
                            if let Ok(name) = section.name()
                                && !section_data.is_empty()
                            {
                                section_entropy
                                    .insert(name.to_string(), calculate_entropy(section_data));
                            }
                        }
                    }
                }
                goblin::mach::Mach::Fat(fat) => {
                    for arch in fat {
                        if let Ok(goblin::mach::SingleArch::MachO(macho)) = arch {
                            for segment in &macho.segments {
                                for (section, section_data) in segment.into_iter().flatten() {
                                    if let Ok(name) = section.name()
                                        && !section_data.is_empty()
                                    {
                                        section_entropy.insert(
                                            name.to_string(),
                                            calculate_entropy(section_data),
                                        );
                                    }
                                }
                            }
                            break;
                        }
                    }
                }
            },
            _ => {}
        }

        Ok(section_entropy)
    }

    pub fn parse_buffer(&self) -> Result<HashMap<String, MapValue>> {
        match &self.binary_object {
            Object::Elf(elf) => {
                let mut binary_data: HashMap<String, MapValue> = HashMap::new();
                binary_data.insert("os".to_string(), MapValue::OS(DisasmType::Linux));
                binary_data.insert("entry_addr".to_string(), MapValue::Word(elf.entry));

                for ph in &elf.program_headers {
                    if ph.p_type == goblin::elf::program_header::PT_LOAD
                        && ph.p_flags & goblin::elf::program_header::PF_X != 0
                    {
                        let start = ph.p_offset as usize;
                        let size = ph.p_filesz as usize;
                        let end = start.checked_add(size).ok_or_else(|| {
                            RbatError::InvalidBinaryLayout(
                                "Executable segment offset overflowed file bounds".to_string(),
                            )
                        })?;
                        let text_bytes = self.buffer.get(start..end).ok_or_else(|| {
                            RbatError::InvalidBinaryLayout(format!(
                                "Executable segment range {start}..{end} is outside file bounds"
                            ))
                        })?;
                        binary_data.insert(
                            "text_bytes".to_string(),
                            MapValue::Bytes(text_bytes.to_vec()),
                        );
                        break;
                    }
                }

                if !binary_data.contains_key("text_bytes") {
                    for sh in &elf.section_headers {
                        if let (Some(name), Some(end)) = (
                            elf.shdr_strtab.get_at(sh.sh_name),
                            (sh.sh_offset as usize).checked_add(sh.sh_size as usize),
                        ) && name == ".text"
                        {
                            let start = sh.sh_offset as usize;
                            let text_bytes = self.buffer.get(start..end).ok_or_else(|| {
                                RbatError::InvalidBinaryLayout(format!(
                                    "Executable section range {start}..{end} is outside file bounds"
                                ))
                            })?;
                            binary_data.insert(
                                "text_bytes".to_string(),
                                MapValue::Bytes(text_bytes.to_vec()),
                            );
                            break;
                        }
                    }
                }

                if !binary_data.contains_key("text_bytes") {
                    return Err(RbatError::MissingExecutableSection);
                }
                Ok(binary_data)
            }
            Object::PE(pe) => {
                let mut binary_data: HashMap<String, MapValue> = HashMap::new();
                binary_data.insert("os".to_string(), MapValue::OS(DisasmType::Win));
                binary_data.insert(
                    "entry_addr".to_string(),
                    MapValue::Word(pe.image_base + pe.entry as u64),
                );

                const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
                let entry_rva = pe.entry;
                let executable_section = pe
                    .sections
                    .iter()
                    .find(|section| {
                        let start = section.virtual_address;
                        let size = section.virtual_size.max(section.size_of_raw_data);
                        let end = start.saturating_add(size);
                        section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
                            && entry_rva >= start
                            && entry_rva < end
                    })
                    .or_else(|| {
                        pe.sections
                            .iter()
                            .find(|section| section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0)
                    });

                if let Some(section) = executable_section {
                    let start = section.pointer_to_raw_data as usize;
                    let size = section.size_of_raw_data as usize;
                    let end = start.checked_add(size).ok_or_else(|| {
                        RbatError::InvalidBinaryLayout(
                            "PE executable section offset overflowed file bounds".to_string(),
                        )
                    })?;
                    let text_bytes = self.buffer.get(start..end).ok_or_else(|| {
                        RbatError::InvalidBinaryLayout(format!(
                            "PE executable section range {start}..{end} is outside file bounds"
                        ))
                    })?;
                    binary_data.insert(
                        "text_bytes".to_string(),
                        MapValue::Bytes(text_bytes.to_vec()),
                    );
                }

                if !binary_data.contains_key("text_bytes") {
                    return Err(RbatError::MissingExecutableSection);
                }
                Ok(binary_data)
            }
            Object::Mach(mach) => {
                let mut binary_data: HashMap<String, MapValue> = HashMap::new();
                binary_data.insert("os".to_string(), MapValue::OS(DisasmType::Mac));

                match mach {
                    goblin::mach::Mach::Binary(macho) => {
                        binary_data.insert("entry_addr".to_string(), MapValue::Word(macho.entry));

                        for segment in &macho.segments {
                            for (section, section_data) in segment.into_iter().flatten() {
                                let section_name = section.name().unwrap_or("");
                                let segment_name = section.segname().unwrap_or("");
                                if segment_name == "__TEXT" && section_name == "__text" {
                                    binary_data.insert(
                                        "text_bytes".to_string(),
                                        MapValue::Bytes(section_data.to_vec()),
                                    );
                                    break;
                                }
                            }
                            if binary_data.contains_key("text_bytes") {
                                break;
                            }
                        }
                    }
                    goblin::mach::Mach::Fat(fat) => {
                        for arch in fat {
                            if let Ok(goblin::mach::SingleArch::MachO(macho)) = arch {
                                binary_data
                                    .insert("entry_addr".to_string(), MapValue::Word(macho.entry));

                                for segment in &macho.segments {
                                    for (section, section_data) in segment.into_iter().flatten() {
                                        let section_name = section.name().unwrap_or("");
                                        let segment_name = section.segname().unwrap_or("");
                                        if segment_name == "__TEXT" && section_name == "__text" {
                                            binary_data.insert(
                                                "text_bytes".to_string(),
                                                MapValue::Bytes(section_data.to_vec()),
                                            );
                                            break;
                                        }
                                    }
                                    if binary_data.contains_key("text_bytes") {
                                        break;
                                    }
                                }
                                break;
                            }
                        }
                    }
                }

                if !binary_data.contains_key("entry_addr")
                    || !binary_data.contains_key("text_bytes")
                {
                    return Err(RbatError::MissingExecutableSection);
                }
                Ok(binary_data)
            }
            Object::Archive(_) => Err(RbatError::UnsupportedBinaryFormat(
                "Archive files are not supported for disassembly".to_string(),
            )),
            Object::Unknown(magic) => Err(RbatError::UnsupportedBinaryFormat(format!(
                "Unknown file format magic: {magic:#x}"
            ))),
            _ => Err(RbatError::UnsupportedBinaryFormat(
                "Unsupported file type for disassembly".to_string(),
            )),
        }
    }

    pub fn check_process_injec(&self) -> Result<HashSet<String>> {
        let blacklist = get_txt_from_file("blacklisted_process_injec.txt")?;
        let mut sus_func: HashSet<String> = HashSet::new();

        match &self.binary_object {
            Object::Elf(elf) => {
                // For ELF, check dynamic symbols that are imported (st_shndx == 0)
                for dy in &elf.dynsyms {
                    if dy.st_shndx == 0
                        && let Some(name) = elf.dynstrtab.get_at(dy.st_name)
                        && blacklist.contains(&name.to_string())
                    {
                        sus_func.insert(name.to_owned());
                    }
                }
                Ok(sus_func)
            }
            Object::PE(pe) => {
                for import in &pe.imports {
                    let import_name = import.name.to_string();
                    if blacklist
                        .iter()
                        .any(|item| item.eq_ignore_ascii_case(&import_name))
                    {
                        sus_func.insert(import_name);
                    }
                }
                Ok(sus_func)
            }
            Object::Mach(mach) => {
                let matches_blacklist = |name: &str| {
                    let normalized = name.trim_start_matches('_');
                    blacklist
                        .iter()
                        .any(|item| item.eq_ignore_ascii_case(normalized))
                };

                let mut collect_from_macho = |macho: &goblin::mach::MachO<'_>| -> Result<()> {
                    if let Ok(imports) = macho.imports() {
                        for import in imports {
                            if matches_blacklist(import.name) {
                                sus_func.insert(import.name.to_string());
                            }
                        }
                    }

                    for (name, nlist) in macho.symbols().flatten() {
                        if nlist.is_undefined() && matches_blacklist(name) {
                            sus_func.insert(name.to_string());
                        }
                    }
                    Ok(())
                };

                match mach {
                    goblin::mach::Mach::Binary(macho) => collect_from_macho(macho)?,
                    goblin::mach::Mach::Fat(fat) => {
                        for arch in fat {
                            if let Ok(goblin::mach::SingleArch::MachO(macho)) = arch {
                                collect_from_macho(&macho)?;
                            }
                        }
                    }
                }
                Ok(sus_func)
            }
            _ => Err(RbatError::UnsupportedBinaryFormat(
                "Process injection checks currently support ELF, PE, and Mach-O binaries only"
                    .to_string(),
            )),
        }
    }

    pub fn detect_api_hooking(&self) -> Result<HashMap<String, u64>> {
        use crate::rbat::yarahandler::YaraHandler;
        let mut api_hooking_func: HashMap<String, u64> = HashMap::new();
        let blacklist = get_txt_from_file("api_hooking_apis.txt")?;

        match &self.binary_object {
            Object::Elf(elf) => {
                for dy in &elf.dynsyms {
                    if dy.st_shndx > 0
                        && let Some(name) = elf.dynstrtab.get_at(dy.st_name)
                        && blacklist.iter().any(|b| name.contains(b))
                    {
                        // Only flag if it's a known hooking-related name or suspicious export
                        api_hooking_func.insert(name.to_owned(), dy.st_value);
                    }
                }
            }
            Object::PE(pe) => {
                for import in &pe.imports {
                    let function = import.name.to_string();
                    if blacklist.iter().any(|b| function.contains(b)) {
                        api_hooking_func
                            .insert(format!("{}!{}", import.dll, function), import.rva as u64);
                    }
                }
            }
            Object::Mach(mach) => {
                let mut collect_from_macho = |macho: &goblin::mach::MachO<'_>| -> Result<()> {
                    for (name, symbol) in macho.symbols().flatten() {
                        if symbol.is_global()
                            && !symbol.is_undefined()
                            && blacklist.iter().any(|b| name.contains(b))
                        {
                            api_hooking_func.insert(name.to_string(), symbol.n_value);
                        }
                    }
                    Ok(())
                };

                match mach {
                    goblin::mach::Mach::Binary(macho) => collect_from_macho(macho)?,
                    goblin::mach::Mach::Fat(fat) => {
                        for arch in fat {
                            if let Ok(goblin::mach::SingleArch::MachO(macho)) = arch {
                                collect_from_macho(&macho)?;
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        // Supplement with YARA scan for patterns and strings
        let yara = YaraHandler::new("api_hooking.yar".to_owned());
        if let Ok(rules) = yara.compile_yara_rule()
            && let Ok(matches) = yara.scan_file(rules, self.bin_path)
        {
            for (rule_name, instances) in matches {
                for m in instances {
                    let key = format!("{}:{}", rule_name, m.data);
                    api_hooking_func.entry(key).or_insert(m.offset as u64);
                }
            }
        }

        Ok(api_hooking_func)
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
        let binary_object = Object::parse(&buffer).unwrap();
        let parser = Parser::new(&path, buffer.to_owned(), binary_object);
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
        let binary_object = Object::parse(&buffer).unwrap();
        let parser = Parser::new(&path, buffer.to_owned(), binary_object);
        let result = parser.parse_buffer();
        match result {
            Ok(data) => {
                assert!(data.contains_key("os"));
                assert!(data.contains_key("text_bytes"));
            }
            Err(e) => panic!("parse_buffer failed with: {:?}", e),
        }
    }

    #[test]
    fn test_evaluate_section_entropy_macho() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("dummy_macho");
        test_helpers::generate_macho(&path);

        let buffer = fs::read(&path).unwrap();
        let binary_object = Object::parse(&buffer).unwrap();
        let parser = Parser::new(&path, buffer.to_owned(), binary_object);
        let result = parser.evaluate_section_entropy();
        assert!(result.is_ok());
        let entropy = result.unwrap();
        assert!(entropy.contains_key("__text"));
    }
}
