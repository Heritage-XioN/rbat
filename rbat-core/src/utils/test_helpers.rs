#[cfg(test)]
#[allow(clippy::module_inception)]
pub mod test_helpers {
    use object::write::{Object, Symbol, SymbolSection};
    use object::{
        Architecture, BinaryFormat, Endianness, SectionKind, SymbolFlags, SymbolKind, SymbolScope,
    };
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;

    pub fn generate_elf(path: &Path) {
        let mut obj = Object::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
        let section_id = obj.add_section(vec![], b".text".to_vec(), SectionKind::Text);
        obj.append_section_data(section_id, &[0x90; 100], 1);
        obj.add_symbol(Symbol {
            name: b"_start".to_vec(),
            value: 0,
            size: 0,
            kind: SymbolKind::Text,
            scope: SymbolScope::Dynamic,
            weak: false,
            section: SymbolSection::Section(section_id),
            flags: SymbolFlags::None,
        });
        let result = obj.write().unwrap();
        let mut file = File::create(path).unwrap();
        file.write_all(&result).unwrap();
    }

    pub fn generate_macho(path: &Path) {
        let mut obj = Object::new(
            BinaryFormat::MachO,
            Architecture::X86_64,
            Endianness::Little,
        );
        let section_id = obj.add_section(b"__TEXT".to_vec(), b"__text".to_vec(), SectionKind::Text);
        obj.append_section_data(section_id, &[0x90; 100], 1);
        let result = obj.write().unwrap();
        let mut file = File::create(path).unwrap();
        file.write_all(&result).unwrap();
    }

    pub fn generate_pe_stub(path: &Path) {
        let mut stub = vec![0u8; 0x200];
        stub[0..2].copy_from_slice(b"MZ");
        stub[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        stub[0x80..0x84].copy_from_slice(b"PE\0\0");
        stub[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        let mut file = File::create(path).unwrap();
        file.write_all(&stub).unwrap();
    }

    pub fn generate_elf_x86(path: &Path) {
        let mut obj = Object::new(BinaryFormat::Elf, Architecture::I386, Endianness::Little);
        let section_id = obj.add_section(vec![], b".text".to_vec(), SectionKind::Text);
        obj.append_section_data(section_id, &[0x90; 100], 1);
        let result = obj.write().unwrap();
        let mut file = File::create(path).unwrap();
        file.write_all(&result).unwrap();
    }

    pub fn generate_macho_arm64(path: &Path) {
        let mut obj = Object::new(
            BinaryFormat::MachO,
            Architecture::Aarch64,
            Endianness::Little,
        );
        let section_id = obj.add_section(b"__TEXT".to_vec(), b"__text".to_vec(), SectionKind::Text);
        obj.append_section_data(section_id, &[0x90; 100], 1);
        let result = obj.write().unwrap();
        let mut file = File::create(path).unwrap();
        file.write_all(&result).unwrap();
    }

    pub fn generate_pe_x86(path: &Path) {
        let mut stub = vec![0u8; 0x200];
        stub[0..2].copy_from_slice(b"MZ");
        stub[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        stub[0x80..0x84].copy_from_slice(b"PE\0\0");
        stub[0x84..0x86].copy_from_slice(&0x014Cu16.to_le_bytes()); // IMAGE_FILE_MACHINE_I386
        let mut file = File::create(path).unwrap();
        file.write_all(&stub).unwrap();
    }

    pub fn generate_elf_unsupported(path: &Path) {
        let mut obj = Object::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
        let section_id = obj.add_section(vec![], b".text".to_vec(), SectionKind::Text);
        obj.append_section_data(section_id, &[0x90; 100], 1);
        let mut result = obj.write().unwrap();
        // Overwrite e_machine with 0xFFFF (unsupported)
        // For ELF64, e_machine is at offset 18
        result[18..20].copy_from_slice(&0xFFFFu16.to_le_bytes());
        let mut file = File::create(path).unwrap();
        file.write_all(&result).unwrap();
    }
}
