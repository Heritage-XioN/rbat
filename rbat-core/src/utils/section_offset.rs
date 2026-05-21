use crate::core::{Result, SectionRange};
use goblin::Object;

pub fn build_section_map(binary_object: &Object, _buffer: &[u8]) -> Result<Vec<SectionRange>> {
    let mut ranges = Vec::new();
    match binary_object {
        Object::Elf(elf) => {
            for section in &elf.section_headers {
                let start = section.sh_offset as usize;
                let end = start + section.sh_size as usize;
                if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
                    ranges.push(SectionRange {
                        start,
                        end,
                        name: name.to_string(),
                    });
                }
            }
        }
        Object::PE(pe) => {
            for section in &pe.sections {
                let start = section.pointer_to_raw_data as usize;
                let end = start + section.size_of_raw_data as usize;
                let name = String::from_utf8_lossy(&section.name);
                let trimmed_name = name.trim_matches(char::from(0)).to_string();
                ranges.push(SectionRange {
                    start,
                    end,
                    name: trimmed_name,
                });
            }
        }
        Object::Mach(mach) => match mach {
            goblin::mach::Mach::Binary(macho) => {
                for segment in &macho.segments {
                    for (section, _) in segment.into_iter().flatten() {
                        let start = section.offset as usize;
                        let end = start.saturating_add(section.size as usize);
                        let name = section.name().unwrap_or("<unnamed>").to_string();
                        ranges.push(SectionRange { start, end, name });
                    }
                }
            }
            goblin::mach::Mach::Fat(fat) => {
                if let Ok(arches) = fat.arches() {
                    for (index, arch) in arches.iter().enumerate() {
                        let base = arch.offset as usize;
                        if let Ok(goblin::mach::SingleArch::MachO(macho)) = fat.get(index) {
                            for segment in &macho.segments {
                                for (section, _) in segment.into_iter().flatten() {
                                    let start = base.saturating_add(section.offset as usize);
                                    let end = start.saturating_add(section.size as usize);
                                    let name = section.name().unwrap_or("<unnamed>").to_string();
                                    ranges.push(SectionRange { start, end, name });
                                }
                            }
                        }
                    }
                }
            }
        },
        _ => {}
    }
    Ok(ranges)
}

/// Finds the section name based on a cached section range and offset.
pub fn get_section_for_offset(ranges: &[SectionRange], offset: usize) -> String {
    for range in ranges {
        if offset >= range.start && offset < range.end {
            return range.name.clone();
        }
    }
    "".to_string()
}
