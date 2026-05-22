//! # Section Boundary Offset Mapper
//!
//! This module builds a cached map of binary sections (using [`SectionRange`]) and provides
//! lookup to determine which binary section contains a specific raw file offset.
//! This improves YARA scan match localization performance.

use crate::core::{Result, SectionRange};
use goblin::Object;

/// Builds a cached mapping of file offset boundaries for all sections in a parsed binary object.
///
/// # Example
/// ```rust
/// use goblin::Object;
/// use rbat::utils::section_offset::build_section_map;
///
/// # fn run(buffer: &[u8]) {
/// let obj = Object::parse(buffer).unwrap();
/// let section_ranges = build_section_map(&obj, buffer).unwrap();
/// # }
/// ```
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

/// Finds the section name containing the given file offset.
/// Returns an empty string if no section bounds encompass the offset.
pub fn get_section_for_offset(ranges: &[SectionRange], offset: usize) -> String {
    for range in ranges {
        if offset >= range.start && offset < range.end {
            return range.name.clone();
        }
    }
    "".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_helpers::test_helpers;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_get_section_for_offset_match() {
        let ranges = vec![
            SectionRange {
                start: 0,
                end: 100,
                name: ".text".to_string(),
            },
            SectionRange {
                start: 100,
                end: 200,
                name: ".data".to_string(),
            },
        ];

        assert_eq!(get_section_for_offset(&ranges, 50), ".text");
        assert_eq!(get_section_for_offset(&ranges, 100), ".data");
        assert_eq!(get_section_for_offset(&ranges, 150), ".data");
        assert_eq!(get_section_for_offset(&ranges, 250), "");
    }

    #[test]
    fn test_build_section_map_elf() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("mock_elf");
        test_helpers::generate_elf(&path);

        let buffer = fs::read(&path).unwrap();
        let obj = Object::parse(&buffer).unwrap();

        let ranges = build_section_map(&obj, &buffer).unwrap();
        assert!(!ranges.is_empty());

        let has_text = ranges.iter().any(|r| r.name == ".text");
        assert!(has_text);
    }
}
