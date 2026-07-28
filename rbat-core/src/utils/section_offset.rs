//! # Section Boundary Offset Mapper
//!
//! This module builds a cached map of binary sections (using [`SectionRange`]) and provides
//! lookup to determine which binary section contains a specific raw file offset.
//! This improves YARA scan match localization performance.

use crate::core::{Result, SectionRange};
use object::{Object, ObjectSection};

/// Builds a cached mapping of file offset boundaries for all sections in a parsed binary object.
///
/// # Example
/// ```rust
/// use object::File;
/// use rbat::utils::section_offset::build_section_map;
///
/// # fn run(buffer: &[u8]) {
/// let obj = File::parse(buffer).unwrap();
/// let section_ranges = build_section_map(&obj, buffer).unwrap();
/// # }
/// ```
pub fn build_section_map(
    binary_object: &object::File,
    _buffer: &[u8],
) -> Result<Vec<SectionRange>> {
    let mut ranges = Vec::new();
    for section in binary_object.sections() {
        if let Some((start, size)) = section.file_range() {
            let start = start as usize;
            let end = start.saturating_add(size as usize);
            let name = section.name().unwrap_or("<unnamed>").to_string();
            ranges.push(SectionRange { start, end, name });
        }
    }
    Ok(ranges)
}

/// Finds the section name containing the given file offset.
/// Returns `"<unknown>"` if no section bounds encompass the offset.
pub fn get_section_for_offset(ranges: &[SectionRange], offset: usize) -> String {
    for range in ranges {
        if offset >= range.start && offset < range.end {
            return range.name.clone();
        }
    }
    "<unknown>".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_helpers::test_helpers;
    use object::File;
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
        assert_eq!(get_section_for_offset(&ranges, 250), "<unknown>");
    }

    #[test]
    fn test_build_section_map_elf() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("mock_elf");
        test_helpers::generate_elf(&path);

        let buffer = fs::read(&path).unwrap();
        let obj = File::parse(buffer.as_slice()).unwrap();

        let ranges = build_section_map(&obj, &buffer).unwrap();
        assert!(!ranges.is_empty());

        let has_text = ranges.iter().any(|r| r.name == ".text");
        assert!(has_text);
    }
}
