use crate::rbat::*;
use goblin::Object;

/// A simple helper function to find the section name based on a YARA offset
pub fn get_section_for_offset(offset: usize, buffer: &[u8]) -> Result<String> {
    match Object::parse(buffer)? {
        Object::Elf(elf) => {
            let mut res: String = "".to_string();
            for section in &elf.section_headers {
                let start = section.sh_offset as usize;
                let end = start + section.sh_size as usize;

                // Check if the YARA offset falls within this section's boundaries
                if offset >= start && offset < end {
                    res = elf
                        .shdr_strtab
                        .get_at(section.sh_name)
                        .unwrap_or("<unnamed>")
                        .to_string();
                }
            }
            Ok(res)
        }
        Object::PE(pe) => {
            let mut res: String = "".to_string();
            for section in &pe.sections {
                let start = section.pointer_to_raw_data as usize;
                let end = start + section.size_of_raw_data as usize;

                if offset >= start && offset < end {
                    let name = String::from_utf8_lossy(&section.name);
                    res = name.trim_matches(char::from(0)).to_string();
                }
            }
            Ok(res)
        }
        Object::Mach(mach) => {
            let mut res: String = "".to_string();
            match mach {
                goblin::mach::Mach::Binary(macho) => {
                    for segment in &macho.segments {
                        for (section, _) in segment.into_iter().flatten() {
                            let start = section.offset as usize;
                            let end = start.saturating_add(section.size as usize);
                            if offset >= start && offset < end {
                                res = section.name().unwrap_or("<unnamed>").to_string();
                            }
                        }
                    }
                }
                goblin::mach::Mach::Fat(fat) => {
                    let arches = fat.arches()?;
                    for (index, arch) in arches.iter().enumerate() {
                        let base = arch.offset as usize;
                        if let Ok(goblin::mach::SingleArch::MachO(macho)) = fat.get(index) {
                            for segment in &macho.segments {
                                for (section, _) in segment.into_iter().flatten() {
                                    let start = base.saturating_add(section.offset as usize);
                                    let end = start.saturating_add(section.size as usize);
                                    if offset >= start && offset < end {
                                        res = section.name().unwrap_or("<unnamed>").to_string();
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Ok(res)
        }
        _ => Ok("Unknown Format".to_string()),
    }

    // If the offset doesn't fall into any defined section, it might be in the header or an overlay
    //Ok("Outside Sections".to_string())
}
