//! # Raw Padding Scanner
//!
//! This module scans a slice of bytes to identify sequences of a single repeating byte value.
//! This is commonly used to find runs of NOPs (`0x90`), NULLs (`0x00`), or trap/INT3 (`0xCC`)
//! which can denote code caves or padding zones inside binary sections.

/// Scans a byte slice for consecutive runs of `target_byte` of length at least `min_length`.
/// Returns the absolute virtual memory addresses of all bytes within the matching runs.
pub fn scan_raw_padding(
    bytes: &[u8],
    target_byte: u8,
    min_length: usize,
    text_section_offset: u64,
) -> Vec<u64> {
    let mut addresses = Vec::new();
    let mut start_idx = None;
    let mut count = 0;

    for (idx, &b) in bytes.iter().enumerate() {
        if b == target_byte {
            if start_idx.is_none() {
                start_idx = Some(idx);
            }
            count += 1;
        } else {
            if count >= min_length
                && let Some(start) = start_idx
            {
                for i in 0..count {
                    addresses.push(text_section_offset + (start + i) as u64);
                }
            }
            start_idx = None;
            count = 0;
        }
    }

    if count >= min_length
        && let Some(start) = start_idx
    {
        for i in 0..count {
            addresses.push(text_section_offset + (start + i) as u64);
        }
    }
    addresses
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_raw_padding_nulls() {
        let mut bytes = vec![0x90; 100];
        for idx in 40..70 {
            bytes[idx] = 0x00;
        }

        let results = scan_raw_padding(&bytes, 0x00, 30, 0x1000);
        assert_eq!(results.len(), 30);
        assert_eq!(results[0], 0x1000 + 40);
        assert_eq!(results[29], 0x1000 + 69);
    }

    #[test]
    fn test_scan_raw_padding_int3() {
        let mut bytes = vec![0x90; 100];
        for idx in 20..55 {
            bytes[idx] = 0xCC;
        }

        let results = scan_raw_padding(&bytes, 0xCC, 30, 0x1000);
        assert_eq!(results.len(), 35);
        assert_eq!(results[0], 0x1000 + 20);
        assert_eq!(results[34], 0x1000 + 54);
    }
}
