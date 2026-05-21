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
            if count >= min_length {
                if let Some(start) = start_idx {
                    for i in 0..count {
                        addresses.push(text_section_offset + (start + i) as u64);
                    }
                }
            }
            start_idx = None;
            count = 0;
        }
    }

    if count >= min_length {
        if let Some(start) = start_idx {
            for i in 0..count {
                addresses.push(text_section_offset + (start + i) as u64);
            }
        }
    }
    addresses
}
