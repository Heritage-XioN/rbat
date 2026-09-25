#![no_main]

use libfuzzer_sys::fuzz_target;
use rbat::core::FlirtMatcher;
use rustc_hash::FxHashSet;

fuzz_target!(|data: &[u8]| {
    // 1. Fuzz matching against embedded signatures database with arbitrary candidate function bytes
    let matcher = FlirtMatcher::embedded_shared();
    let _ = matcher.match_bytes(data);

    // 2. Fuzz identify_library_functions with candidate text section bytes and entry points
    if data.len() >= 8 {
        let mut entry_points = FxHashSet::default();
        let base = 0x1000;
        for chunk in data.chunks_exact(8) {
            let addr = u64::from_le_bytes(chunk.try_into().unwrap());
            entry_points.insert(addr);
            if entry_points.len() >= 16 {
                break;
            }
        }
        let _ = matcher.identify_library_functions(&entry_points, data, base);
    }
});
