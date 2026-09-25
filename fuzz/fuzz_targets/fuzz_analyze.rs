#![no_main]

use libfuzzer_sys::fuzz_target;
use rbat::core::analyzer::analyze_streaming;
use rbat::core::types::NeedleIndex;
use rbat::core::Rule;
use std::sync::{Arc, LazyLock};

static NEEDLE: LazyLock<Arc<NeedleIndex>> = LazyLock::new(|| {
    let rules = Rule::load_embedded();
    Arc::new(NeedleIndex::build_from_rules(&rules))
});

fuzz_target!(|data: &[u8]| {
    let needle = Arc::clone(&NEEDLE);
    let _ = analyze_streaming(data, &None, needle, |_| {});
});
