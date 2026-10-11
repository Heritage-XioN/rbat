#![no_main]

use libfuzzer_sys::fuzz_target;
use rbat::core::analyzer::Analyzer;

fuzz_target!(|data: &[u8]| {
    let a = Analyzer::builder().build();
    let _ = a.streaming(data, |_| {});
});
