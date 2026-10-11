#![no_main]

use libfuzzer_sys::fuzz_target;
use rbat::core::{features::FeatureSet, needle::NeedleIndex, rule::Rule, types::AnalysisResult};

fuzz_target!(|data: &[u8]| {
    if let Ok(rule) = Rule::from_slice(data) {
        let _ = rule.has_match_dependency();
        let needle = NeedleIndex::new(std::slice::from_ref(&rule));
        let res = AnalysisResult::default();
        let features = FeatureSet::new(&res, data);
        let rules = [rule];
        let _ = Rule::evaluate(&features, &rules, &needle);
    }
});
