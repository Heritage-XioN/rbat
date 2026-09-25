#![no_main]

use libfuzzer_sys::fuzz_target;
use rbat::core::types::NeedleIndex;
use rbat::core::{AnalysisResult, FeatureSet, Rule};

fuzz_target!(|data: &[u8]| {
    if let Ok(rule) = Rule::from_slice(data) {
        let _ = rule.has_match_dependency();
        let needle = NeedleIndex::build_from_rules(std::slice::from_ref(&rule));
        let res = AnalysisResult::default();
        let features = FeatureSet::from_analysis_result(&res);
        let rules = [rule];
        let _ = Rule::evaluate(&features, &rules, &needle);
    }
});
