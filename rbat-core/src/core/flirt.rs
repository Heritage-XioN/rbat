//! Fast Library Identification and Recognition Technology module.

use fast_flirt::{FlirtSet, Pattern, sig};
use rust_embed::RustEmbed;
use std::collections::HashMap;
use std::path::Path;

use crate::utils::flirt::normalize_symbol;

#[derive(RustEmbed)]
#[folder = "assets/signatures_embedded/"]
struct EmbeddedSignatures;

/// FLIRT signature matcher for identifying statically-linked library functions.
///
/// Follows the same load pattern as `Rule`: call `load_embedded()` to get the
/// bundled signatures, then optionally `extend` with `load_from_directory()`.
pub struct FlirtMatcher {
    set: FlirtSet,
}

impl FlirtMatcher {
    /// Loads the bundled FLIRT signatures compiled into the binary at build time.
    pub fn load_embedded() -> Self {
        let mut patterns: Vec<Pattern> = Vec::new();

        for file in EmbeddedSignatures::iter() {
            if let Some(embedded_file) = EmbeddedSignatures::get(&file)
                && let Ok(mut p) = sig::parse(&embedded_file.data)
            {
                patterns.append(&mut p);
            }
        }

        Self {
            set: FlirtSet::with_patterns(patterns),
        }
    }

    /// Loads FLIRT signatures (`.sig` and `.pat` files) from the given directory.
    pub fn load_from_directory(dir: &Path) -> Self {
        if !dir.is_dir() {
            return Self {
                set: FlirtSet::with_patterns(Vec::new()),
            };
        }

        // Use FlirtSet::load_dir which handles recursive walking and both formats
        match FlirtSet::load_dir(dir) {
            Ok(set) => Self { set },
            Err(_) => Self {
                set: FlirtSet::with_patterns(Vec::new()),
            },
        }
    }

    /// Merges another matcher's patterns into this one.
    pub fn extend(&mut self, other: Self) {
        let mut patterns =
            Vec::with_capacity(self.set.patterns().len() + other.set.patterns().len());
        patterns.extend_from_slice(self.set.patterns());
        patterns.extend_from_slice(other.set.patterns());
        self.set = FlirtSet::with_patterns(patterns);
    }

    /// Queries the FLIRT trie with candidate function bytes.
    /// Returns a normalized, demangled name if a signature matches.
    pub fn match_bytes(&self, function_bytes: &[u8]) -> Option<String> {
        self.set
            .matches(function_bytes)
            .first()
            .and_then(|pattern| pattern.public_name())
            .map(normalize_symbol)
    }

    /// Scans a set of function entry points against the `.text` section bytes
    /// and returns a map of matched library function addresses to their names.
    pub fn identify_library_functions(
        &self,
        entry_points: &std::collections::HashSet<u64>,
        text_bytes: &[u8],
        text_base: u64,
    ) -> HashMap<u64, String> {
        let mut library_functions = HashMap::new();

        for &addr in entry_points {
            if addr >= text_base {
                let offset = (addr - text_base) as usize;
                if offset < text_bytes.len() {
                    let max_len = 1024.min(text_bytes.len() - offset);
                    let func_bytes = &text_bytes[offset..offset + max_len];
                    if let Some(matched_name) = self.match_bytes(func_bytes) {
                        library_functions.insert(addr, matched_name);
                    }
                }
            }
        }

        library_functions
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_flirt_matcher_load_embedded() {
        let matcher = FlirtMatcher::load_embedded();
        // NOP sled should not match any library signature
        assert!(matcher.match_bytes(&[0x90; 300]).is_none());
    }

    #[test]
    fn test_flirt_matcher_extend() {
        let mut base = FlirtMatcher::load_embedded();
        let extra = FlirtMatcher::load_embedded();
        base.extend(extra);
        // Merging should not break matching
        assert!(base.match_bytes(&[0x90; 300]).is_none());
    }
}
