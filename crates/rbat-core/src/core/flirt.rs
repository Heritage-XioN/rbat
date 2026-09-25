//! Fast Library Identification and Recognition Technology module.

use fast_flirt::{FlirtSet, FlirtSetBuilder};
use rayon::prelude::*;
use rust_embed::RustEmbed;
use rustc_hash::{FxHashMap, FxHashSet};
use std::path::Path;
use std::sync::OnceLock;

use crate::utils::flirt::normalize_symbol;

#[derive(RustEmbed)]
#[folder = "assets/signatures_embedded/"]
struct EmbeddedSignatures;

/// Process-wide cache of the bundled signature database, parsed on first use.
static EMBEDDED_FLIRT: OnceLock<FlirtMatcher> = OnceLock::new();

/// FLIRT signature matcher for identifying statically-linked library functions.
///
/// Follows the same load pattern as `Rule`: call `load_embedded()` to get the
/// bundled signatures, then optionally `extend` with `load_from_directory()`.
#[derive(Debug, Clone, Default)]
pub struct FlirtMatcher {
    sets: Vec<FlirtSet>,
}

impl FlirtMatcher {
    /// Returns a process-wide shared reference to the bundled signature database.
    ///
    /// Parses and caches [`FlirtMatcher::load_embedded`] on first use so repeated
    /// analysis from upstream consumers (e.g. rbat-server handling many uploads) don't re-parse the
    /// signatures every call. Use [`FlirtMatcher::load_embedded`] directly when an
    /// owned matcher is needed for [`FlirtMatcher::extend`].
    pub fn embedded_shared() -> &'static Self {
        EMBEDDED_FLIRT.get_or_init(Self::load_embedded)
    }

    /// Loads the bundled FLIRT signatures compiled into the binary at build time.
    pub fn load_embedded() -> Self {
        let mut builder = FlirtSetBuilder::new();

        for file in EmbeddedSignatures::iter() {
            if let Some(embedded_file) = EmbeddedSignatures::get(&file) {
                let name = file.to_lowercase();
                if name.ends_with(".sig") {
                    let _ = builder.add_sig(&embedded_file.data);
                } else if name.ends_with(".pat.gz") {
                    let _ = builder.add_pat_gz(&embedded_file.data);
                } else if name.ends_with(".pat")
                    && let Ok(text) = std::str::from_utf8(&embedded_file.data)
                {
                    let _ = builder.add_pat(text);
                }
            }
        }

        match builder.build() {
            Ok(set) if !set.is_empty() => Self { sets: vec![set] },
            _ => Self { sets: Vec::new() },
        }
    }

    /// Loads FLIRT signatures (`.sig` and `.pat` files) from the given directory.
    pub fn load_from_directory(dir: &Path) -> Self {
        if !dir.is_dir() {
            return Self { sets: Vec::new() };
        }

        // handles recursive walking and both formats
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| FlirtSet::load_dir(dir)));

        match result {
            Ok(Ok(set)) if !set.is_empty() => Self { sets: vec![set] },
            _ => Self { sets: Vec::new() },
        }
    }

    /// Total number of signatures loaded across all signature sets.
    pub fn len(&self) -> usize {
        self.sets.iter().map(|s| s.len()).sum()
    }

    /// Checks if any signatures are loaded.
    pub fn is_empty(&self) -> bool {
        self.sets.iter().all(|s| s.is_empty())
    }

    /// Merges another matcher's patterns into this one.
    pub fn extend(&mut self, other: Self) {
        for set in other.sets {
            if !set.is_empty() {
                self.sets.push(set);
            }
        }
    }

    /// Queries the FLIRT trie with candidate function bytes.
    /// Returns a normalized, demangled name if a signature matches.
    pub fn match_bytes(&self, function_bytes: &[u8]) -> Option<String> {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            for set in &self.sets {
                if let Some(name) = set.match_public_name(function_bytes) {
                    return Some(normalize_symbol(name));
                }
            }
            None
        }));
        result.unwrap_or(None)
    }

    /// Scans a set of function entry points against the `.text` section bytes
    /// and returns a map of matched library function addresses to their names.
    pub fn identify_library_functions(
        &self,
        entry_points: &FxHashSet<u64>,
        text_bytes: &[u8],
        text_base: u64,
    ) -> FxHashMap<u64, String> {
        entry_points
            .par_iter()
            .filter_map(|&addr| {
                if addr >= text_base {
                    let offset = (addr - text_base) as usize;
                    if offset < text_bytes.len() {
                        let max_len = 1024.min(text_bytes.len() - offset);
                        let func_bytes = &text_bytes[offset..offset + max_len];
                        return self.match_bytes(func_bytes).map(|name| (addr, name));
                    }
                }
                None
            })
            .collect()
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

    #[test]
    fn test_flirt_malformed_signature_resilience() {
        // 126-byte malformed .sig payload discovered by cargo-fuzz (fuzz_flirt)
        // triggers subtraction overflow in fast-flirt v0.2.2.
        let malformed_sig: &[u8] = &[
            0x49, 0x44, 0x41, 0x53, 0x47, 0x4e, 0x09, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x26, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x20,
            0x00, 0x6c, 0x69, 0x62, 0x62, 0x6f, 0x6f, 0x73, 0x74, 0x2d, 0x65, 0x78, 0x63, 0x65,
            0x70, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xba, 0x74,
            0x2d, 0x73, 0x2d, 0x78, 0x36, 0x34, 0x2d, 0x31, 0x2e, 0x37, 0x32, 0x01, 0x06, 0x41,
            0x53, 0x47, 0x4e, 0x09, 0x00, 0xc3, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x3f, 0x63,
            0x6c, 0x6f, 0x6e, 0x65, 0x5f, 0x1b, 0x00, 0x00, 0x00, 0x63, 0x75, 0x72, 0x72, 0x65,
            0x74, 0x5f, 0x65, 0x78, 0x63, 0x65, 0x70, 0x74, 0x69, 0x49, 0x44, 0x41, 0x53, 0x47,
            0x4e, 0x09, 0x00, 0x2d, 0x6f, 0x6e, 0x65,
        ];

        // 1. match_bytes with this input must not panic
        let matcher = FlirtMatcher::embedded_shared();
        assert!(matcher.match_bytes(malformed_sig).is_none());

        // 2. Loading a directory containing this malformed .sig file must not panic and must return an empty matcher
        let temp_dir = tempfile::tempdir().expect("failed to create tempdir");
        let sig_path = temp_dir.path().join("crash.sig");
        std::fs::write(&sig_path, malformed_sig).expect("failed to write crash.sig");

        let loaded = FlirtMatcher::load_from_directory(temp_dir.path());
        assert!(loaded.is_empty());
        assert_eq!(loaded.len(), 0);
    }
}
