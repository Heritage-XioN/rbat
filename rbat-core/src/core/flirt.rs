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
        match FlirtSet::load_dir(dir) {
            Ok(set) if !set.is_empty() => Self { sets: vec![set] },
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
        for set in &self.sets {
            if let Some(name) = set.match_public_name(function_bytes) {
                return Some(normalize_symbol(name));
            }
        }
        None
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
}
