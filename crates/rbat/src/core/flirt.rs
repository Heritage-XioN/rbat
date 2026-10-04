//! # FLIRT Library Function Identification
//!
//! Implements Fast Library Identification and Recognition Technology (FLIRT) signature
//! matching for identifying statically-linked library functions in stripped binaries using
//! the [`fast_flirt`] lib.
//!
//! ## Core Types
//!
//! - [`FlirtMatcher`]: Trie-based signature matcher for recognizing standard library function prefixes.
//!   it directly wraps [`fast_flirt::FlirtSet`].
//!
//! ## Overview
//!
//! Stripped binaries often contain hundreds of statically linked standard library functions
//! (e.g. from `libc`, `libstdc++`, or `MSVCRT`). Without debugging symbols, these functions
//! appear as arbitrary user code, which inflates false-positive detections in heuristic and
//! capability rule engines.
//!
//! FLIRT solves this by matching initial byte sequences against signature sets generated
//! from compiler runtime libraries:
//! 1. **Embedded Bundles**: Compressed `.sig` and `.pat` database files embedded into the
//!    binary at compile time via `RustEmbed`, parsed and cached process-wide in a [`OnceLock`].
//! 2. **Extensible Signatures**: External directories containing user-provided `.sig` or `.pat`
//!    files can be loaded and merged on top of embedded assets using [`FlirtMatcher::extend`].
//! 3. **Symbol Demangling & Normalization**: Strips compiler-specific prefixes (`__imp_`, `__imp___`,
//!    leading `_`) and automatically demangles MSVC (`?`) and GCC/Clang/Itanium (`_Z`) symbol names.
//!
//! ## Examples
//!
//! Checking byte slices against bundled library signatures:
//!
//! ```rust
//! use rbat::core::flirt::FlirtMatcher;
//!
//! let matcher = FlirtMatcher::load_embedded();
//! // NOP sled will not match any library signatures
//! assert!(matcher.match_bytes(&[0x90; 64]).is_none());
//! ```

use crate::core::{
    cfg::InstructionClass, disassembler::InstructionInfo, parser::BinaryArch,
    types::result::RbatResult,
};
use fast_flirt::{FlirtSet, FlirtSetBuilder};
use object::{Object, ObjectSymbol};
use rayon::prelude::*;
use rust_embed::RustEmbed;
use rustc_hash::{FxHashMap, FxHashSet};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
    sync::OnceLock,
};

/// Embedded flirt signatures
#[derive(RustEmbed)]
#[folder = "assets/signatures_embedded/"]
struct EmbedFlirtSig;

/// Process-wide cache of the bundled signature database, parsed on first use.
static EMBEDDED_FLIRT: OnceLock<FlirtMatcher> = OnceLock::new();

/// FLIRT signature matcher for identifying statically-linked library functions.
///
/// `FlirtMatcher` encapsulates compiled prefix tries ([`FlirtSet`]) that inspect
/// candidate function entry points and match them against known compiler runtime libraries.
///
/// Use [`FlirtMatcher::load_embedded`] to obtain an owned matcher with bundled signatures,
/// or [`FlirtMatcher::extend`] to augment it with external `.sig` / `.pat` files.
///
/// # Examples
///
/// ```rust
/// use rbat::core::flirt::FlirtMatcher;
///
/// let matcher = FlirtMatcher::load_embedded();
/// assert!(!matcher.is_empty());
/// ```
#[derive(Debug, Clone, Default)]
pub struct FlirtMatcher {
    sets: Vec<FlirtSet>,
}

impl FlirtMatcher {
    /// Returns a process-wide shared reference to the bundled signature database.
    ///
    /// Parses and caches [`FlirtMatcher::load_embedded`] on first use so repeated
    /// analyses avoid re-parsing embedded signature files.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rbat::core::flirt::FlirtMatcher;
    ///
    /// let shared_matcher = FlirtMatcher::embedded_shared();
    /// assert!(!shared_matcher.is_empty());
    /// ```
    pub fn embedded_shared() -> &'static Self {
        EMBEDDED_FLIRT.get_or_init(Self::load_embedded)
    }

    /// Loads the bundled FLIRT signatures compiled into the binary at build time.
    ///
    /// Extracts and parses all `.sig`, `.pat`, and `.pat.gz` files from embedded assets.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rbat::core::flirt::FlirtMatcher;
    ///
    /// let matcher = FlirtMatcher::load_embedded();
    /// assert!(matcher.len() > 0);
    /// ```
    pub fn load_embedded() -> Self {
        let mut builder = FlirtSetBuilder::new();

        for file in EmbedFlirtSig::iter() {
            if let Some(embedded_file) = EmbedFlirtSig::get(&file) {
                if file.to_lowercase().ends_with(".sig") {
                    let _ = builder.add_sig(&embedded_file.data);
                } else if file.to_lowercase().ends_with(".pat.gz") {
                    let _ = builder.add_pat_gz(&embedded_file.data);
                } else if file.to_lowercase().ends_with(".pat")
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

    /// Total number of signatures loaded across all signature sets.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rbat::core::flirt::FlirtMatcher;
    ///
    /// let matcher = FlirtMatcher::load_embedded();
    /// println!("Loaded {} signatures", matcher.len());
    /// ```
    pub fn len(&self) -> usize {
        self.sets.iter().map(|s| s.len()).sum()
    }

    /// Checks if any signatures are loaded.
    ///
    /// Returns `true` if no signature sets are loaded or all contained sets are empty.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rbat::core::flirt::FlirtMatcher;
    ///
    /// let matcher = FlirtMatcher::load_embedded();
    /// assert!(!matcher.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.sets.iter().all(|s| s.is_empty())
    }

    /// Loads external FLIRT signatures from a directory and merges them with embedded signatures.
    ///
    /// Recursively scans `path` for `.sig` and `.pat` files, parses them, and appends
    /// the resulting signature sets to the bundled embedded database.
    ///
    /// # Errors
    ///
    /// Returns an error if directory traversal fails or an invalid signature file is encountered.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rbat::core::flirt::FlirtMatcher;
    ///
    /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let matcher = FlirtMatcher::extend("path/to/custom_signatures")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn extend<P: AsRef<Path>>(path: P) -> RbatResult<Self> {
        let mut flirt = Self::load_embedded();
        if let Ok(r) = catch_unwind(AssertUnwindSafe(|| FlirtSet::load_dir(path.as_ref()))) {
            let flirt_set = r?;
            if !flirt_set.is_empty() {
                flirt.sets.push(flirt_set);
            }
        };
        Ok(flirt)
    }

    /// Queries the FLIRT trie with candidate function bytes.
    ///
    /// Returns a normalized, demangled symbol name if a signature matches the byte sequence.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rbat::core::flirt::FlirtMatcher;
    ///
    /// let matcher = FlirtMatcher::load_embedded();
    /// let result = matcher.match_bytes(&[0x90; 128]);
    /// assert!(result.is_none());
    /// ```
    pub fn match_bytes(&self, function_bytes: &[u8]) -> Option<String> {
        let result = catch_unwind(AssertUnwindSafe(|| {
            for set in &self.sets {
                if let Some(name) = set.match_public_name(function_bytes) {
                    return Some(Self::normalize_symbol(name));
                }
            }
            None
        }));
        result.unwrap_or(None)
    }

    /// Scans a set of function entry points against `.text` section bytes.
    ///
    /// Concurrently checks candidate entry points in parallel using [`Rayon`] and returns
    /// a map of virtual memory addresses to demangled library function names.
    ///
    /// [`Rayon`]: rayon
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

    /// Normalizes and demangles symbol names returned by the FLIRT engine.
    fn normalize_symbol(name: &str) -> String {
        let mut name = name.to_owned();

        // 1. Demangle MSVC C++ symbols (start with '?')
        if name.starts_with('?') {
            if let Ok(demangled) =
                msvc_demangler::demangle(&name, msvc_demangler::DemangleFlags::llvm())
            {
                name = demangled;
            }
        }
        // 2. Demangle GCC/Clang/Itanium C++ symbols (start with '_Z')
        else if name.starts_with("_Z")
            && let Ok(sym) = cpp_demangle::Symbol::new(&name)
        {
            name = sym.to_string();
        }

        // 3. Remove common compiler-specific prefixes
        if let Some(stripped) = name.strip_prefix("__imp___") {
            name = stripped.to_owned();
        } else if let Some(stripped) = name.strip_prefix("__imp_") {
            name = stripped.to_owned();
        }

        // Strip leading underscore commonly added by C compilers for x86 platform symbols
        if name.starts_with('_') && !name.starts_with("__") && name.len() > 1 {
            name = name[1..].to_owned();
        }

        name
    }

    /// Discovers potential function entry points from symbols, exports, and call destinations.
    pub(crate) fn collect_entry_points(
        binary_object: &object::File,
        instructions: &[InstructionInfo],
        arch: &BinaryArch,
        entry_addr: u64,
    ) -> FxHashSet<u64> {
        let mut entry_points = FxHashSet::default();
        entry_points.insert(entry_addr);

        // Collect from call instructions
        for insn in instructions {
            if insn.class(arch) == InstructionClass::Call
                && let Some(target) = insn.branch_target()
            {
                entry_points.insert(target);
            }
        }

        for sym in binary_object.symbols() {
            if sym.address() > 0 && sym.kind() == object::SymbolKind::Text {
                entry_points.insert(sym.address());
            }
        }
        for sym in binary_object.dynamic_symbols() {
            if sym.address() > 0 && sym.kind() == object::SymbolKind::Text {
                entry_points.insert(sym.address());
            }
        }
        if let Ok(exports) = binary_object.exports() {
            for export in exports {
                if export.address() > 0 {
                    entry_points.insert(export.address());
                }
            }
        }

        entry_points
    }

    /// Traces execution from a start address to find the semantic end address of a function.
    pub(crate) fn find_function_range(
        start_addr: u64,
        instructions: &[InstructionInfo],
        all_entry_points: &FxHashSet<u64>,
        arch: &BinaryArch,
    ) -> (u64, u64) {
        let start_idx = match instructions.binary_search_by_key(&start_addr, |insn| insn.address())
        {
            Ok(idx) => idx,
            Err(_) => {
                return (start_addr, start_addr);
            }
        };

        let mut end_addr = start_addr;
        for insn in instructions.iter().skip(start_idx) {
            if insn.address() != start_addr && all_entry_points.contains(&insn.address()) {
                break;
            }

            end_addr = insn.address();

            if insn.class(arch) == InstructionClass::Return {
                break;
            }
        }

        (start_addr, end_addr)
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

        // 2. Loading a directory containing this malformed .sig file must not panic
        // and must safely retain the embedded signature set without crashing.
        let temp_dir = tempfile::tempdir().expect("failed to create tempdir");
        let sig_path = temp_dir.path().join("crash.sig");
        std::fs::write(&sig_path, malformed_sig).expect("failed to write crash.sig");

        let embedded = FlirtMatcher::load_embedded();
        let loaded = FlirtMatcher::extend(temp_dir.path()).unwrap();
        assert_eq!(loaded.len(), embedded.len());
        assert!(!loaded.is_empty());
    }
}
