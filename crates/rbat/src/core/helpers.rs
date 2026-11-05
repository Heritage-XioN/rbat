//! # Binary Analysis Helper Utilities
//!
//! Provides fundamental mathematical, statistical, and cryptographic utility functions used
//! across the static binary analysis pipeline, including Shannon entropy estimation and
//! comprehensive triage hash calculation.
//!
//! ## Core Functions
//!
//! - [`calculate_entropy`]: Computes the Shannon entropy of raw byte slices in the range $[0.0, 8.0]$.
//! - [`compute_hashes`]: Concurrently generates cryptographic (MD5, SHA-1, SHA-256) and similarity
//!   (SSDEEP, TLSH) hashes over binary buffers.
//!
//! ## Overview
//!
//! Static binary triage relies heavily on structural randomness and content hashing:
//! - **Shannon Entropy**: Measures the information density and randomness of binary sections. Executable
//!   machine code typically exhibits entropy between $4.5$ and $6.5$. Entropy values approaching $8.0$
//!   strongly indicate compression, packing (e.g. UPX, Themida), or encrypted payloads.
//! - **Cryptographic & Similarity Hashes**: Autoritative cryptographic hashing (SHA-256) provides unique
//!   file identification, while fuzzy and locality-sensitive matching (SSDEEP, TLSH) identifies near-duplicate
//!   and polymorphic malware variants. Streaming passes process data in 64 KiB chunks to preserve
//!   L1/L2 cache locality.
//!
//! ## Examples
//!
//! ```rust
//! use rbat::core::helpers::{calculate_entropy, compute_hashes};
//!
//! let sample = [0x90, 0x90, 0xcc, 0xc3]; // nop, nop, int3, ret
//! let entropy = calculate_entropy(&sample);
//! assert!(entropy > 0.0);
//!
//! let hashes = compute_hashes(b"malware payload sample");
//! assert!(!hashes.sha256.is_empty());
//! ```

use crate::core::types::analysis::BinaryHashes;
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};

/// Chunk size in bytes for streaming digest passes (64 KiB keeps instruction-cache and L1/L2 pressure low).
const DIGEST_CHUNK_SIZE: usize = 64 * 1024;

/// Calculates the Shannon entropy of a byte slice to assess data randomness.
///
/// Shannon entropy measures the average amount of information or unpredictability contained
/// in each byte of the provided slice:
///
/// $$H(X) = -\sum_{i=0}^{255} P(x_i) \log_2 P(x_i)$$
///
/// where $P(x_i)$ is the empirical probability of occurrence of byte value $x_i$ divided by
/// the total byte length.
///
/// # Security Applications
///
/// In binary analysis, section entropy serves as an indicator of code transformation:
/// - **Zero-Padded / Uniform Blocks**: Values near $0.0$ to $2.0$ (e.g. `.bss` or uninitialized buffers).
/// - **Native Compiled Code**: Values typically between $4.5$ and $6.5$.
/// - **Compressed / Encrypted / Packed Payloads**: Values approaching $8.0$ (typically $> 7.2$),
///   strongly suggesting packed executables (UPX, ASPack), encrypted shellcode, or obfuscated resources.
///
/// # Parameters
///
/// - `data`: Raw byte slice to evaluate.
///
/// # Returns
///
/// The calculated Shannon entropy as an `f64` in the range `[0.0, 8.0]`. If `data` is empty,
/// returns `0.0`.
///
/// # Examples
///
/// ```rust
/// use rbat::core::helpers::calculate_entropy;
///
/// // Uniform single-byte sequences have zero entropy
/// assert_eq!(calculate_entropy(&[0u8; 64]), 0.0);
///
/// // Perfectly distributed 256 unique byte values have maximum entropy (8.0)
/// let all_bytes: Vec<u8> = (0..=255).collect();
/// assert_eq!(calculate_entropy(&all_bytes), 8.0);
/// ```
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    // array to count the occurrences of each of the 256 possible byte values.
    let mut byte_counts = [0usize; 256];
    // Tally up the bytes.
    for &byte in data {
        byte_counts[byte as usize] += 1;
    }
    let mut entropy: f64 = 0.0;
    let total_bytes = data.len() as f64;

    // Apply the Shannon Entropy formula
    for &count in &byte_counts {
        if count > 0 {
            // Calculate the probability of this byte occurring
            let probability = count as f64 / total_bytes;

            // Add to the total entropy: P(x) * log2(P(x))
            entropy -= probability * probability.log2();
        }
    }
    entropy
}

/// Computes all triage cryptographic and similarity hashes for a binary buffer.
///
/// Updates streaming cryptographic hash accumulators (MD5, SHA-1, SHA-256) simultaneously in
/// 64 KiB chunks to preserve L1/L2 cache locality and minimize memory bus overhead. Additionally
/// evaluates context-triggered piecewise hashing (SSDEEP via `fuzzyhash`) and locality-sensitive
/// trend hashing (TLSH via `tlsh`).
///
/// # Parameters
///
/// - `buffer`: Raw binary byte slice to be hashed.
///
/// # Returns
///
/// A fully populated [`BinaryHashes`] structure containing lowercase hex-encoded strings for
/// cryptographic hashes, alongside SSDEEP and TLSH strings (or empty strings if inputs are
/// too small for fuzzy hashing algorithms).
///
/// # Examples
///
/// ```rust
/// use rbat::core::helpers::compute_hashes;
///
/// let hashes = compute_hashes(b"abc");
/// assert_eq!(hashes.md5, "900150983cd24fb0d6963f7d28e17f72");
/// assert_eq!(hashes.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
/// assert_eq!(
///     hashes.sha256,
///     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
/// );
/// ```
pub fn compute_hashes(buffer: &[u8]) -> BinaryHashes {
    let mut md5_hasher = Md5::new();
    let mut sha1_hasher = Sha1::new();
    let mut sha256_hasher = Sha256::new();

    for chunk in buffer.chunks(DIGEST_CHUNK_SIZE) {
        Digest::update(&mut md5_hasher, chunk);
        Digest::update(&mut sha1_hasher, chunk);
        Digest::update(&mut sha256_hasher, chunk);
    }

    BinaryHashes {
        md5: to_hex(&md5_hasher.finalize()),
        sha1: to_hex(&sha1_hasher.finalize()),
        sha256: to_hex(&sha256_hasher.finalize()),
        ssdeep: compute_ssdeep(buffer),
        tlsh: compute_tlsh(buffer),
    }
}

/// Encodes a raw byte slice into a lowercase hexadecimal string.
///
/// Pre-allocates a string buffer with twice the capacity of `bytes` to prevent
/// dynamic reallocations during formatting.
///
/// # Parameters
///
/// - `bytes`: Raw digest or binary byte slice.
///
/// # Returns
///
/// A lowercase hexadecimal representation of `bytes`.
fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Computes an SSDEEP context-triggered piecewise hash (fuzzy hash).
///
/// Divides the input into variable-sized chunks based on rolling checksum boundaries
/// and computes traditional hashes over each chunk. Used to identify similar or modified
/// binary variants.
///
/// # Parameters
///
/// - `buffer`: Raw binary byte slice.
///
/// # Returns
///
/// The SSDEEP fuzzy hash string, or an empty string if the input is below the algorithmic
/// block-size minimum.
fn compute_ssdeep(buffer: &[u8]) -> String {
    fuzzyhash::FuzzyHash::new(buffer).to_string()
}

/// Computes a Trend Micro Locality Sensitive Hash (TLSH).
///
/// Generates a distance-comparable hash based on quantile byte frequencies and tri-gram
/// frequencies. Unlike cryptographic hashes, similar inputs produce similar TLSH outputs.
///
/// # Parameters
///
/// - `buffer`: Raw binary byte slice.
///
/// # Returns
///
/// The TLSH hash string (prefixed with `'T'`), or an empty string if the buffer is too small
/// (typically $< 50$ bytes) or lacks sufficient entropy for the algorithm.
fn compute_tlsh(buffer: &[u8]) -> String {
    tlsh::hash_buf(buffer)
        .map(|hash| hash.to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_entropy() {
        let data = vec![0u8; 100];
        assert_eq!(calculate_entropy(&data), 0.0);
    }

    #[test]
    fn test_high_entropy() {
        let mut data = Vec::with_capacity(256);
        for i in 0..256 {
            data.push(i as u8);
        }
        // Maximum entropy for 256 unique bytes is 8.0
        assert_eq!(calculate_entropy(&data), 8.0);
    }

    #[test]
    fn test_empty_data() {
        let data = vec![];
        assert_eq!(calculate_entropy(&data), 0.0);
    }

    #[test]
    fn test_partial_entropy() {
        let data = vec![0u8, 1u8];
        // p(0) = 0.5, p(1) = 0.5
        // entropy = -(0.5 * log2(0.5) + 0.5 * log2(0.5))
        // entropy = -(0.5 * -1 + 0.5 * -1) = 1.0
        assert_eq!(calculate_entropy(&data), 1.0);
    }

    #[test]
    fn test_known_vectors_abc() {
        let hashes = compute_hashes(b"abc");
        assert_eq!(hashes.md5, "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(hashes.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            hashes.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_known_vectors_empty() {
        let hashes = compute_hashes(b"");
        assert_eq!(hashes.md5, "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hashes.sha1, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            hashes.sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_large_buffer_chunked_consistency() {
        // Two chunks of identical data must hash identically to one big buffer,
        // proving the chunked update loop doesn't alter results.
        let single = compute_hashes(&vec![0xAB_u8; DIGEST_CHUNK_SIZE * 2]);
        assert_eq!(
            single.sha256,
            "aa2c1a737a0a0dd85a31ab41d5d0522b59d538d8f229975128b4c1cab0cbc281"
        );
        assert_eq!(single.md5, "4b48829714d20a4e73a0cf1565270076");
        assert_eq!(single.sha1, "a2260413720a1b8b28a629a609adcbcd1e6c5dfa");
    }

    #[test]
    fn test_fuzzy_hashes_present_on_realistic_input() {
        // TLSH requires >= ~50 bytes with some entropy; ssdeep needs enough
        // data for its smallest window.
        let buffer: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let hashes = compute_hashes(&buffer);

        assert!(!hashes.ssdeep.is_empty(), "ssdeep should hash 4KiB input");
        assert!(
            hashes.tlsh.starts_with('T'),
            "tlsh should produce T-prefixed digest"
        );
    }

    #[test]
    fn test_fuzzy_hashes_empty_on_tiny_input() {
        let hashes = compute_hashes(b"tiny");
        // Below algorithmic minimums these degrade gracefully instead of failing.
        assert_eq!(hashes.tlsh, "");
    }

    #[test]
    fn test_hex_encoding_is_lowercase() {
        assert_eq!(to_hex(&[0xDE, 0xAD, 0xBE, 0xEF]), "deadbeef");
        assert_eq!(to_hex(&[]), "");
    }
}
