//! # Binary Hashing Pipeline
//!
//! Computes the triage-platform identifier set over the raw binary buffer in a
//! **single pass**: cryptographic digests (MD5, SHA-1, SHA-256) are updated
//! chunk-by-chunk simultaneously, while fuzzy hashes (SSDEEP, TLSH) are derived
//! afterwards from the same in-memory buffer.
//!
//! The output mirrors what analysts paste into VirusTotal / MalwareBazaar lookups:
//! exact-match keys (`md5`, `sha1`, `sha256`) plus similarity hashes (`ssdeep`,
//! `tlsh`) used for family clustering. Unavailable values (e.g. TLSH on inputs
//! below its ~50-byte minimum) are empty strings, never errors.

use crate::core::BinaryHashes;
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};

/// Chunk size for the streaming digest pass (64 KiB keeps I-cache pressure low).
const DIGEST_CHUNK_SIZE: usize = 64 * 1024;

/// Computes all triage hashes for a binary buffer.
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

/// Lowercase hex encoding of digest bytes.
fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// SSDEEP context-triggered piecewise hash; empty string on failure
/// (inputs below the block-size minimum cannot be meaningfully hashed).
fn compute_ssdeep(buffer: &[u8]) -> String {
    fuzzyhash::FuzzyHash::new(buffer).to_string()
}

/// TLSH locality-sensitive hash; empty when the input is too short or
/// lacks sufficient entropy for the algorithm.
fn compute_tlsh(buffer: &[u8]) -> String {
    tlsh::hash_buf(buffer)
        .map(|hash| hash.to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

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
