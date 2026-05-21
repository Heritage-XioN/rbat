//! # Shannon Entropy Calculator
//!
//! This module calculates the Shannon entropy of a byte slice to assess the randomness
//! of data. High entropy (approaching 8.0) suggests compressed, encrypted, or packed binary code.

/// Calculates the Shannon entropy of a given byte slice.
/// Returns a value between 0.0 and 8.0.
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
}
