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
