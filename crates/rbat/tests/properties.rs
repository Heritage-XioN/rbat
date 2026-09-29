use proptest::prelude::*;
use rbat::core::features::FeatureSet;
use smallvec::SmallVec;

proptest! {
    /// Invariant: FeatureSet::merge_ranges must always produce strictly ascending,
    /// disjoint, non-overlapping intervals, and every input interval must be fully
    /// enclosed by one of the merged intervals.
    #[test]
    fn test_merge_ranges_invariants(raw_ranges in prop::collection::vec((any::<u64>(), any::<u64>()), 0..200)) {
        // Normalize pairs to valid (start, end) where start <= end
        let ranges: Vec<(u64, u64)> = raw_ranges
            .into_iter()
            .map(|(a, b)| (a.min(b), a.max(b)))
            .collect();

        let merged = FeatureSet::merge_ranges(ranges.clone());

        // 1. Strictly ascending and non-overlapping
        for i in 0..merged.len().saturating_sub(1) {
            prop_assert!(
                merged[i].1 < merged[i + 1].0,
                "Overlapping or non-disjoint intervals found: {:?} and {:?}",
                merged[i],
                merged[i + 1]
            );
            prop_assert!(
                merged[i].0 < merged[i + 1].0,
                "Start addresses are not strictly increasing: {} >= {}",
                merged[i].0,
                merged[i + 1].0
            );
        }

        // 2. Interval validity
        for (s, e) in &merged {
            prop_assert!(s <= e, "Interval has inverted bounds: {} > {}", s, e);
        }

        // 3. Every input range must be fully covered by at least one merged interval
        for (in_s, in_e) in ranges {
            let covered = merged.iter().any(|&(m_s, m_e)| m_s <= in_s && in_e <= m_e);
            prop_assert!(
                covered,
                "Input interval ({}, {}) is not covered by any merged interval in {:?}",
                in_s,
                in_e,
                merged
            );
        }
    }

    /// Invariant: A strictly forward Directed Acyclic Graph (DAG) where all edges
    /// satisfy u < v must NEVER contain a cycle.
    #[test]
    fn test_has_cycle_dag_invariants(n in 1usize..64) {
        let mut adj: Vec<SmallVec<[u32; 2]>> = vec![SmallVec::new(); n];

        // Generate forward-only edges (u -> v where u < v)
        for (u, succs) in adj.iter_mut().enumerate() {
            for v in (u + 1)..n {
                if (u + v) % 3 == 0 && succs.len() < 2 {
                    succs.push(v as u32);
                }
            }
        }

        prop_assert!(!FeatureSet::has_cycle(&adj), "DAG falsely reported having a cycle!");
    }

    /// Invariant: Any graph with an explicit cycle must be detected as having a cycle.
    #[test]
    fn test_has_cycle_detected_on_synthetic_cycles(n in 2usize..64) {
        let mut adj: Vec<SmallVec<[u32; 2]>> = vec![SmallVec::new(); n];

        // Form a simple Hamiltonian ring 0 -> 1 -> 2 -> ... -> (n-1) -> 0
        for (i, succs) in adj[..n - 1].iter_mut().enumerate() {
            succs.push((i + 1) as u32);
        }
        adj[n - 1].push(0);

        prop_assert!(FeatureSet::has_cycle(&adj), "Cycle ring was not detected!");
    }

    /// Invariant: McCabe Cyclomatic Complexity must always evaluate to at least 1
    /// for any arbitrary graph structure.
    #[test]
    fn test_max_cyclomatic_complexity_invariants(
        n in 1usize..50,
        edges in prop::collection::vec((any::<u8>(), any::<u8>()), 0..100)
    ) {
        let mut adj: Vec<SmallVec<[u32; 2]>> = vec![SmallVec::new(); n];

        for (u, v) in edges {
            let u = (u as usize) % n;
            let v = (v as usize) % n;
            if adj[u].len() < 2 && !adj[u].contains(&(v as u32)) {
                adj[u].push(v as u32);
            }
        }

        let cc = FeatureSet::max_cyclomatic_complexity(&adj);
        prop_assert!(cc >= 1, "Cyclomatic complexity was less than 1: {}", cc);
    }
}
