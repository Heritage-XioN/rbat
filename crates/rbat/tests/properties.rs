use petgraph::unionfind::UnionFind;
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

    /// Invariant: An arbitrary forward-directed DAG where all edges satisfy u < v
    /// must NEVER be detected as having a cycle.
    #[test]
    fn test_has_cycle_dag_invariants(
        n in 1usize..64,
        raw_edges in prop::collection::vec((any::<u8>(), any::<u8>()), 0..100)
    ) {
        let mut adj: Vec<SmallVec<[u32; 2]>> = vec![SmallVec::new(); n];

        // Add random forward edges (u < v)
        for (a, b) in raw_edges {
            let u = (a as usize) % n;
            let v = (b as usize) % n;
            let (u, v) = (u.min(v), u.max(v));
            if u != v && adj[u].len() < 2 && !adj[u].contains(&(v as u32)) {
                adj[u].push(v as u32);
            }
        }

        prop_assert!(!FeatureSet::has_cycle(&adj), "Random DAG falsely reported having a cycle!");
    }

    /// Invariant: Any graph containing a back-edge or cycle must be detected as having a cycle.
    #[test]
    fn test_has_cycle_detected_on_synthetic_cycles(
        n in 2usize..64,
        cycle_start in 0usize..63
    ) {
        let cycle_start = cycle_start % (n - 1);
        let mut adj: Vec<SmallVec<[u32; 2]>> = vec![SmallVec::new(); n];

        // Form a path from 0 to n-1
        for (i, succs) in adj[..n - 1].iter_mut().enumerate() {
            succs.push((i + 1) as u32);
        }
        // Inject a back-edge from n-1 to cycle_start forming a cycle
        adj[n - 1].push(cycle_start as u32);

        prop_assert!(FeatureSet::has_cycle(&adj), "Injected cycle was not detected!");
    }

    /// Invariant: McCabe Cyclomatic Complexity must strictly follow the formula
    /// CC = max_r (E_r - N_r + 2) across weakly connected components.
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

        // Calculate expected McCabe complexity independently using UnionFind
        let mut uf = UnionFind::new(n);
        for (s, succs) in adj.iter().enumerate() {
            for &d in succs {
                uf.union(s, d as usize);
            }
        }
        let labels = uf.into_labeling();

        let mut comp_nodes = vec![0u32; n];
        let mut comp_edges = vec![0u32; n];
        for (s, succs) in adj.iter().enumerate() {
            let r = labels[s];
            comp_nodes[r] += 1;
            comp_edges[r] += succs.len() as u32;
        }

        let expected_cc = (0..n)
            .filter(|&r| comp_nodes[r] > 0)
            .map(|r| (comp_edges[r] + 2).saturating_sub(comp_nodes[r]).max(1) as usize)
            .max()
            .unwrap_or(1);

        prop_assert_eq!(cc, expected_cc, "Cyclomatic complexity mismatch: computed {}, expected {}", cc, expected_cc);
    }
}
