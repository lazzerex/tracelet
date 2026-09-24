#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub count: u64,
    pub sum: u64,
    pub max: u64,
    pub p50: u64,
    pub p95: u64,
    pub p99: u64,
}

pub fn upper_bound_ns(slot: u32) -> u64 {
    if slot >= 63 {
        u64::MAX
    } else {
        1u64 << (slot + 1)
    }
}

pub fn summarize(counts: &[u64]) -> Stats {
    let hist_len = (tracelet_common::HIST_SLOTS as usize).min(counts.len());
    let hist = &counts[..hist_len];
    let count: u64 = hist.iter().sum();
    let sum = *counts
        .get(tracelet_common::HIST_SLOTS as usize)
        .unwrap_or(&0);
    let max = *counts
        .get(tracelet_common::HIST_SLOTS as usize + 1)
        .unwrap_or(&0);
    Stats {
        count,
        sum,
        max,
        p50: percentile(hist, count, 50),
        p95: percentile(hist, count, 95),
        p99: percentile(hist, count, 99),
    }
}

pub fn format_ns(ns: u64) -> String {
    if ns < 1_000 {
        format!("{ns}ns")
    } else if ns < 1_000_000 {
        format!("{}us", ns / 1_000)
    } else if ns < 1_000_000_000 {
        format!("{:.1}ms", ns as f64 / 1_000_000.0)
    } else {
        format!("{:.2}s", ns as f64 / 1_000_000_000.0)
    }
}

fn percentile(counts: &[u64], total: u64, p: u64) -> u64 {
    if total == 0 {
        return 0;
    }
    let rank = (p * total).div_ceil(100);
    let mut seen = 0u64;
    for (slot, &count) in counts.iter().enumerate() {
        seen += count;
        if seen >= rank {
            return upper_bound_ns(slot as u32);
        }
    }
    upper_bound_ns(counts.len().saturating_sub(1) as u32)
}

#[cfg(test)]
mod tests {
    use super::{format_ns, summarize, upper_bound_ns};
    use tracelet_common::{HIST_SLOTS, LATENCY_SLOTS, SYSCALL_COUNT, SYSCALL_NAMES};

    fn c_slot_for_ns(ns: u64) -> u32 {
        if ns == 0 {
            return 0;
        }
        (63 - ns.leading_zeros()).min(HIST_SLOTS - 1)
    }

    #[test]
    fn c_slot_matches_floor_log2() {
        assert_eq!(c_slot_for_ns(0), 0);
        for ns in 1..=10_000u64 {
            assert_eq!(c_slot_for_ns(ns), ns.ilog2());
        }
        assert_eq!(c_slot_for_ns(1 << 31), 31);
    }

    #[test]
    fn c_slot_clamps_to_last_bucket() {
        assert_eq!(c_slot_for_ns(u64::MAX), HIST_SLOTS - 1);
        assert_eq!(c_slot_for_ns(u64::MAX >> 1), HIST_SLOTS - 1);
    }

    #[test]
    fn upper_bounds_are_next_power_of_two() {
        assert_eq!(upper_bound_ns(0), 2);
        assert_eq!(upper_bound_ns(10), 2048);
        assert_eq!(upper_bound_ns(31), 1u64 << 32);
        assert_eq!(upper_bound_ns(63), u64::MAX);
    }

    #[test]
    fn empty_histogram_has_no_samples() {
        let stats = summarize(&vec![0u64; HIST_SLOTS as usize]);
        assert_eq!(stats.count, 0);
        assert_eq!((stats.p50, stats.p95, stats.p99), (0, 0, 0));
    }

    #[test]
    fn single_sample_reports_its_bucket() {
        let mut counts = vec![0u64; HIST_SLOTS as usize];
        counts[5] = 1;
        let stats = summarize(&counts);
        assert_eq!(stats.count, 1);
        assert_eq!(stats.p50, upper_bound_ns(5));
        assert_eq!(stats.p99, upper_bound_ns(5));
    }

    #[test]
    fn percentiles_follow_cumulative_counts() {
        let mut counts = vec![0u64; HIST_SLOTS as usize];
        counts[0] = 90;
        counts[10] = 10;
        let stats = summarize(&counts);
        assert_eq!(stats.count, 100);
        assert_eq!(stats.p50, upper_bound_ns(0));
        assert_eq!(stats.p95, upper_bound_ns(10));
        assert_eq!(stats.p99, upper_bound_ns(10));
    }

    #[test]
    fn formats_durations() {
        assert_eq!(format_ns(999), "999ns");
        assert_eq!(format_ns(1_000), "1us");
        assert_eq!(format_ns(8_192), "8us");
        assert_eq!(format_ns(1_048_576), "1.0ms");
        assert_eq!(format_ns(2_000_000_000), "2.00s");
    }

    #[test]
    fn syscall_table_matches_c_contract() {
        assert_eq!(SYSCALL_NAMES.len(), SYSCALL_COUNT as usize);
        assert_eq!(HIST_SLOTS * SYSCALL_COUNT, 96);
    }

    #[test]
    fn latency_slots_matches_c_contract() {
        assert_eq!(LATENCY_SLOTS, HIST_SLOTS + 2);
        assert_eq!(LATENCY_SLOTS * SYSCALL_COUNT, 102);
    }

    #[test]
    fn summarize_handles_extended_slice() {
        let mut counts = vec![0u64; LATENCY_SLOTS as usize];
        counts[5] = 10;
        counts[HIST_SLOTS as usize] = 500;
        counts[HIST_SLOTS as usize + 1] = 100;
        let stats = summarize(&counts);
        assert_eq!(stats.count, 10);
        assert_eq!(stats.sum, 500);
        assert_eq!(stats.max, 100);
        assert_eq!(stats.p50, upper_bound_ns(5));
    }
}
