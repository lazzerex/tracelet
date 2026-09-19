use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, MapMut};
use tracelet_common::{HIST_SLOTS, SYSCALL_COUNT, SYSCALL_NAMES};

use crate::error::TraceletError;
use crate::events::clock_time;
use crate::hist::{format_ns, summarize};
use crate::TraceletSkelBuilder;

fn read_histogram(map: &MapMut<'_>) -> Result<Vec<Vec<u64>>, TraceletError> {
    let mut histogram = Vec::with_capacity(SYSCALL_COUNT as usize);
    for syscall in 0..SYSCALL_COUNT {
        let mut slots = vec![0u64; HIST_SLOTS as usize];
        for (slot, count) in slots.iter_mut().enumerate() {
            let key = (syscall * HIST_SLOTS + slot as u32).to_ne_bytes();
            if let Some(value) = map.lookup(&key, MapFlags::ANY)? {
                if value.len() == 8 {
                    let mut raw = [0u8; 8];
                    raw.copy_from_slice(&value[..8]);
                    *count = u64::from_ne_bytes(raw);
                }
            }
        }
        histogram.push(slots);
    }
    Ok(histogram)
}

fn print_row(syscall: &str, count: &str, p50: &str, p95: &str, p99: &str) {
    println!(
        "{:<11} {:<11} {:<9} {:<9} {}",
        syscall, count, p50, p95, p99
    );
}

fn print_snapshot(histogram: &[Vec<u64>]) {
    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    println!("--- {} ---", clock_time(now_ns));
    print_row("SYSCALL", "COUNT", "P50", "P95", "P99");
    for (syscall, slots) in histogram.iter().enumerate() {
        let stats = summarize(slots);
        print_row(
            SYSCALL_NAMES[syscall],
            &stats.count.to_string(),
            &format_ns(stats.p50),
            &format_ns(stats.p95),
            &format_ns(stats.p99),
        );
    }
}

pub fn run() -> Result<(), TraceletError> {
    let skel_builder = TraceletSkelBuilder::default();
    let mut object = std::mem::MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut object)?;
    let skel = open_skel.load()?;

    let _read_enter = skel.progs.trace_read_enter.attach()?;
    let _read_exit = skel.progs.trace_read_exit.attach()?;
    let _write_enter = skel.progs.trace_write_enter.attach()?;
    let _write_exit = skel.progs.trace_write_exit.attach()?;
    let _openat_enter = skel.progs.trace_openat_enter.attach()?;
    let _openat_exit = skel.progs.trace_openat_exit.attach()?;

    loop {
        print_snapshot(&read_histogram(&skel.maps.latency_hist)?);
        std::thread::sleep(Duration::from_secs(1));
    }
}
