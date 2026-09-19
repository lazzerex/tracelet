use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{Link, MapCore, MapFlags, MapMut};
use tracelet_common::{HIST_SLOTS, SYSCALL_COUNT};

use crate::error::TraceletError;
use crate::events::clock_time;
use crate::filter::{self, FilterArgs, SyscallKind};
use crate::hist::{format_ns, summarize};
use crate::stats::warn_on_drops;
use crate::TraceletSkelBuilder;

fn selected(syscall: Option<SyscallKind>) -> Vec<SyscallKind> {
    match syscall {
        Some(kind) => vec![kind],
        None => vec![SyscallKind::Read, SyscallKind::Write, SyscallKind::Openat],
    }
}

fn attach(
    skel: &crate::TraceletSkel<'_>,
    kinds: &[SyscallKind],
) -> Result<Vec<Link>, TraceletError> {
    let mut links = Vec::new();
    for kind in kinds {
        match kind {
            SyscallKind::Read => {
                links.push(skel.progs.trace_read_enter.attach()?);
                links.push(skel.progs.trace_read_exit.attach()?);
            }
            SyscallKind::Write => {
                links.push(skel.progs.trace_write_enter.attach()?);
                links.push(skel.progs.trace_write_exit.attach()?);
            }
            SyscallKind::Openat => {
                links.push(skel.progs.trace_openat_enter.attach()?);
                links.push(skel.progs.trace_openat_exit.attach()?);
            }
        }
    }
    Ok(links)
}

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

fn print_snapshot(histogram: &[Vec<u64>], kinds: &[SyscallKind]) {
    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    println!("--- {} ---", clock_time(now_ns));
    print_row("SYSCALL", "COUNT", "P50", "P95", "P99");
    for kind in kinds {
        let stats = summarize(&histogram[kind.index() as usize]);
        print_row(
            kind.name(),
            &stats.count.to_string(),
            &format_ns(stats.p50),
            &format_ns(stats.p95),
            &format_ns(stats.p99),
        );
    }
}

pub fn run(args: &FilterArgs, syscall: Option<SyscallKind>) -> Result<(), TraceletError> {
    let config = filter::config(args, tracelet_common::FILTER_EVENT_ALL)?;
    let skel_builder = TraceletSkelBuilder::default();
    let mut object = std::mem::MaybeUninit::uninit();
    let mut open_skel = skel_builder.open(&mut object)?;
    filter::apply(
        &mut open_skel.maps.rodata_data.as_deref_mut().unwrap().filt,
        &config,
    );
    let skel = open_skel.load()?;

    let kinds = selected(syscall);
    let _links = attach(&skel, &kinds)?;

    let mut dropped = 0;
    loop {
        print_snapshot(&read_histogram(&skel.maps.latency_hist)?, &kinds);
        warn_on_drops(&skel.maps.drops, &mut dropped)?;
        std::thread::sleep(Duration::from_secs(1));
    }
}
