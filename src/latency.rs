use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{Link, MapCore, MapFlags, MapMut};
use tracelet_common::{LATENCY_SLOTS, SYSCALL_COUNT};

use crate::error::TraceletError;
use crate::events::clock_time;
use crate::filter::{self, FilterArgs, SyscallKind};
use crate::hist::{format_ns, summarize};
use crate::output::{self, print_summary};
use crate::stats::warn_on_drops;
use crate::{OutputFormat, TraceletSkelBuilder};

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
        let mut slots = vec![0u64; LATENCY_SLOTS as usize];
        for (slot, count) in slots.iter_mut().enumerate() {
            let key = (syscall * LATENCY_SLOTS + slot as u32).to_ne_bytes();
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

pub fn run(
    args: &FilterArgs,
    buffer_mb: u32,
    syscall: Option<SyscallKind>,
    duration: Option<Duration>,
    json: OutputFormat,
) -> Result<(), TraceletError> {
    crate::kernel::check_prereqs("latency")?;
    let config = filter::config(args, tracelet_common::FILTER_EVENT_ALL)?;
    let skel_builder = TraceletSkelBuilder::default();
    let mut object = std::mem::MaybeUninit::uninit();
    let mut open_skel = skel_builder.open(&mut object)?;
    if buffer_mb != 16 {
        open_skel
            .maps
            .events
            .set_max_entries(buffer_mb * 1024 * 1024)?;
    }
    let skel = open_skel.load()?;
    filter::apply_map(&skel.maps.filter_map, &config)?;

    let kinds = selected(syscall);
    let _links = attach(&skel, &kinds)?;

    let mut drops_seen = [0u64; 2];
    let start = Instant::now();
    let mut buf = String::with_capacity(512);

    while !crate::should_stop(0, None, start, duration) {
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let time = clock_time(now_ns);
        let histogram = read_histogram(&skel.maps.latency_hist)?;

        match json {
            OutputFormat::Text => {
                println!("--- {} ---", time);
                let (h0, h1, h2, h3, h4, h5, h6) =
                    ("SYSCALL", "COUNT", "P50", "P95", "P99", "MEAN", "MAX");
                println!(
                    "{:<11} {:<11} {:<9} {:<9} {:<9} {:<9} {}",
                    h0, h1, h2, h3, h4, h5, h6
                );
                for kind in &kinds {
                    let stats = summarize(&histogram[kind.index() as usize]);
                    let mean = stats.sum.checked_div(stats.count).unwrap_or(0);
                    println!(
                        "{:<11} {:<11} {:<9} {:<9} {:<9} {:<9} {}",
                        kind.name(),
                        stats.count,
                        format_ns(stats.p50),
                        format_ns(stats.p95),
                        format_ns(stats.p99),
                        format_ns(mean),
                        format_ns(stats.max),
                    );
                }
            }
            OutputFormat::Json => {
                for kind in &kinds {
                    let stats = summarize(&histogram[kind.index() as usize]);
                    let mean = stats.sum.checked_div(stats.count).unwrap_or(0);
                    buf.clear();
                    output::latency_json_line(
                        &mut buf,
                        &time,
                        kind.name(),
                        stats.count,
                        &format_ns(stats.p50),
                        &format_ns(stats.p95),
                        &format_ns(stats.p99),
                        &format_ns(mean),
                        &format_ns(stats.max),
                    );
                    output::write_all(&buf);
                }
            }
        }

        warn_on_drops(&skel.maps.drops, &mut drops_seen)?;
        std::thread::sleep(Duration::from_secs(1));
    }

    let total_drops = drops_seen[0] + drops_seen[1];
    print_summary(0, total_drops, start.elapsed());
    Ok(())
}
