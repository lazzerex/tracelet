use std::cell::Cell;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::RingBufferBuilder;
use tracelet_common::FILTER_EVENT_ALL;

use crate::error::TraceletError;
use crate::events::{boot_time_ns, decode_open, str_of, wall_time};
use crate::filter::{self, FilterArgs};
use crate::output::{self, print_summary};
use crate::stats::warn_on_drops;
use crate::{OutputFormat, TraceletSkelBuilder, RUNNING};

pub fn run(
    args: &FilterArgs,
    count: Option<u64>,
    duration: Option<Duration>,
    json: OutputFormat,
) -> Result<(), TraceletError> {
    let config = filter::config(args, FILTER_EVENT_ALL)?;
    let skel_builder = TraceletSkelBuilder::default();
    let mut object = std::mem::MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut object)?;
    let skel = open_skel.load()?;
    filter::apply_map(&skel.maps.filter_map, &config)?;

    let mut links = Vec::new();
    for prog in [
        &skel.progs.trace_open,
        &skel.progs.trace_openat,
        &skel.progs.trace_openat2,
    ] {
        links.push(prog.attach()?);
    }

    let boot_offset_ns = boot_time_ns();
    if matches!(json, OutputFormat::Text) {
        println!("TIME         PID     PROCESS          PATH");
    }

    let printed = Cell::new(0u64);
    let mut dropped: u64 = 0;
    let start = Instant::now();
    let mut buf = String::with_capacity(256);

    let mut rb_builder = RingBufferBuilder::new();
    rb_builder.add(&skel.maps.events, |data| {
        if !RUNNING.load(Ordering::SeqCst) {
            return 0;
        }
        if let Some(ev) = decode_open(data) {
            let time = wall_time(ev.ktime_ns, boot_offset_ns);
            let comm = str_of(&ev.comm);
            let filename = str_of(&ev.filename);
            match json {
                OutputFormat::Text => {
                    println!("{:<12} {:<7} {:<16} {}", time, ev.pid, comm, filename);
                }
                OutputFormat::Json => {
                    buf.clear();
                    output::open_json_line(&mut buf, &time, ev.pid, comm, filename);
                    output::write_all(&buf);
                }
            }
            printed.set(printed.get() + 1);
        }
        0
    })?;
    let rb = rb_builder.build()?;

    while !crate::should_stop(printed.get(), count, start, duration) {
        rb.poll(Duration::from_millis(200))?;
        warn_on_drops(&skel.maps.drops, &mut dropped)?;
    }

    print_summary(printed.get(), dropped, start.elapsed());
    Ok(())
}
