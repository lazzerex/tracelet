use std::cell::Cell;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::RingBufferBuilder;

use crate::error::TraceletError;
use crate::events::{boot_time_ns, decode_tcp, str_of, wall_time};
use crate::filter::{self, EventKind, FilterArgs};
use crate::output::{self, print_summary};
use crate::stats::warn_on_drops;
use crate::{OutputFormat, TraceletSkelBuilder, RUNNING};

pub fn run(
    args: &FilterArgs,
    event: Option<EventKind>,
    count: Option<u64>,
    duration: Option<Duration>,
    json: OutputFormat,
) -> Result<(), TraceletError> {
    let config = filter::config(args, filter::event_mask(event))?;
    let skel_builder = TraceletSkelBuilder::default();
    let mut object = std::mem::MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut object)?;
    let skel = open_skel.load()?;
    filter::apply_map(&skel.maps.filter_map, &config)?;

    let _link = skel.progs.trace_tcp.attach()?;

    let boot_offset_ns = boot_time_ns();
    if matches!(json, OutputFormat::Text) {
        println!("TIME         PROCESS          PID     EVENT     DESTINATION");
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
        if let Some(ev) = decode_tcp(data) {
            let time = wall_time(ev.ktime_ns, boot_offset_ns);
            let comm = str_of(&ev.comm);
            let event_name = ev.event_name();
            let dest = ev.destination();
            match json {
                OutputFormat::Text => {
                    println!(
                        "{:<12} {:<16} {:<7} {:<9} {}",
                        time, comm, ev.pid, event_name, dest
                    );
                }
                OutputFormat::Json => {
                    buf.clear();
                    output::tcp_json_line(
                        &mut buf,
                        &time,
                        ev.pid,
                        comm,
                        event_name,
                        &ev.source(),
                        &dest,
                    );
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
