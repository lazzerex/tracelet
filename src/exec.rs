use std::time::Duration;

use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::RingBufferBuilder;
use tracelet_common::{ExecEvent, FILTER_EVENT_ALL};

use crate::error::TraceletError;
use crate::events::{boot_time_ns, decode_exec, str_of, wall_time};
use crate::filter::{self, FilterArgs};
use crate::stats::warn_on_drops;
use crate::TraceletSkelBuilder;

fn print_event(ev: &ExecEvent, boot_offset_ns: u64) {
    println!(
        "{:<12} {:<7} {:<7} {:<16} {}",
        wall_time(ev.ktime_ns, boot_offset_ns),
        ev.pid,
        ev.ppid,
        str_of(&ev.comm),
        str_of(&ev.filename)
    );
}

pub fn run(args: &FilterArgs) -> Result<(), TraceletError> {
    let config = filter::config(args, FILTER_EVENT_ALL)?;
    let skel_builder = TraceletSkelBuilder::default();
    let mut object = std::mem::MaybeUninit::uninit();
    let mut open_skel = skel_builder.open(&mut object)?;
    filter::apply(
        &mut open_skel.maps.rodata_data.as_deref_mut().unwrap().filt,
        &config,
    );
    let skel = open_skel.load()?;

    let _link = skel.progs.trace_exec.attach()?;

    let boot_offset_ns = boot_time_ns();
    println!("TIME         PID     PPID    PROCESS          COMMAND");

    let mut rb_builder = RingBufferBuilder::new();
    rb_builder.add(&skel.maps.events, |data| {
        if let Some(ev) = decode_exec(data) {
            print_event(&ev, boot_offset_ns);
        }
        0
    })?;
    let rb = rb_builder.build()?;

    let mut dropped = 0;
    loop {
        rb.poll(Duration::from_millis(200))?;
        warn_on_drops(&skel.maps.drops, &mut dropped)?;
    }
}
