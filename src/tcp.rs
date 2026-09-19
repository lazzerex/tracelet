use std::time::Duration;

use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::RingBufferBuilder;
use tracelet_common::TcpEvent;

use crate::error::TraceletError;
use crate::events::{boot_time_ns, decode_tcp, str_of, wall_time};
use crate::filter::{self, EventKind, FilterArgs};
use crate::stats::warn_on_drops;
use crate::TraceletSkelBuilder;

fn print_event(ev: &TcpEvent, boot_offset_ns: u64) {
    println!(
        "{:<12} {:<16} {:<7} {:<9} {}",
        wall_time(ev.ktime_ns, boot_offset_ns),
        str_of(&ev.comm),
        ev.pid,
        ev.event_name(),
        ev.destination()
    );
}

pub fn run(args: &FilterArgs, event: Option<EventKind>) -> Result<(), TraceletError> {
    let config = filter::config(args, filter::event_mask(event))?;
    let skel_builder = TraceletSkelBuilder::default();
    let mut object = std::mem::MaybeUninit::uninit();
    let mut open_skel = skel_builder.open(&mut object)?;
    filter::apply(
        &mut open_skel.maps.rodata_data.as_deref_mut().unwrap().filt,
        &config,
    );
    let skel = open_skel.load()?;

    let _link = skel.progs.trace_tcp.attach()?;

    let boot_offset_ns = boot_time_ns();
    println!("TIME         PROCESS          PID     EVENT     DESTINATION");

    let mut rb_builder = RingBufferBuilder::new();
    rb_builder.add(&skel.maps.events, |data| {
        if let Some(ev) = decode_tcp(data) {
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
