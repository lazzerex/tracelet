use std::time::Duration;

use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::RingBufferBuilder;
use tracelet_common::OpenEvent;

use crate::error::TraceletError;
use crate::events::{boot_time_ns, decode_open, str_of, wall_time};
use crate::TraceletSkelBuilder;

fn print_event(ev: &OpenEvent, boot_offset_ns: u64) {
    println!(
        "{:<12} {:<7} {:<16} {}",
        wall_time(ev.ktime_ns, boot_offset_ns),
        ev.pid,
        str_of(&ev.comm),
        str_of(&ev.filename)
    );
}

pub fn run(pid: Option<u32>) -> Result<(), TraceletError> {
    let skel_builder = TraceletSkelBuilder::default();
    let mut object = std::mem::MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut object)?;
    let skel = open_skel.load()?;

    let _open = skel.progs.trace_open.attach()?;
    let _openat = skel.progs.trace_openat.attach()?;
    let _openat2 = skel.progs.trace_openat2.attach()?;

    let boot_offset_ns = boot_time_ns();
    println!("TIME         PID     PROCESS          PATH");

    let mut rb_builder = RingBufferBuilder::new();
    rb_builder.add(&skel.maps.events, |data| {
        if let Some(ev) = decode_open(data) {
            if pid.is_none_or(|p| p == ev.pid) {
                print_event(&ev, boot_offset_ns);
            }
        }
        0
    })?;
    let rb = rb_builder.build()?;

    loop {
        rb.poll(Duration::from_millis(200))?;
    }
}
