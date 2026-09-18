use std::time::Duration;

use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::RingBufferBuilder;
use tracelet_common::ExecEvent;

use crate::error::TraceletError;
use crate::TraceletSkelBuilder;

fn boot_time_ns() -> u64 {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) } != 0 {
        return 0;
    }
    (ts.tv_sec as u64) * 1_000_000_000 + ts.tv_nsec as u64
}

fn printable(buf: &[u8]) -> bool {
    buf.iter().all(|&b| b == 0 || (0x20..0x7f).contains(&b))
}

fn decode(data: &[u8]) -> Option<ExecEvent> {
    if data.len() != std::mem::size_of::<ExecEvent>() {
        return None;
    }
    let ev = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const ExecEvent) };
    if !printable(&ev.comm) || !printable(&ev.filename) {
        return None;
    }
    Some(ev)
}

fn str_of(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

fn print_event(ev: &ExecEvent, boot_offset_ns: u64) {
    let wall_ns = boot_offset_ns.wrapping_add(ev.ktime_ns);
    let secs = wall_ns / 1_000_000_000;
    let millis = (wall_ns % 1_000_000_000) / 1_000_000;
    let time = format!(
        "{:02}:{:02}:{:02}.{:03}",
        (secs / 3600) % 24,
        (secs / 60) % 60,
        secs % 60,
        millis
    );
    println!(
        "{:<12} {:<7} {:<7} {:<16} {}",
        time,
        ev.pid,
        ev.ppid,
        str_of(&ev.comm),
        str_of(&ev.filename)
    );
}

pub fn run() -> Result<(), TraceletError> {
    let skel_builder = TraceletSkelBuilder::default();
    let mut object = std::mem::MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut object)?;
    let skel = open_skel.load()?;

    let _link = skel.progs.trace_exec.attach()?;

    let boot_offset_ns = boot_time_ns();
    println!("TIME         PID     PPID    PROCESS          COMMAND");

    let mut rb_builder = RingBufferBuilder::new();
    rb_builder.add(&skel.maps.events, |data| {
        if let Some(ev) = decode(data) {
            print_event(&ev, boot_offset_ns);
        }
        0
    })?;
    let rb = rb_builder.build()?;

    loop {
        rb.poll(Duration::from_millis(200))?;
    }
}

#[cfg(test)]
mod tests {
    use super::{decode, printable};
    use tracelet_common::ExecEvent;

    fn sample() -> ExecEvent {
        let mut ev = ExecEvent {
            ktime_ns: 123,
            pid: 42,
            ppid: 7,
            comm: [0; 16],
            filename: [0; 128],
        };
        ev.comm[..4].copy_from_slice(b"bash");
        ev.filename[..2].copy_from_slice(b"ls");
        ev
    }

    #[test]
    fn decodes_exact_size_bytes() {
        let ev = sample();
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&ev as *const ExecEvent) as *const u8,
                std::mem::size_of::<ExecEvent>(),
            )
        };
        let got = decode(bytes).unwrap();
        assert_eq!(got.pid, 42);
        assert_eq!(got.ppid, 7);
        assert_eq!(&got.comm[..4], b"bash");
        assert_eq!(&got.filename[..2], b"ls");
    }

    #[test]
    fn rejects_wrong_size() {
        assert!(decode(&[0u8; 8]).is_none());
    }

    #[test]
    fn rejects_non_printable_bytes() {
        let mut ev = sample();
        ev.comm[0] = 0x01;
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&ev as *const ExecEvent) as *const u8,
                std::mem::size_of::<ExecEvent>(),
            )
        };
        assert!(decode(bytes).is_none());
    }

    #[test]
    fn printable_allows_nul_and_ascii() {
        assert!(printable(b"bash\0"));
        assert!(!printable(b"ba\xffsh"));
    }
}
