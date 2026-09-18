use tracelet_common::{ExecEvent, OpenEvent};

pub fn boot_time_ns() -> u64 {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) } != 0 {
        return 0;
    }
    (ts.tv_sec as u64) * 1_000_000_000 + ts.tv_nsec as u64
}

pub fn wall_time(ktime_ns: u64, boot_offset_ns: u64) -> String {
    let wall_ns = boot_offset_ns.wrapping_add(ktime_ns);
    let secs = wall_ns / 1_000_000_000;
    let millis = (wall_ns % 1_000_000_000) / 1_000_000;
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        (secs / 3600) % 24,
        (secs / 60) % 60,
        secs % 60,
        millis
    )
}

fn printable(buf: &[u8]) -> bool {
    buf.iter().all(|&b| b == 0 || (0x20..0x7f).contains(&b))
}

fn read_event<E: Copy>(data: &[u8]) -> Option<E> {
    if data.len() != std::mem::size_of::<E>() {
        return None;
    }
    Some(unsafe { std::ptr::read_unaligned(data.as_ptr() as *const E) })
}

pub fn decode_exec(data: &[u8]) -> Option<ExecEvent> {
    let ev = read_event::<ExecEvent>(data)?;
    if !printable(&ev.comm) || !printable(&ev.filename) {
        return None;
    }
    Some(ev)
}

pub fn decode_open(data: &[u8]) -> Option<OpenEvent> {
    let ev = read_event::<OpenEvent>(data)?;
    if !printable(&ev.comm) || !printable(&ev.filename) {
        return None;
    }
    Some(ev)
}

pub fn str_of(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::{boot_time_ns, decode_exec, decode_open, wall_time};
    use tracelet_common::{ExecEvent, OpenEvent};

    fn as_bytes<E: Copy>(ev: &E) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts((ev as *const E) as *const u8, std::mem::size_of::<E>())
        }
    }

    fn exec_event() -> ExecEvent {
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

    fn open_event() -> OpenEvent {
        let mut ev = OpenEvent {
            ktime_ns: 456,
            pid: 9,
            comm: [0; 16],
            filename: [0; 128],
        };
        ev.comm[..3].copy_from_slice(b"cat");
        ev.filename[..10].copy_from_slice(b"/etc/hosts");
        ev
    }

    #[test]
    fn decodes_exec_event() {
        let got = decode_exec(as_bytes(&exec_event())).unwrap();
        assert_eq!(got.pid, 42);
        assert_eq!(got.ppid, 7);
        assert_eq!(&got.comm[..4], b"bash");
        assert_eq!(&got.filename[..2], b"ls");
    }

    #[test]
    fn decodes_open_event() {
        let got = decode_open(as_bytes(&open_event())).unwrap();
        assert_eq!(got.pid, 9);
        assert_eq!(&got.comm[..3], b"cat");
        assert_eq!(&got.filename[..10], b"/etc/hosts");
    }

    #[test]
    fn rejects_wrong_size() {
        assert!(decode_exec(&[0u8; 8]).is_none());
        assert!(decode_open(&[0u8; 8]).is_none());
    }

    #[test]
    fn rejects_non_printable_bytes() {
        let mut ev = exec_event();
        ev.comm[0] = 0x01;
        assert!(decode_exec(as_bytes(&ev)).is_none());
        let mut ev = open_event();
        ev.filename[0] = 0xff;
        assert!(decode_open(as_bytes(&ev)).is_none());
    }

    #[test]
    fn formats_wall_time() {
        let boot: u64 = (10 * 3600 + 31 * 60 + 2) * 1_000_000_000 + 183_000_000;
        assert_eq!(wall_time(0, boot), "10:31:02.183");
    }

    #[test]
    fn boot_time_is_nonzero() {
        assert!(boot_time_ns() > 0);
    }
}
