use tracelet_common::{
    ExecEvent, OpenEvent, TcpEvent, AF_INET, AF_INET6, TCP_EVENT_CLOSE, TCP_EVENT_CONNECT,
};

pub fn boot_time_ns() -> u64 {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) } != 0 {
        return 0;
    }
    (ts.tv_sec as u64) * 1_000_000_000 + ts.tv_nsec as u64
}

pub fn clock_time(ns: u64) -> String {
    let secs = ns / 1_000_000_000;
    let millis = (ns % 1_000_000_000) / 1_000_000;
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        (secs / 3600) % 24,
        (secs / 60) % 60,
        secs % 60,
        millis
    )
}

pub fn wall_time(ktime_ns: u64, boot_offset_ns: u64) -> String {
    clock_time(boot_offset_ns.wrapping_add(ktime_ns))
}

pub fn str_of(buf: &[u8]) -> &str {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    std::str::from_utf8(&buf[..end]).unwrap_or("")
}

fn printable(buf: &[u8]) -> bool {
    buf.iter().all(|&b| b == 0 || (0x20..0x7f).contains(&b))
}

pub fn read_event<E: Copy>(data: &[u8]) -> Option<E> {
    if data.len() != std::mem::size_of::<E>() {
        return None;
    }
    Some(unsafe { std::ptr::read_unaligned(data.as_ptr() as *const E) })
}

fn skip_header(data: &[u8]) -> Option<&[u8]> {
    if data.len() < 8 {
        return None;
    }
    let version = u32::from_ne_bytes([data[4], data[5], data[6], data[7]]);
    if version != tracelet_common::RECORD_VERSION {
        return None;
    }
    Some(&data[8..])
}

pub fn decode_exec(data: &[u8]) -> Option<ExecEvent> {
    let payload = skip_header(data)?;
    let ev = read_event::<ExecEvent>(payload)?;
    if !printable(&ev.comm) || !printable(&ev.filename) {
        return None;
    }
    Some(ev)
}

pub fn decode_open(data: &[u8]) -> Option<OpenEvent> {
    let payload = skip_header(data)?;
    let ev = read_event::<OpenEvent>(payload)?;
    if !printable(&ev.comm) || !printable(&ev.filename) {
        return None;
    }
    Some(ev)
}

pub fn decode_tcp(data: &[u8]) -> Option<TcpEvent> {
    let payload = skip_header(data)?;
    let ev = read_event::<TcpEvent>(payload)?;
    if !printable(&ev.comm) {
        return None;
    }
    if ev.family != AF_INET && ev.family != AF_INET6 {
        return None;
    }
    if !(TCP_EVENT_CONNECT..=TCP_EVENT_CLOSE).contains(&ev.event_type) {
        return None;
    }
    Some(ev)
}

#[cfg(test)]
mod tests {
    use super::{boot_time_ns, decode_exec, decode_open, decode_tcp, skip_header, wall_time};
    use tracelet_common::{
        ExecEvent, OpenEvent, TcpEvent, AF_INET, AF_INET6, EVENT_KIND_EXEC, EVENT_KIND_OPEN,
        RECORD_VERSION, TCP_EVENT_ACCEPT, TCP_EVENT_CLOSE, TCP_EVENT_CONNECT,
    };

    fn wrap_with_header(kind: u32, ev_bytes: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + ev_bytes.len());
        buf.extend_from_slice(&kind.to_ne_bytes());
        buf.extend_from_slice(&RECORD_VERSION.to_ne_bytes());
        buf.extend_from_slice(ev_bytes);
        buf
    }

    fn exec_bytes(ev: &ExecEvent) -> Vec<u8> {
        let ev_bytes = unsafe {
            std::slice::from_raw_parts(
                (ev as *const ExecEvent) as *const u8,
                std::mem::size_of::<ExecEvent>(),
            )
        };
        wrap_with_header(EVENT_KIND_EXEC, ev_bytes)
    }

    fn open_bytes(ev: &OpenEvent) -> Vec<u8> {
        let ev_bytes = unsafe {
            std::slice::from_raw_parts(
                (ev as *const OpenEvent) as *const u8,
                std::mem::size_of::<OpenEvent>(),
            )
        };
        wrap_with_header(EVENT_KIND_OPEN, ev_bytes)
    }

    fn tcp_bytes(ev: &TcpEvent) -> Vec<u8> {
        let ev_bytes = unsafe {
            std::slice::from_raw_parts(
                (ev as *const TcpEvent) as *const u8,
                std::mem::size_of::<TcpEvent>(),
            )
        };
        wrap_with_header(0, ev_bytes)
    }

    fn exec_event() -> ExecEvent {
        let mut ev = ExecEvent {
            ktime_ns: 123,
            kind: EVENT_KIND_EXEC,
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
            kind: EVENT_KIND_OPEN,
            pid: 9,
            comm: [0; 16],
            filename: [0; 128],
        };
        ev.comm[..3].copy_from_slice(b"cat");
        ev.filename[..10].copy_from_slice(b"/etc/hosts");
        ev
    }

    fn tcp_event() -> TcpEvent {
        let mut ev = TcpEvent {
            ktime_ns: 789,
            pid: 9123,
            comm: [0; 16],
            event_type: TCP_EVENT_CONNECT,
            family: AF_INET,
            sport: 54321,
            dport: 443,
            saddr: [0; 16],
            daddr: [0; 16],
        };
        ev.comm[..4].copy_from_slice(b"curl");
        ev.saddr[..4].copy_from_slice(&[10, 0, 0, 5]);
        ev.daddr[..4].copy_from_slice(&[142, 250, 1, 1]);
        ev
    }

    #[test]
    fn decodes_exec_event() {
        let got = decode_exec(&exec_bytes(&exec_event())).unwrap();
        assert_eq!(got.pid, 42);
        assert_eq!(got.ppid, 7);
        assert_eq!(&got.comm[..4], b"bash");
        assert_eq!(&got.filename[..2], b"ls");
    }

    #[test]
    fn decodes_open_event() {
        let got = decode_open(&open_bytes(&open_event())).unwrap();
        assert_eq!(got.pid, 9);
        assert_eq!(&got.comm[..3], b"cat");
        assert_eq!(&got.filename[..10], b"/etc/hosts");
    }

    #[test]
    fn rejects_wrong_size() {
        assert!(decode_exec(&[0u8; 8]).is_none());
        assert!(decode_open(&[0u8; 8]).is_none());
        assert!(decode_tcp(&[0u8; 8]).is_none());
    }

    #[test]
    fn decodes_tcp_event() {
        let got = decode_tcp(&tcp_bytes(&tcp_event())).unwrap();
        assert_eq!(got.pid, 9123);
        assert_eq!(got.event_name(), "CONNECT");
        assert_eq!(got.source(), "10.0.0.5:54321");
        assert_eq!(got.destination(), "142.250.1.1:443");
    }

    #[test]
    fn formats_tcp_event_names() {
        let mut ev = tcp_event();
        ev.event_type = TCP_EVENT_ACCEPT;
        let got = decode_tcp(&tcp_bytes(&ev)).unwrap();
        assert_eq!(got.event_name(), "ACCEPT");
        ev.event_type = TCP_EVENT_CLOSE;
        let got = decode_tcp(&tcp_bytes(&ev)).unwrap();
        assert_eq!(got.event_name(), "CLOSE");
    }

    #[test]
    fn formats_ipv6_addresses() {
        let mut ev = tcp_event();
        ev.family = AF_INET6;
        ev.saddr = [0; 16];
        ev.saddr[0] = 0xfe;
        ev.saddr[1] = 0x80;
        ev.saddr[15] = 1;
        ev.daddr = [0; 16];
        ev.daddr[1] = 1;
        let got = decode_tcp(&tcp_bytes(&ev)).unwrap();
        assert_eq!(got.source(), "[fe80::1]:54321");
        assert_eq!(got.destination(), "[1::]:443");
    }

    #[test]
    fn rejects_unknown_tcp_family_and_type() {
        let mut ev = tcp_event();
        ev.family = 99;
        assert!(decode_tcp(&tcp_bytes(&ev)).is_none());
        let mut ev = tcp_event();
        ev.event_type = 0;
        assert!(decode_tcp(&tcp_bytes(&ev)).is_none());
    }

    #[test]
    fn rejects_non_printable_bytes() {
        let mut ev = exec_event();
        ev.comm[0] = 0x01;
        assert!(decode_exec(&exec_bytes(&ev)).is_none());
        let mut ev = open_event();
        ev.filename[0] = 0xff;
        assert!(decode_open(&open_bytes(&ev)).is_none());
    }

    #[test]
    fn event_struct_sizes_match_c_layout() {
        assert_eq!(std::mem::size_of::<ExecEvent>(), 168);
        assert_eq!(std::mem::size_of::<OpenEvent>(), 160);
        assert_eq!(std::mem::size_of::<TcpEvent>(), 72);
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

    #[test]
    fn rejects_wrong_version() {
        let ev = exec_event();
        let ev_bytes = unsafe {
            std::slice::from_raw_parts(
                (&ev as *const ExecEvent) as *const u8,
                std::mem::size_of::<ExecEvent>(),
            )
        };
        let mut buf = Vec::new();
        buf.extend_from_slice(&EVENT_KIND_EXEC.to_ne_bytes());
        buf.extend_from_slice(&999u32.to_ne_bytes());
        buf.extend_from_slice(ev_bytes);
        assert!(decode_exec(&buf).is_none());
    }

    #[test]
    fn skip_header_validates_version() {
        assert!(skip_header(&[0u8; 4]).is_none());
        assert!(skip_header(&[]).is_none());
        let mut buf = vec![0u8; 8 + 168];
        buf[0..4].copy_from_slice(&EVENT_KIND_EXEC.to_ne_bytes());
        buf[4..8].copy_from_slice(&RECORD_VERSION.to_ne_bytes());
        assert!(skip_header(&buf).is_some());
    }
}
