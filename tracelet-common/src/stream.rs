use crate::{ExecEvent, OpenEvent, TcpEvent, AF_INET, AF_INET6};

pub const STREAM_MAX: usize = 512;

pub const FILE_EVENT_EXEC: u8 = 0;
pub const FILE_EVENT_OPEN: u8 = 1;

pub fn file_event_name(kind: u8) -> &'static str {
    match kind {
        FILE_EVENT_EXEC => "EXEC",
        FILE_EVENT_OPEN => "OPEN",
        _ => "UNKNOWN",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DashboardEvent {
    File {
        pid: u32,
        ppid: u32,
        kind: u8,
        comm: [u8; 16],
        path: [u8; 128],
    },
    Tcp {
        pid: u32,
        event_type: u8,
        family: u8,
        comm: [u8; 16],
        dest: String,
    },
}

impl DashboardEvent {
    pub fn pid(&self) -> u32 {
        match self {
            DashboardEvent::File { pid, .. } => *pid,
            DashboardEvent::Tcp { pid, .. } => *pid,
        }
    }

    pub fn ppid(&self) -> u32 {
        match self {
            DashboardEvent::File { ppid, .. } => *ppid,
            DashboardEvent::Tcp { .. } => 0,
        }
    }

    pub fn kind(&self) -> u8 {
        match self {
            DashboardEvent::File { kind, .. } => *kind,
            DashboardEvent::Tcp { .. } => u8::MAX,
        }
    }

    pub fn event_name(&self) -> &'static str {
        match self {
            DashboardEvent::File { kind, .. } => file_event_name(*kind),
            DashboardEvent::Tcp { event_type, .. } => TcpEvent {
                event_type: *event_type,
                ..placeholders()
            }
            .event_name(),
        }
    }

    pub fn comm(&self) -> &[u8] {
        match self {
            DashboardEvent::File { comm, .. } | DashboardEvent::Tcp { comm, .. } => comm,
        }
    }

    pub fn details(&self) -> String {
        match self {
            DashboardEvent::File { path, .. } => String::from_utf8_lossy(
                &path[..path.iter().position(|&b| b == 0).unwrap_or(path.len())],
            )
            .into_owned(),
            DashboardEvent::Tcp { dest, .. } => dest.clone(),
        }
    }
}

fn placeholders() -> TcpEvent {
    TcpEvent {
        ktime_ns: 0,
        pid: 0,
        comm: [0; 16],
        event_type: 0,
        family: 0,
        sport: 0,
        dport: 0,
        saddr: [0; 16],
        daddr: [0; 16],
    }
}

pub fn printable(buf: &[u8]) -> bool {
    buf.iter().all(|&b| b == 0 || (0x20..0x7f).contains(&b))
}

fn read_event<E: Copy>(data: &[u8]) -> Option<E> {
    if data.len() != std::mem::size_of::<E>() {
        return None;
    }
    Some(unsafe { std::ptr::read_unaligned(data.as_ptr() as *const E) })
}

fn decode_tcp(data: &[u8]) -> Option<TcpEvent> {
    let ev = read_event::<TcpEvent>(data)?;
    if !printable(&ev.comm) {
        return None;
    }
    if ev.family != AF_INET && ev.family != AF_INET6 {
        return None;
    }
    if !(1..=3).contains(&ev.event_type) {
        return None;
    }
    Some(ev)
}

pub fn decode_stream(data: &[u8]) -> Option<DashboardEvent> {
    match data.len() {
        72 => {
            let ev = decode_tcp(data)?;
            Some(DashboardEvent::Tcp {
                pid: ev.pid,
                event_type: ev.event_type,
                family: ev.family,
                comm: ev.comm,
                dest: ev.destination().to_string(),
            })
        }
        168 => {
            let ev = read_event::<ExecEvent>(data)?;
            if ev.kind != crate::EVENT_KIND_EXEC {
                return None;
            }
            if !printable(&ev.comm) || !printable(&ev.filename) {
                return None;
            }
            Some(DashboardEvent::File {
                pid: ev.pid,
                ppid: ev.ppid,
                kind: FILE_EVENT_EXEC,
                comm: ev.comm,
                path: ev.filename,
            })
        }
        160 => {
            let ev = read_event::<OpenEvent>(data)?;
            if ev.kind != crate::EVENT_KIND_OPEN {
                return None;
            }
            if !printable(&ev.comm) || !printable(&ev.filename) {
                return None;
            }
            Some(DashboardEvent::File {
                pid: ev.pid,
                ppid: 0,
                kind: FILE_EVENT_OPEN,
                comm: ev.comm,
                path: ev.filename,
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_stream, file_event_name, DashboardEvent, FILE_EVENT_EXEC, FILE_EVENT_OPEN};
    use crate::{
        ExecEvent, OpenEvent, TcpEvent, AF_INET, EVENT_KIND_EXEC, EVENT_KIND_OPEN,
        TCP_EVENT_CONNECT,
    };

    fn as_bytes<E: Copy>(ev: &E) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts((ev as *const E) as *const u8, std::mem::size_of::<E>())
        }
    }

    fn exec_event() -> ExecEvent {
        let mut ev = ExecEvent {
            ktime_ns: 0,
            kind: EVENT_KIND_EXEC,
            pid: 3,
            ppid: 2,
            comm: [0; 16],
            filename: [0; 128],
        };
        ev.comm[..4].copy_from_slice(b"bash");
        ev.filename[..6].copy_from_slice(b"/bin/x");
        ev
    }

    fn open_event() -> OpenEvent {
        let mut ev = OpenEvent {
            ktime_ns: 0,
            kind: EVENT_KIND_OPEN,
            pid: 5,
            comm: [0; 16],
            filename: [0; 128],
        };
        ev.comm[..3].copy_from_slice(b"cat");
        ev.filename[..10].copy_from_slice(b"/etc/hosts");
        ev
    }

    fn tcp_event() -> TcpEvent {
        let mut ev = TcpEvent {
            ktime_ns: 0,
            pid: 7,
            comm: [0; 16],
            event_type: TCP_EVENT_CONNECT,
            family: AF_INET,
            sport: 54321,
            dport: 443,
            saddr: [0; 16],
            daddr: [0; 16],
        };
        ev.comm[..4].copy_from_slice(b"curl");
        ev.daddr[..4].copy_from_slice(&[142, 250, 1, 1]);
        ev
    }

    #[test]
    fn decodes_exec_events() {
        let got = decode_stream(as_bytes(&exec_event())).unwrap();
        match got {
            DashboardEvent::File { kind, ppid, .. } => {
                assert_eq!(kind, FILE_EVENT_EXEC);
                assert_eq!(ppid, 2);
            }
            _ => panic!("expected file event"),
        }
        assert_eq!(got.event_name(), "EXEC");
        assert_eq!(got.details(), "/bin/x");
    }

    #[test]
    fn decodes_open_events() {
        let got = decode_stream(as_bytes(&open_event())).unwrap();
        match got {
            DashboardEvent::File { kind, ppid, .. } => {
                assert_eq!(kind, FILE_EVENT_OPEN);
                assert_eq!(ppid, 0);
            }
            _ => panic!("expected file event"),
        }
        assert_eq!(got.event_name(), "OPEN");
        assert_eq!(got.details(), "/etc/hosts");
    }

    #[test]
    fn decodes_tcp_events() {
        let got = decode_stream(as_bytes(&tcp_event())).unwrap();
        let (pid, dest) = match got {
            DashboardEvent::Tcp { pid, dest, .. } => (pid, dest),
            _ => panic!("expected tcp event"),
        };
        assert_eq!(pid, 7);
        assert_eq!(dest, "142.250.1.1:443");
    }

    #[test]
    fn rejects_wrong_kind_and_garbage_sizes() {
        let mut ev = exec_event();
        ev.kind = EVENT_KIND_OPEN;
        assert!(decode_stream(as_bytes(&ev)).is_none());
        let mut ev = open_event();
        ev.kind = EVENT_KIND_EXEC;
        assert!(decode_stream(as_bytes(&ev)).is_none());
        assert!(decode_stream(&[0u8; 100]).is_none());
    }

    #[test]
    fn file_event_names_map_kinds() {
        assert_eq!(file_event_name(FILE_EVENT_EXEC), "EXEC");
        assert_eq!(file_event_name(FILE_EVENT_OPEN), "OPEN");
        assert_eq!(file_event_name(9), "UNKNOWN");
    }
}
