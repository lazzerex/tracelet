#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExecEvent {
    pub ktime_ns: u64,
    pub pid: u32,
    pub ppid: u32,
    pub comm: [u8; 16],
    pub filename: [u8; 128],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OpenEvent {
    pub ktime_ns: u64,
    pub pid: u32,
    pub comm: [u8; 16],
    pub filename: [u8; 128],
}

pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;

pub const TCP_EVENT_CONNECT: u8 = 1;
pub const TCP_EVENT_ACCEPT: u8 = 2;
pub const TCP_EVENT_CLOSE: u8 = 3;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TcpEvent {
    pub ktime_ns: u64,
    pub pid: u32,
    pub comm: [u8; 16],
    pub event_type: u8,
    pub family: u8,
    pub sport: u16,
    pub dport: u16,
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
}

impl TcpEvent {
    pub fn event_name(&self) -> &'static str {
        match self.event_type {
            TCP_EVENT_CONNECT => "CONNECT",
            TCP_EVENT_ACCEPT => "ACCEPT",
            TCP_EVENT_CLOSE => "CLOSE",
            _ => "UNKNOWN",
        }
    }

    pub fn source(&self) -> String {
        format!("{}:{}", self.addr_of(&self.saddr), self.sport)
    }

    pub fn destination(&self) -> String {
        format!("{}:{}", self.addr_of(&self.daddr), self.dport)
    }

    fn addr_of(&self, bytes: &[u8; 16]) -> String {
        match self.family {
            AF_INET => std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string(),
            _ => format!("[{}]", std::net::Ipv6Addr::from(*bytes)),
        }
    }
}

impl ExecEvent {
    pub fn comm(&self) -> &[u8] {
        let end = self
            .comm
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.comm.len());
        &self.comm[..end]
    }

    pub fn filename(&self) -> &[u8] {
        let end = self
            .filename
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.filename.len());
        &self.filename[..end]
    }
}

#[cfg(test)]
mod tests {
    use super::ExecEvent;

    fn event(comm: &[u8], filename: &[u8]) -> ExecEvent {
        let mut ev = ExecEvent {
            ktime_ns: 0,
            pid: 1,
            ppid: 0,
            comm: [0; 16],
            filename: [0; 128],
        };
        ev.comm[..comm.len()].copy_from_slice(comm);
        ev.filename[..filename.len()].copy_from_slice(filename);
        ev
    }

    #[test]
    fn reads_nul_terminated_strings() {
        let ev = event(b"bash", b"/bin/ls");
        assert_eq!(ev.comm(), b"bash");
        assert_eq!(ev.filename(), b"/bin/ls");
    }

    #[test]
    fn handles_full_buffers_without_nul() {
        let mut ev = event(b"abcdefghij", b"/bin/ls");
        ev.filename = [b'a'; 128];
        assert_eq!(ev.comm(), b"abcdefghij");
        assert_eq!(ev.filename(), [b'a'; 128]);
    }
}
