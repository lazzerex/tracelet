#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExecEvent {
    pub ktime_ns: u64,
    pub pid: u32,
    pub ppid: u32,
    pub comm: [u8; 16],
    pub filename: [u8; 128],
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
