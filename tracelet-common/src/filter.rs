pub const FILTER_EVENT_CONNECT: u32 = 1;
pub const FILTER_EVENT_ACCEPT: u32 = 2;
pub const FILTER_EVENT_CLOSE: u32 = 4;
pub const FILTER_EVENT_ALL: u32 = 7;

pub const COMM_MAX_LEN: usize = 15;
pub const MAX_PIDS: usize = 16;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FilterConfig {
    pub event_mask: u32,
    pub pid_count: u32,
    pub pids: [u32; MAX_PIDS],
    pub ppid: u32,
    pub ppid_enabled: u32,
    pub comm_enabled: u32,
    pub comm: [u8; 16],
}
