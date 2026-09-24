pub mod event;
pub mod filter;
pub mod latency;
pub mod stream;

pub use event::{
    ExecEvent, OpenEvent, TcpEvent, AF_INET, AF_INET6, EVENT_KIND_EXEC, EVENT_KIND_OPEN,
    TCP_EVENT_ACCEPT, TCP_EVENT_CLOSE, TCP_EVENT_CONNECT,
};
pub use filter::{
    FilterConfig, COMM_MAX_LEN, FILTER_EVENT_ACCEPT, FILTER_EVENT_ALL, FILTER_EVENT_CLOSE,
    FILTER_EVENT_CONNECT, MAX_PIDS,
};
pub use latency::{HIST_SLOTS, SYSCALL_COUNT, SYSCALL_NAMES};

pub const EXEC_EVENT_SIZE: usize = std::mem::size_of::<ExecEvent>();
pub const OPEN_EVENT_SIZE: usize = std::mem::size_of::<OpenEvent>();
pub const TCP_EVENT_SIZE: usize = std::mem::size_of::<TcpEvent>();

pub const RECORD_VERSION: u32 = 1;

pub const RECORD_HEADER_SIZE: usize = 8;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RecordHeader {
    pub kind: u32,
    pub version: u32,
}

const _: () = assert!(std::mem::size_of::<RecordHeader>() == RECORD_HEADER_SIZE);
const _: () = assert!(EXEC_EVENT_SIZE == 168);
const _: () = assert!(OPEN_EVENT_SIZE == 160);
const _: () = assert!(TCP_EVENT_SIZE == 72);
