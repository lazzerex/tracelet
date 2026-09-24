pub const HIST_SLOTS: u32 = 32;

pub const SYSCALL_COUNT: u32 = 3;

pub const SYSCALL_NAMES: [&str; SYSCALL_COUNT as usize] = ["read", "write", "openat"];

pub const LATENCY_SLOTS: u32 = HIST_SLOTS + 2;
