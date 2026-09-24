use clap::{Args, ValueEnum};
use tracelet_common::{
    FilterConfig, COMM_MAX_LEN, FILTER_EVENT_ACCEPT, FILTER_EVENT_CLOSE, FILTER_EVENT_CONNECT,
    MAX_PIDS,
};

use crate::error::TraceletError;

#[derive(Args, Clone, Default)]
pub struct FilterArgs {
    #[arg(
        long,
        value_delimiter = ',',
        help = "Only trace events from these PIDs (comma-separated, max 16)"
    )]
    pub pid: Option<Vec<u32>>,
    #[arg(long, help = "Only trace events from this parent PID")]
    pub ppid: Option<u32>,
    #[arg(
        long,
        value_name = "NAME",
        help = "Only trace events from this process name"
    )]
    pub comm: Option<String>,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum EventKind {
    Connect,
    Accept,
    Close,
}

impl EventKind {
    pub fn mask(self) -> u32 {
        match self {
            EventKind::Connect => FILTER_EVENT_CONNECT,
            EventKind::Accept => FILTER_EVENT_ACCEPT,
            EventKind::Close => FILTER_EVENT_CLOSE,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SyscallKind {
    Read,
    Write,
    Openat,
}

impl SyscallKind {
    pub fn name(self) -> &'static str {
        match self {
            SyscallKind::Read => "read",
            SyscallKind::Write => "write",
            SyscallKind::Openat => "openat",
        }
    }

    pub fn index(self) -> u32 {
        match self {
            SyscallKind::Read => 0,
            SyscallKind::Write => 1,
            SyscallKind::Openat => 2,
        }
    }
}

pub fn event_mask(kind: Option<EventKind>) -> u32 {
    match kind {
        Some(kind) => kind.mask(),
        None => tracelet_common::FILTER_EVENT_ALL,
    }
}

pub fn config(args: &FilterArgs, event_mask: u32) -> Result<FilterConfig, TraceletError> {
    let mut cfg = FilterConfig {
        event_mask,
        ..FilterConfig::default()
    };
    if let Some(pids) = &args.pid {
        if pids.len() > MAX_PIDS {
            return Err(TraceletError::Invalid(format!(
                "at most {MAX_PIDS} PIDs supported"
            )));
        }
        cfg.pid_count = pids.len() as u32;
        for (i, &pid) in pids.iter().enumerate() {
            cfg.pids[i] = pid;
        }
    }
    if let Some(ppid) = args.ppid {
        cfg.ppid = ppid;
        cfg.ppid_enabled = 1;
    }
    if let Some(comm) = &args.comm {
        cfg.comm = comm_bytes(comm)?;
        cfg.comm_enabled = 1;
    }
    Ok(cfg)
}

pub fn apply_map(
    map: &impl libbpf_rs::MapCore,
    config: &FilterConfig,
) -> Result<(), TraceletError> {
    let key = 0u32.to_ne_bytes();
    let val = crate::types::filter_config {
        event_mask: config.event_mask,
        pid_count: config.pid_count,
        pids: config.pids,
        ppid: config.ppid,
        ppid_enabled: config.ppid_enabled,
        comm_enabled: config.comm_enabled,
        comm: config.comm.map(|byte| byte as i8),
    };
    let bytes = unsafe {
        std::slice::from_raw_parts(
            &val as *const crate::types::filter_config as *const u8,
            std::mem::size_of::<crate::types::filter_config>(),
        )
    };
    map.update(&key, bytes, libbpf_rs::MapFlags::ANY)?;
    Ok(())
}

fn comm_bytes(comm: &str) -> Result<[u8; 16], TraceletError> {
    let bytes = comm.as_bytes();
    if bytes.is_empty() {
        return Err(TraceletError::Invalid(
            "comm filter must not be empty".into(),
        ));
    }
    if bytes.len() > COMM_MAX_LEN {
        return Err(TraceletError::Invalid(format!(
            "comm filter must be at most {COMM_MAX_LEN} bytes"
        )));
    }
    let mut out = [0u8; 16];
    out[..bytes.len()].copy_from_slice(bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{config, event_mask, EventKind, FilterArgs, SyscallKind};
    use tracelet_common::{FilterConfig, FILTER_EVENT_ALL, FILTER_EVENT_CONNECT};

    fn args(pid: Option<Vec<u32>>, ppid: Option<u32>, comm: Option<&str>) -> FilterArgs {
        FilterArgs {
            pid,
            ppid,
            comm: comm.map(str::to_string),
        }
    }

    #[test]
    fn no_filters_disables_all() {
        let cfg = config(&args(None, None, None), FILTER_EVENT_ALL).unwrap();
        assert_eq!(
            cfg,
            FilterConfig {
                event_mask: FILTER_EVENT_ALL,
                ..Default::default()
            }
        );
    }

    #[test]
    fn single_pid_filter() {
        let cfg = config(&args(Some(vec![4242]), None, None), FILTER_EVENT_ALL).unwrap();
        assert_eq!(cfg.pid_count, 1);
        assert_eq!(cfg.pids[0], 4242);
    }

    #[test]
    fn multi_pid_filter() {
        let cfg = config(&args(Some(vec![1, 2, 3]), None, None), FILTER_EVENT_ALL).unwrap();
        assert_eq!(cfg.pid_count, 3);
        assert_eq!(&cfg.pids[..3], &[1, 2, 3]);
    }

    #[test]
    fn pid_filter_rejects_too_many() {
        let many_pids: Vec<u32> = (0..=16).collect();
        assert!(config(&args(Some(many_pids), None, None), FILTER_EVENT_ALL).is_err());
    }

    #[test]
    fn ppid_filter_is_enabled_with_value() {
        let cfg = config(&args(None, Some(100), None), FILTER_EVENT_ALL).unwrap();
        assert_eq!(cfg.ppid, 100);
        assert_eq!(cfg.ppid_enabled, 1);
    }

    #[test]
    fn comm_filter_is_nul_padded() {
        let cfg = config(&args(None, None, Some("bash")), FILTER_EVENT_ALL).unwrap();
        assert_eq!(cfg.comm_enabled, 1);
        assert_eq!(&cfg.comm[..4], b"bash");
        assert_eq!(&cfg.comm[4..], &[0u8; 12]);
    }

    #[test]
    fn comm_filter_rejects_too_long_and_empty() {
        assert!(config(
            &args(None, None, Some("0123456789abcdef")),
            FILTER_EVENT_ALL
        )
        .is_err());
        assert!(config(&args(None, None, Some("")), FILTER_EVENT_ALL).is_err());
    }

    #[test]
    fn event_masks_map_to_kernel_bits() {
        assert_eq!(event_mask(None), FILTER_EVENT_ALL);
        assert_eq!(event_mask(Some(EventKind::Connect)), FILTER_EVENT_CONNECT);
        assert_eq!(event_mask(Some(EventKind::Accept)), 2);
        assert_eq!(event_mask(Some(EventKind::Close)), 4);
    }

    #[test]
    fn syscall_kind_matches_c_indices() {
        assert_eq!(SyscallKind::Read.index(), 0);
        assert_eq!(SyscallKind::Write.index(), 1);
        assert_eq!(SyscallKind::Openat.index(), 2);
    }
}
