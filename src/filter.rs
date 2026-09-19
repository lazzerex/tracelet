use clap::{Args, ValueEnum};
use tracelet_common::{
    FilterConfig, COMM_MAX_LEN, FILTER_EVENT_ACCEPT, FILTER_EVENT_CLOSE, FILTER_EVENT_CONNECT,
};

use crate::error::TraceletError;

#[derive(Args, Clone, Default)]
pub struct FilterArgs {
    #[arg(long, help = "Only trace events from this PID")]
    pub pid: Option<u32>,
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
    let mut config = FilterConfig {
        event_mask,
        ..FilterConfig::default()
    };
    if let Some(pid) = args.pid {
        config.pid = pid;
        config.pid_enabled = 1;
    }
    if let Some(comm) = &args.comm {
        config.comm = comm_bytes(comm)?;
        config.comm_enabled = 1;
    }
    Ok(config)
}

pub fn apply(dst: &mut crate::types::filter_config, config: &FilterConfig) {
    dst.pid = config.pid;
    dst.pid_enabled = config.pid_enabled;
    dst.comm_enabled = config.comm_enabled;
    dst.event_mask = config.event_mask;
    dst.comm = config.comm.map(|byte| byte as i8);
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
    use super::{comm_bytes, config, event_mask, EventKind, FilterArgs, SyscallKind};
    use tracelet_common::{FilterConfig, FILTER_EVENT_ALL, FILTER_EVENT_CONNECT};

    fn args(pid: Option<u32>, comm: Option<&str>) -> FilterArgs {
        FilterArgs {
            pid,
            comm: comm.map(str::to_string),
        }
    }

    #[test]
    fn no_filters_disables_both() {
        let cfg = config(&args(None, None), FILTER_EVENT_ALL).unwrap();
        assert_eq!(
            cfg,
            FilterConfig {
                event_mask: FILTER_EVENT_ALL,
                ..Default::default()
            }
        );
    }

    #[test]
    fn pid_filter_is_enabled_with_value() {
        let cfg = config(&args(Some(4242), None), FILTER_EVENT_ALL).unwrap();
        assert_eq!(cfg.pid, 4242);
        assert_eq!(cfg.pid_enabled, 1);
        assert_eq!(cfg.comm_enabled, 0);
    }

    #[test]
    fn comm_filter_is_nul_padded() {
        let cfg = config(&args(None, Some("bash")), FILTER_EVENT_ALL).unwrap();
        assert_eq!(cfg.comm_enabled, 1);
        assert_eq!(&cfg.comm[..4], b"bash");
        assert_eq!(&cfg.comm[4..], &[0u8; 12]);
    }

    #[test]
    fn comm_filter_accepts_max_length() {
        let cfg = config(&args(None, Some("0123456789abcde")), FILTER_EVENT_ALL).unwrap();
        assert_eq!(cfg.comm, *b"0123456789abcde\0");
    }

    #[test]
    fn comm_filter_rejects_too_long_and_empty() {
        assert!(config(&args(None, Some("0123456789abcdef")), FILTER_EVENT_ALL).is_err());
        assert!(config(&args(None, Some("")), FILTER_EVENT_ALL).is_err());
    }

    #[test]
    fn comm_bytes_pads_to_sixteen() {
        let bytes = comm_bytes("ls").unwrap();
        assert_eq!(bytes.len(), 16);
        assert_eq!(&bytes[..2], b"ls");
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
        assert_eq!(SyscallKind::Openat.name(), "openat");
    }
}
