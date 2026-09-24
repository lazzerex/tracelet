use crate::error::TraceletError;

fn tracepoints_for(collector: &str) -> Vec<&'static str> {
    match collector {
        "exec" => vec!["sched/sched_process_exec"],
        "open" => vec![
            "syscalls/sys_enter_open",
            "syscalls/sys_enter_openat",
            "syscalls/sys_enter_openat2",
        ],
        "tcp" => vec!["sock/inet_sock_set_state"],
        "latency" => vec![
            "syscalls/sys_enter_read",
            "syscalls/sys_exit_read",
            "syscalls/sys_enter_write",
            "syscalls/sys_exit_write",
            "syscalls/sys_enter_openat",
            "syscalls/sys_exit_openat",
        ],
        "dashboard" => vec![
            "sched/sched_process_exec",
            "syscalls/sys_enter_open",
            "syscalls/sys_enter_openat",
            "syscalls/sys_enter_openat2",
            "syscalls/sys_exit_openat",
            "syscalls/sys_enter_read",
            "syscalls/sys_exit_read",
            "syscalls/sys_enter_write",
            "syscalls/sys_exit_write",
            "sock/inet_sock_set_state",
        ],
        _ => vec![],
    }
}

fn find_tracefs() -> Result<String, TraceletError> {
    for dir in ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"] {
        if std::path::Path::new(dir).join("events").exists() {
            return Ok(dir.to_string());
        }
    }
    Err(TraceletError::Bpf(
        "tracefs not found; needed for tracepoint validation".into(),
    ))
}

pub fn check_prereqs(collector: &str) -> Result<(), TraceletError> {
    if !std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
        return Err(TraceletError::Bpf(
            "kernel BTF required at /sys/kernel/btf/vmlinux (Linux 5.4+ with CONFIG_DEBUG_INFO_BTF)"
                .into(),
        ));
    }

    let tracefs = find_tracefs()?;
    let tracepoints = tracepoints_for(collector);
    let mut missing = Vec::new();
    for tp in &tracepoints {
        let path = format!("{tracefs}/events/{tp}");
        if !std::path::Path::new(&path).exists() {
            missing.push(*tp);
        }
    }
    if !missing.is_empty() {
        return Err(TraceletError::Bpf(format!(
            "missing tracepoints: {}; kernel may be too old",
            missing.join(", ")
        )));
    }
    Ok(())
}
