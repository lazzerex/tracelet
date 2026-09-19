#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "tracelet.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tp/sched/sched_process_exec")
int trace_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct exec_event *ev;
    struct task_struct *task;

    ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->ktime_ns = bpf_ktime_get_ns();
    ev->pid = (__u32)ctx->pid;
    task = (struct task_struct *)bpf_get_current_task_btf();
    ev->ppid = (__u32)BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(ev->comm, sizeof(ev->comm));
    bpf_probe_read_kernel_str(ev->filename, sizeof(ev->filename),
                              (const char *)ctx + (ctx->__data_loc_filename & 0xFFFF));
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

static int submit_open(const char *fname)
{
    struct open_event *ev;

    ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev)
        return 0;
    ev->ktime_ns = bpf_ktime_get_ns();
    ev->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    bpf_get_current_comm(ev->comm, sizeof(ev->comm));
    bpf_probe_read_user_str(ev->filename, sizeof(ev->filename), fname);
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_open")
int trace_open(struct trace_event_raw_sys_enter *ctx)
{
    return submit_open((const char *)ctx->args[0]);
}

SEC("tp/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
    return submit_open((const char *)ctx->args[1]);
}

SEC("tp/syscalls/sys_enter_openat2")
int trace_openat2(struct trace_event_raw_sys_enter *ctx)
{
    return submit_open((const char *)ctx->args[1]);
}

static void submit_tcp(struct trace_event_raw_inet_sock_set_state *ctx, __u8 type)
{
    struct tcp_event *ev;

    ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev)
        return;
    ev->ktime_ns = bpf_ktime_get_ns();
    ev->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    bpf_get_current_comm(ev->comm, sizeof(ev->comm));
    ev->event_type = type;
    ev->family = (__u8)ctx->family;
    ev->sport = ctx->sport;
    ev->dport = ctx->dport;
    if (ctx->family == AF_INET) {
        __builtin_memcpy(ev->saddr, ctx->saddr, 4);
        __builtin_memcpy(ev->daddr, ctx->daddr, 4);
    } else {
        __builtin_memcpy(ev->saddr, ctx->saddr_v6, 16);
        __builtin_memcpy(ev->daddr, ctx->daddr_v6, 16);
    }
    bpf_ringbuf_submit(ev, 0);
}

SEC("tp/sock/inet_sock_set_state")
int trace_tcp(struct trace_event_raw_inet_sock_set_state *ctx)
{
    if (ctx->newstate == TCP_ESTABLISHED) {
        if (ctx->oldstate == TCP_SYN_SENT)
            submit_tcp(ctx, TCP_EVENT_CONNECT);
        else if (ctx->oldstate == TCP_SYN_RECV)
            submit_tcp(ctx, TCP_EVENT_ACCEPT);
    } else if (ctx->newstate == TCP_CLOSE) {
        submit_tcp(ctx, TCP_EVENT_CLOSE);
    }
    return 0;
}
