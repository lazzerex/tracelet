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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, __u64);
} latency_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, SYSCALL_COUNT * HIST_SLOTS);
    __type(key, __u32);
    __type(value, __u64);
} latency_hist SEC(".maps");

static __always_inline __u32 log2_slot(__u64 v)
{
    __u32 r = 0;

    if (v >> 32) {
        r += 32;
        v >>= 32;
    }
    if (v >> 16) {
        r += 16;
        v >>= 16;
    }
    if (v >> 8) {
        r += 8;
        v >>= 8;
    }
    if (v >> 4) {
        r += 4;
        v >>= 4;
    }
    if (v >> 2) {
        r += 2;
        v >>= 2;
    }
    if (v >> 1)
        r += 1;
    return r;
}

static __always_inline int syscall_enter(void)
{
    __u64 key = bpf_get_current_pid_tgid();
    __u64 ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&latency_start, &key, &ts, BPF_ANY);
    return 0;
}

static __always_inline int syscall_exit(__u32 syscall)
{
    __u64 key = bpf_get_current_pid_tgid();
    __u64 *start = bpf_map_lookup_elem(&latency_start, &key);
    __u64 delta, *count;
    __u32 slot, idx;

    if (!start)
        return 0;
    delta = bpf_ktime_get_ns() - *start;
    bpf_map_delete_elem(&latency_start, &key);

    slot = log2_slot(delta);
    if (slot >= HIST_SLOTS)
        slot = HIST_SLOTS - 1;
    idx = syscall * HIST_SLOTS + slot;
    count = bpf_map_lookup_elem(&latency_hist, &idx);
    if (count)
        __sync_fetch_and_add(count, 1);
    return 0;
}

SEC("tp/syscalls/sys_enter_read")
int trace_read_enter(void *ctx)
{
    return syscall_enter();
}

SEC("tp/syscalls/sys_exit_read")
int trace_read_exit(void *ctx)
{
    return syscall_exit(SYSCALL_READ);
}

SEC("tp/syscalls/sys_enter_write")
int trace_write_enter(void *ctx)
{
    return syscall_enter();
}

SEC("tp/syscalls/sys_exit_write")
int trace_write_exit(void *ctx)
{
    return syscall_exit(SYSCALL_WRITE);
}

SEC("tp/syscalls/sys_enter_openat")
int trace_openat_enter(void *ctx)
{
    return syscall_enter();
}

SEC("tp/syscalls/sys_exit_openat")
int trace_openat_exit(void *ctx)
{
    return syscall_exit(SYSCALL_OPENAT);
}
