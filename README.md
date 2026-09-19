# Tracelet

Tracelet is an educational Linux observability tool that watches kernel and
system activity using Rust in userspace and C/eBPF for kernel-side
instrumentation.

## Why Rust + C/eBPF?

Kernel tracing needs code that runs inside the Linux kernel with strict safety
rules: eBPF programs are verified before loading, cannot crash the kernel, and
can attach to tracepoints, kprobes, and other hooks. The Linux toolchain for
this (clang, libbpf) is C-based, so kernel-side programs are written in C.

Rust handles the userspace side: loading eBPF objects via libbpf-rs, reading
events from BPF ring buffers, decoding them, and rendering output. Rust gives
memory safety, expressive types, and a modern CLI ecosystem (clap) without a
garbage collector, which matters for tools that process high event rates.

The split also follows the trust boundary: the kernel side is small, fixed, and
verified; everything flexible lives in userspace where bugs are ordinary
crashes instead of kernel panics.

## Architecture

```
src/
  main.rs            CLI entry point (clap)
  error.rs           error types
  events.rs          event decoding and time formatting
  exec.rs            exec collector
  open.rs            open collector
  tcp.rs             tcp collector
  latency.rs         latency collector
  hist.rs            histogram to percentile math
  bpf/               eBPF programs (C), compiled by clang -target bpf
tracelet-common/     event structs and constants shared between eBPF and Rust
build.rs             generates the libbpf-rs skeleton at build time
```

Pipeline:

```
kernel hook (tracepoint/kprobe)
  -> eBPF program (C)
  -> BPF ring buffer
  -> Rust collector (libbpf-rs)
  -> CLI output
```

`tracelet latency` replaces the ring buffer with BPF maps and moves
aggregation into the kernel:

```
kernel hook (tracepoint)
  -> eBPF program (C)
  -> BPF maps (histogram counters)
  -> Rust reads counters
  -> CLI output
```

## Commands

| Command             | Purpose                      | Status        |
| ------------------- | ---------------------------- | ------------- |
| `tracelet exec`     | process execution events     | working       |
| `tracelet open`     | file open events             | working       |
| `tracelet tcp`      | TCP connection events        | working       |
| `tracelet latency`  | latency statistics           | working       |
| `tracelet top`      | live top-style view          | placeholder   |
| `tracelet dashboard`| terminal dashboard           | placeholder   |

## How exec tracing works

`tracelet exec` attaches an eBPF program to the `sched_process_exec`
tracepoint, which fires in the kernel every time a process calls
`execve()`. The program reserves space in a BPF ring buffer, fills it
with a compact event (monotonic timestamp, PID, parent PID, process
name, executable path read from the tracepoint's data-loc argument),
and submits it. The Rust side polls the ring buffer with libbpf-rs,
decodes the fixed-size struct, and prints one line per exec.

## How open tracing works

`tracelet open` attaches eBPF programs to the `sys_enter_open`,
`sys_enter_openat`, and `sys_enter_openat2` syscall tracepoints,
covering every open variant. The programs share one helper that
reserves an event in the same ring buffer used by exec tracing, and
copy the filename with `bpf_probe_read_user_str` because the path is
a userspace pointer at syscall entry. The filename is whatever the
caller passed (relative paths stay relative); the syscall may still
fail afterwards, so events are attempts, not successful opens.
`--pid <PID>` filters in userspace after decode.

Manual test for `tracelet open`:

```
sudo tracelet open                    # terminal 1
cat /etc/hosts                        # terminal 2
sudo tracelet open --pid $$           # only one shell's opens
touch /tmp/x
```

## How tcp tracing works

`tracelet tcp` attaches to the `sock:inet_sock_set_state` tracepoint,
which fires whenever the kernel changes a TCP socket's state. Only
three transitions are reported:

| Transition                        | Reported as |
| --------------------------------- | ----------- |
| `SYN_SENT` -> `ESTABLISHED`        | CONNECT     |
| `SYN_RECV` -> `ESTABLISHED`        | ACCEPT      |
| any -> `CLOSE`                     | CLOSE       |

The event carries the timestamp, PID, process name, address family,
source and destination address and port. Addresses come from the
socket's own fields (`inet_saddr`/`inet_daddr` for IPv4,
`inet6_saddr`/`inet6_daddr` for IPv6), so no packet inspection is
involved: this is connection metadata taken straight from the socket
state machine.

Manual test for `tracelet tcp`:

```
sudo tracelet tcp                          # terminal 1
curl -s https://example.com > /dev/null    # terminal 2 -> CONNECT
python3 -m http.server 8080                # terminal 3
curl -s http://localhost:8080 > /dev/null  # -> CONNECT
                                           #   ACCEPT + CLOSE on the server side
```

## How latency works

`tracelet latency` measures how long three syscalls (`read`, `write`,
`openat`) spend inside the kernel. Unlike the other commands it does
not use the ring buffer at all: aggregation happens in the kernel.

On `sys_enter_*` the program stores `bpf_ktime_get_ns()` (monotonic)
in a hash map keyed by thread id. On the matching `sys_exit_*` it
looks the timestamp up, deletes the entry, and adds one to a log2
histogram bucket for that syscall in a BPF array map. Userspace only
reads the counters, so no per-event data crosses the kernel boundary.

```
syscall:  read = 0   write = 1   openat = 2
hist map: array, 3 * 32 = 96 slots, 8 bytes each
start map: hash, max 10240 threads, 8 bytes each
```

Each printed value is the upper bound of the bucket where the
cumulative count reached the requested percentile.

Manual test for `tracelet latency`:

```
sudo tracelet latency                    # terminal 1
cat /etc/hosts > /dev/null               # terminal 2 -> read/openat counts rise
dd if=/dev/zero of=/dev/null bs=1M count=200   # write/read counts rise
```

### What is measured, and what is not

The delta is the time between two tracepoints in kernel context. It
includes time the task spent blocked or scheduled out inside the
syscall, and excludes all userspace time before the syscall and after
it returned. It is therefore kernel service time for a syscall, not
application-level latency, and not a wall-clock round trip.

Known limitations:

- Percentiles come from log2 buckets, so a reported value is the upper
  bound of a power-of-two range, not an exact measurement. Resolution
  is coarse for slow operations (e.g. 2.1s is reported as 4.29s).
- The last bucket is an overflow bucket: everything at or above 2^32 ns
  (about 4.29s) lands in it.
- Samples are correlated per thread. A thread that re-enters the same
  syscall overwrites its start timestamp, and a syscall that returns
  after the tracepoint is detached leaves a stale entry behind. Stale
  entries are bounded by the start map size.
- If the start map is full, new samples are silently not recorded. The
  histogram counts only paired enter/exit events.
- Counters are global across all processes and threads; there is no
  per-process breakdown, which is what keeps memory bounded.
- Counters are cumulative since the command started, and a snapshot is
  printed once per second.

## Building

Requirements: Rust (cargo), clang, libelf headers, bpftool.

`cargo build` compiles the eBPF C programs in `src/bpf` with clang
(via libbpf-cargo), generates the libbpf-rs skeleton, and builds the binary.

```
cargo build
cargo test
```

## Usage

```
sudo tracelet exec
```

Most commands need root privileges to attach eBPF programs.

Manual test for `tracelet exec`: run it in one terminal, then in another:

```
ls
sleep 1
python3 -c "pass"
bash -c "exit"
```

Each command prints one line with its timestamp, PID, PPID, process
name and executable path.
