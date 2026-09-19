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
  filter.rs          filter parsing and kernel filter configuration
  stats.rs           kernel drop counter reporting
  bpf/               eBPF programs (C), compiled by clang -target bpf
tracelet-common/     event structs, constants, and filter config shared between eBPF and Rust
bench/               workload generator and overhead measurement scripts
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

`tracelet dashboard` adds a collector thread and a TUI on top:

```
kernel hooks (exec + open + tcp)
  -> eBPF program (C), one shared ring buffer
  -> collector thread: decode, aggregate, hold bounded stream
  -> Mutex<Shared> snapshot
  -> ratatui TUI: redraw at most 1 Hz or on keypress
```

## Commands

| Command             | Purpose                      | Status        |
| ------------------- | ---------------------------- | ------------- |
| `tracelet exec`     | process execution events     | working       |
| `tracelet open`     | file open events             | working       |
| `tracelet tcp`      | TCP connection events        | working       |
| `tracelet latency`  | latency statistics           | working       |
| `tracelet top`      | live top-style view          | phase 8       |
| `tracelet dashboard`| terminal dashboard           | working       |

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
Filters are applied inside the eBPF program before the event is
created; see Filtering.

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

## Filtering

Every collector accepts `--pid <PID>` and `--comm <NAME>`; `tracelet
tcp` adds `--event <connect|accept|close>` and `tracelet latency` adds
`--syscall <read|write|openat>`.

The pid, comm, and event-type filters run inside the eBPF programs.
The collector writes a `filter_config` struct into the skeleton's
read-only data before load, and each program checks it before touching
the ring buffer, so a filtered-out event never reserves a ring buffer
slot, never crosses the kernel boundary, and never wakes the printer:

```
struct filter_config {
    __u32 pid;
    __u32 pid_enabled;
    __u32 comm_enabled;
    __u32 event_mask;
    char comm[16];
};
```

`--syscall` is different: it decides which programs are attached, so
unselected syscalls are not traced at all instead of filtered after
the fact.

The filters are fixed for the lifetime of the process because
read-only data cannot change after load. Runtime filter changes would
need a writable BPF map instead, which is the standard extension point
if this tool ever needs it.

Kernel-side vs userspace-side filtering:

- Kernel-side (used here): the check itself runs in kernel context on
  every hit event even when it rejects it. The pid check is one helper
  call and a compare; the comm check is one helper call plus an
  unrolled 16-byte comparison against `bpf_get_current_comm` output.
  No string helpers run on user data and no user pointers are read,
  so the check's cost is constant regardless of process name content.
  In exchange, rejected events cost nothing else: no ring buffer slot,
  no copy, no wakeup, no userspace scheduling. Under high event rates
  with a narrow filter, userspace stays idle and the ring buffer keeps
  space for events that matter.
- Userspace-side: the kernel program stays minimal and filters can
  change at runtime, but every event is copied across the boundary and
  wakes the collector, and the ring buffer fills with rows the tool
  throws away. At high rates that spending dwarfs the in-kernel check.

## Measuring overhead

`bench/workload.sh` generates controlled amounts of each event type:

```
./bench/workload.sh exec 50        # 50 process executions of /bin/true
./bench/workload.sh open 50        # 50 opens of /etc/hosts
./bench/workload.sh tcp 50         # 50 loopback TCP connections
```

The tcp workload starts a local python server, waits for it to accept,
opens exactly `count` connections, and verifies the server saw every
one of them, so the generated event count is known.

`bench/measure.sh` compares the workload alone against the same
workload with a collector attached:

```
cargo build --release
sudo ./bench/measure.sh exec 200 3
```

It needs the release binary and root. For each of `runs` iterations it
prints one baseline row (workload alone) and one traced row (workload
with `tracelet <kind>` attached in the background):

| Column    | Meaning                                                        |
| --------- | -------------------------------------------------------------- |
| wl_wall_s | wall time of the workload process                              |
| wl_cpu_s  | user+sys CPU of the workload                                   |
| tr_cpu_s  | user+sys CPU of the tracer, read from /proc before stopping it |
| tr_rss_mb | peak resident memory (VmHWM) of the tracer                     |
| tr_map_mb | memlock bytes charged to the tracer's BPF maps and programs    |
| events    | rows the collector printed                                     |
| ev_per_s  | events divided by workload wall time                           |
| dropped   | events dropped by the kernel, from the tracer's warning        |

The report header records the date, kernel version, CPU model, core
count, memory, clang and rustc versions, and the tracelet version;
each report is saved under `bench/results/`.

How to read the numbers: `tr_cpu_s` is the tracer's own CPU cost while
the workload runs. The workload's own `wl_cpu_s` and `wl_wall_s` rows
contain whatever the hooks add to the workload, but wall time carries
scheduling noise, which is why the script runs baseline and traced
iterations several times and why results should be compared between
rows of the same report, not against reports from other machines.
`tr_map_mb` is the kernel-side memory that stays charged while the
collector runs; the 16 MiB ring buffer dominates it, so shrinking
`max_entries` of the `events` map is the first lever if the memory
budget is tighter.

No overhead numbers are claimed here: run the script on the target
machine to produce them. Numbers are only meaningful against the
baseline rows of the same report on the same boot.

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

## Dashboard

```
sudo tracelet dashboard
```

Runs a TUI combining every event source. The eBPF side attaches all
hooks at once (exec, the three open syscalls, and TCP state changes)
and pushes everything through the single shared ring buffer. A
background collector thread decodes events, maintains the aggregates,
and keeps a bounded 512-row stream; the TUI thread takes a snapshot
under the mutex and renders it.

Panes: overview (rate, process count, totals, dropped counter),
per-syscall latency percentiles, live event stream, top processes by
event count.

Keys: `space` pause/resume, arrows scroll one row, pgup/pgdn a page,
`home` newest, `end` oldest, `tab` switch pane, `q` or `ctrl-c` quit.
Pause is display-side only: the collector keeps draining the ring
buffer and updating aggregates, so nothing is lost while paused.

### Implementation notes

- **Event tagging**: exec and open events were indistinguishable on a
  mixed stream (both 160 bytes), so both structs carry a `kind` field
  set by the BPF program; the decoder checks it before trusting the
  payload.
- **Snapshot model**: the collector mutates `Shared` under a mutex;
  `Snapshot::take` clones what it needs and the TUI drops the lock
  before rendering. The stream is newest-first and capped at 512 rows,
  so memory is bounded regardless of runtime.
- **Rate**: events-per-second is total events divided by elapsed wall
  seconds since start (a whole-run average, not a sliding window).
- **Redraw policy**: at most once per second or on keypress, whichever
  comes first; event polling runs at 100 ms.
- **Known limitation**: `home`/`end` scroll positions clamp back to
  the newest/oldest rows only as new events arrive, since the list
  re-renders newest-first on every refresh; the buffer never holds
  more than 512 rows, so scrolling stops there.
