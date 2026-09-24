<h1 align="center">Tracelet</h1>

<p align="center">
  <strong>Linux observability in Rust + eBPF</strong><br />
  Watch kernel and system activity, from process execution and file opens
  to TCP connections and latency, through a CLI or live TUI dashboard.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Rust-2021-CE412B?logo=rust&logoColor=white" alt="Rust 2021" />
  <img src="https://img.shields.io/badge/eBPF-C-49B34D?logo=ebpf&logoColor=white" alt="eBPF (C)" />
  <img src="https://img.shields.io/badge/libbpf-1.x-333333?logo=linux&logoColor=white" alt="libbpf" />
  <img src="https://img.shields.io/badge/clap-4.x-FF6C37?logo=clap&logoColor=white" alt="clap 4" />
  <img src="https://img.shields.io/badge/ratatui-0.29-DC4A30?logo=ratatui&logoColor=white" alt="ratatui" />
  <img src="https://img.shields.io/badge/Platform-Linux%20x86__64-FCC624?logo=linux&logoColor=black" alt="Linux x86_64" />
</p>

<p align="center">
  <a href="https://github.com/lazzerex/tracelet/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/lazzerex/tracelet/ci.yml?label=CI&logo=githubactions&logoColor=white" alt="CI Status" /></a>
  <a href="https://github.com/lazzerex/tracelet/releases/latest"><img src="https://img.shields.io/github/v/release/lazzerex/tracelet?label=release&logo=github" alt="Latest Release" /></a>
  <a href="https://github.com/lazzerex/tracelet/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License: MIT" /></a>
</p>

<p align="center">
  <a href="#tech-stack">Tech Stack</a> ·
  <a href="#commands">Commands</a> ·
  <a href="#filtering">Filtering</a> ·
  <a href="#building">Building</a> ·
  <a href="#running">Running</a> ·
  <a href="#installation">Installation</a>
</p>

---

## Contents

| | |
|---|---|
| [**Tech Stack**](#tech-stack) | [**Commands**](#commands) |
| [**Why Rust + C/eBPF?**](#why-rust--cebpf) | [**Filtering**](#filtering) |
| [**Architecture**](#architecture) | [**Measuring Overhead**](#measuring-overhead) |
| [**Exec Tracing**](#how-exec-tracing-works) | [**Building**](#building) |
| [**Open Tracing**](#how-open-tracing-works) | [**Running**](#running) |
| [**TCP Tracing**](#how-tcp-tracing-works) | [**Dashboard**](#dashboard) |
| [**Latency**](#how-latency-works) | [**Installation**](#installation) |

---

## Tech Stack

| Layer | Technology | Role |
|-------|-----------|------|
| Kernel | **eBPF** (C) | Tracepoints and kprobes for zero-overhead event collection |
| Build | **libbpf-cargo** / **clang** | Compiles eBPF C → BPF bytecode, generates Rust skeleton |
| Userspace | **Rust** (libbpf-rs) | Loads BPF objects, polls ring buffers, decodes events |
| CLI | **clap** | Argument parsing and subcommand dispatch |
| TUI | **ratatui** + **crossterm** | Real-time terminal dashboard with streaming event view |
| Types | **tracelet-common** | Shared event structs and filter config between eBPF and Rust |

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
  collector.rs       dashboard collector thread and shared state
  dashboard.rs       ratatui dashboard
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
Linux activity (exec, open, TCP state change, syscall)
  -> kernel hook (tracepoint)
  -> eBPF program (C): filter, build fixed-size event
  -> BPF ring buffer (events) or BPF maps (latency counters)
  -> Rust collector (libbpf-rs): poll, size-check, decode, validate
  -> aggregation (latency percentiles / dashboard counters)
  -> CLI stdout or ratatui TUI
```

`tracelet exec`, `open`, and `tcp` all follow this shape:

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
| `tracelet top`      | live top-style view          | not implemented (use `dashboard`) |
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

Every collector accepts `--pid <PID>` (repeatable, up to 16) and
`--comm <NAME>`; `tracelet tcp` adds `--ppid <PID>` for parent-PID
filtering and `--event <connect|accept|close>`; `tracelet latency`
adds `--syscall <read|write|openat>`.

The pid, ppid, comm, and event-type filters run inside the eBPF
programs. After loading, the collector writes a `filter_config` struct
into the `filter_map` BPF array, and each program checks it before
touching the ring buffer, so a filtered-out event never reserves a ring
buffer slot, never crosses the kernel boundary, and never wakes the
printer:

```
struct filter_config {
    __u32 event_mask;
    __u32 pid_count;
    __u32 pids[16];
    __u32 ppid;
    __u32 ppid_enabled;
    __u32 comm_enabled;
    char  comm[16];
};
```

Because the config lives in a `BPF_MAP_TYPE_ARRAY` (not read-only
data), it can be updated at runtime without reloading the program —
useful for changing filters between events in long-running sessions.

`--syscall` is different: it decides which programs are attached, so
unselected syscalls are not traced at all instead of filtered after
the fact.

Kernel-side vs userspace-side filtering:

- Kernel-side (used here): the check itself runs in kernel context on
  every hit event even when it rejects it. The multi-pid check uses a
  `#pragma unroll` loop over up to 16 PIDs; the ppid check reads
  `task->real_parent->tgid`; the comm check is one helper call plus
  an unrolled 16-byte comparison against `bpf_get_current_comm` output.
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

Requirements: Rust (cargo), clang, libelf headers, bpftool. Kernel 5.8
or newer for BPF ring buffers (5.10+ with BTF is the tested target; the
load fails with the verifier's message on anything older).

`cargo build` compiles the eBPF C programs in `src/bpf` with clang
(via libbpf-cargo), generates the libbpf-rs skeleton, and builds the binary.

```
cargo build
cargo test
```

### Regenerating vmlinux.h

`src/bpf/vmlinux.h` is auto-generated and checked into the repository so that
builds are reproducible without the exact kernel headers.  You should **not**
hand-edit this file.

If the eBPF programs reference a struct or field that is missing from the
committed copy, regenerate it from your running kernel:

```
bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
```

Commit the updated file alongside your eBPF changes.  The committed baseline
is kernel **7.0.0-31-generic**.

## Running

Loading eBPF programs needs `CAP_BPF`, `CAP_PERFMON`, and access to
`/sys/kernel/tracing` (raise `RLIMIT_MEMLOCK` on kernels before 5.11).
Running as root covers all of this; on unprivileged systems the load
fails with the libbpf error (`EACCES`/`EPERM`) instead of a partial run.

## Verifying

`bench/check.sh` runs the whole verification pass in one command.

```
./bench/check.sh                  # environment, build, tests, CLI (no root)
sudo ./bench/check.sh --no-build  # adds the live eBPF checks
./bench/check.sh --release        # check the release profile instead
```

The unprivileged pass checks the platform, kernel BTF, required tools and
tracepoints, builds the project, runs the test suite, and exercises the CLI
surface (every subcommand, the enum values for `--event`/`--syscall`, and
that unknown subcommands are rejected). The root pass additionally starts
each collector, drives `bench/workload.sh` against it, and asserts what was
actually captured: `exec` and `open` event counts, `tcp` CONNECT/ACCEPT
pairs, a non-zero `latency` read count, that `--comm` filtering drops every
non-matching event in the kernel, and that the dashboard renders its panes
with a live collector.

If a collector cannot start (no permission, missing tracepoint, verifier
rejection), the check prints the captured log so the real error is visible
instead of a bare timeout. `--no-build` skips cargo so running the script
under sudo does not create root-owned files in `target/`. Logs are kept
automatically whenever something fails, and the exit status is non-zero if
any check failed.

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

## Installation

Download the latest release from the [GitHub Releases page](https://github.com/lazzerex/tracelet/releases/latest):

```bash
# download and extract (replace VERSION with the latest tag)
curl -LO https://github.com/lazzerex/tracelet/releases/latest/download/tracelet-VERSION-linux-x86_64.tar.gz
tar -xzf tracelet-VERSION-linux-x86_64.tar.gz

# verify checksum
sha256sum -c tracelet-VERSION-linux-x86_64.tar.gz.sha256

# move to PATH
sudo mv tracelet-VERSION-linux-x86_64/tracelet /usr/local/bin/
```

Tracelet requires Linux x86_64 with kernel ≥ 5.8 (BTF + tracepoint support).
