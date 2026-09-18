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
  bpf/               eBPF programs (C), compiled by clang -target bpf
tracelet-common/     event structs shared between eBPF and Rust
build.rs             generates the libbpf-rs skeleton at build time
```

Pipeline (later phases):

```
kernel hook (tracepoint/kprobe)
  -> eBPF program (C)
  -> BPF ring buffer
  -> Rust collector (libbpf-rs)
  -> CLI output
```

## Commands

| Command             | Purpose                      | Status        |
| ------------------- | ---------------------------- | ------------- |
| `tracelet exec`     | process execution events     | working       |
| `tracelet open`     | file open events             | placeholder   |
| `tracelet tcp`      | TCP connection events        | placeholder   |
| `tracelet latency`  | latency statistics           | placeholder   |
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
