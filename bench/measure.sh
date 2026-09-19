#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: $0 <exec|open|tcp> <count> [runs]" >&2
    exit 2
}

[ "$#" -ge 2 ] || usage
kind=$1
count=$2
runs=${3:-3}
case $kind in
exec | open | tcp) ;;
*) usage ;;
esac
case $count in
'' | *[!0-9]*) usage ;;
esac
case $runs in
'' | *[!0-9]*) usage ;;
esac
[ "$count" -gt 0 ] || usage
[ "$runs" -gt 0 ] || usage

if [ "$(id -u)" -ne 0 ]; then
    echo "measure.sh must run as root: loading eBPF needs CAP_BPF or CAP_SYS_ADMIN" >&2
    exit 1
fi

root=$(cd "$(dirname "$0")/.." && pwd)
binary=$root/target/release/tracelet
workload=$root/bench/workload.sh
results_dir=$root/bench/results

[ -x "$binary" ] || {
    echo "release binary missing, run: cargo build --release" >&2
    exit 1
}

mkdir -p "$results_dir"
report=$results_dir/${kind}-${count}-$(date +%Y%m%d-%H%M%S).txt
out=$(mktemp)
err=$(mktemp)
trap 'rm -f "$out" "$err"' EXIT

TIMEFORMAT='%3R %3U %3S'

env_report() {
    echo "date: $(date -Is)"
    echo "kernel: $(uname -r)"
    echo "cpu: $(awk -F: '/model name/ {print $2; exit}' /proc/cpuinfo | sed 's/^ //')"
    echo "cpus: $(nproc)"
    echo "memory: $(awk '/MemTotal/ {print $2" "$3; exit}' /proc/meminfo)"
    echo "clang: $(clang --version | head -1)"
    echo "rustc: $(rustc --version)"
    echo "tracelet: $("$binary" --version)"
}

baseline_run() {
    local timing
    timing=$({ time "$workload" "$kind" "$count" >/dev/null; } 2>&1)
    echo "$timing" | tail -1
}

cpu_seconds() {
    local pid=$1 ticks
    ticks=$(awk '{ n = split($0, a, ") "); split(a[2], f, " "); print f[12] + f[13] }' "/proc/$pid/stat")
    awk -v t="$ticks" -v hz="$(getconf CLK_TCK)" 'BEGIN { printf "%.3f", t / hz }'
}

peak_rss_kb() {
    awk '/VmHWM/ {print $2; exit}' "/proc/$1/status"
}

memlock_bytes() {
    grep -h '^memlock:' "/proc/$1"/fdinfo/* 2>/dev/null | awk '{s += $2} END {print s + 0}' || true
}

traced_run() {
    local pid t0 t1
    "$binary" "$kind" >"$out" 2>"$err" &
    pid=$!
    sleep 1
    t0=$(date +%s.%N)
    "$workload" "$kind" "$count" >/dev/null
    t1=$(date +%s.%N)
    sleep 0.5
    tracelet_cpu=$(cpu_seconds "$pid")
    tracelet_rss=$(peak_rss_kb "$pid")
    tracelet_memlock=$(memlock_bytes "$pid")
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    workload_wall=$(awk -v a="$t0" -v b="$t1" 'BEGIN { printf "%.3f", b - a }')
    events=$(awk 'END { print (NR > 0 ? NR - 1 : 0) }' "$out")
    drops=$(grep -o '[0-9]* events dropped' "$err" | tail -1 | awk '{print $1}' || true)
    drops=${drops:-0}
    throughput=$(awk -v e="$events" -v w="$workload_wall" 'BEGIN { printf "%.0f", (w > 0 ? e / w : 0) }')
}

{
    echo "tracelet benchmark"
    echo "kind: $kind"
    echo "count: $count"
    echo "runs: $runs"
    echo "workload: $workload $kind $count"
    echo "tracer: $binary $kind"
    echo "environment:"
    env_report
    echo
    echo "method: baseline workload runs alone, traced workload runs with the tracer"
    echo "attached in the background. workload_wall is measured around the workload"
    echo "process; tracelet_cpu is utime+stime of the tracer process read just before"
    echo "it is stopped; rss is VmHWM; memlock is the sum of BPF object memlock from"
    echo "the tracer fdinfo; events are printed output rows; throughput is"
    echo "events/workload_wall; drops come from the tracer drop warnings."
    echo
    printf '%-4s %-14s %-14s %-12s %-12s %-12s %-10s %-8s %-8s\n' \
        run wl_wall_s wl_cpu_s tr_cpu_s tr_rss_mb tr_map_mb events ev_per_s dropped
} | tee "$report"

for run in $(seq 1 "$runs"); do
    read -r wl_wall wl_cpu wl_sys <<<"$(baseline_run)"
    printf '%-4s %-14s %-14s %-12s %-12s %-12s %-10s %-8s %-8s\n' \
        "b$run" "$wl_wall" "$(awk -v u="$wl_cpu" -v s="$wl_sys" 'BEGIN { printf "%.3f", u + s }')" \
        - - - - - - | tee -a "$report"
done

for run in $(seq 1 "$runs"); do
    tracelet_cpu=0 tracelet_rss=0 tracelet_memlock=0 workload_wall=0 events=0 drops=0 throughput=0
    traced_run
    printf '%-4s %-14s %-14s %-12s %-12s %-12s %-10s %-8s %-8s\n' \
        "t$run" "$workload_wall" - "$tracelet_cpu" \
        "$(awk -v k="$tracelet_rss" 'BEGIN { printf "%.1f", k / 1024 }')" \
        "$(awk -v b="$tracelet_memlock" 'BEGIN { printf "%.2f", b / 1048576 }')" \
        "$events" "$throughput" "$drops" | tee -a "$report"
done

echo
echo "raw results: $report"