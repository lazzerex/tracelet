#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

PASSED=0
FAILED=0
SKIPPED=0
TRACER_PID=""
LOGS=$(mktemp -d "${TMPDIR:-/tmp}/tracelet-check.XXXXXX")

BUILD=1
PROFILE=debug
KEEP=0

usage() {
    echo "usage: $0 [--no-build] [--release] [--keep-logs]" >&2
    echo "  --no-build   skip cargo build and cargo test (use with sudo)" >&2
    echo "  --release    build and check the release profile" >&2
    echo "  --keep-logs  keep the captured tracer logs" >&2
    exit 2
}

for arg in "$@"; do
    case $arg in
        --no-build) BUILD=0 ;;
        --release) PROFILE=release ;;
        --keep-logs) KEEP=1 ;;
        -h | --help) usage ;;
        *) usage ;;
    esac
done

for dir in "${HOME:-/root}/.cargo/bin" "/home/${SUDO_USER:-}/.cargo/bin"; do
    if [ -d "$dir" ]; then
        PATH="$dir:$PATH"
    fi
done
export PATH

cleanup() {
    if [ -n "$TRACER_PID" ]; then
        kill -TERM "$TRACER_PID" 2>/dev/null || true
        wait "$TRACER_PID" 2>/dev/null || true
    fi
    if [ "$KEEP" -eq 1 ] || [ "$FAILED" -gt 0 ]; then
        echo "logs kept in $LOGS"
    else
        rm -rf "$LOGS"
    fi
}
trap cleanup EXIT INT TERM

section() { printf '\n== %s ==\n' "$1"; }
pass() { PASSED=$((PASSED + 1)); printf '  [PASS] %s\n' "$1"; }
fail() { FAILED=$((FAILED + 1)); printf '  [FAIL] %s\n' "$1"; }
skip() { SKIPPED=$((SKIPPED + 1)); printf '  [SKIP] %s\n' "$1"; }
note() { printf '  [note] %s\n' "$1"; }

sanitize_log() {
    sed -e 's/\x1b\[[0-9;?]*[a-zA-Z]//g' -e 's/\x1b[()][A-Za-z0-9]//g' -e 's/\x1b[=>]//g' | cat -v
}

show_log() {
    if [ -s "$1" ]; then
        printf '         --- %s (first lines, escapes stripped) ---\n' "$1"
        head -6 "$1" | sanitize_log | sed 's/^/         /'
        if [ "$(wc -l <"$1")" -gt 12 ]; then
            printf '         --- %s (last lines) ---\n' "$1"
            tail -14 "$1" | sanitize_log | sed 's/^/         /'
        fi
        if grep -q 'BPF program load failed' "$1" 2>/dev/null; then
            printf '         note: one rejected program fails the whole object, so every collector\n'
            printf '         note: reports the same error. The verifier reason is at the END of the\n'
            printf '         note: log above; also check: sudo dmesg | tail -20\n'
        fi
    else
        printf '         --- %s (empty) ---\n' "$1"
    fi
}

tracefs() {
    local d
    for d in /sys/kernel/tracing /sys/kernel/debug/tracing; do
        if [ -d "$d/events" ]; then
            printf '%s' "$d"
            return 0
        fi
    done
    printf '%s' /sys/kernel/tracing
}

start_tracer() {
    local log=$1
    shift
    "$BIN" "$@" >"$log" 2>&1 &
    TRACER_PID=$!
}

stop_tracer() {
    if [ -n "$TRACER_PID" ]; then
        kill -TERM "$TRACER_PID" 2>/dev/null || true
        wait "$TRACER_PID" 2>/dev/null || true
        TRACER_PID=""
    fi
}

wait_for_line() {
    local log=$1 pattern=$2 i=0
    while [ "$i" -lt 100 ]; do
        if grep -q -- "$pattern" "$log" 2>/dev/null; then
            return 0
        fi
        if [ -n "$TRACER_PID" ] && ! kill -0 "$TRACER_PID" 2>/dev/null; then
            return 1
        fi
        sleep 0.1
        i=$((i + 1))
    done
    return 1
}

count_lines() {
    local n
    n=$(grep -c -- "$2" "$1" 2>/dev/null || true)
    printf '%s' "${n:-0}"
}

check_exec() {
    local log="$LOGS/exec.log" n
    start_tracer "$log" exec
    if ! wait_for_line "$log" '^TIME'; then
        fail "exec: BPF program did not start"
        show_log "$log"
        stop_tracer
        return
    fi
    pass "exec: attached"
    ./bench/workload.sh exec 20 >/dev/null
    sleep 0.5
    stop_tracer
    n=$(count_lines "$log" '/bin/true')
    if [ "$n" -ge 20 ]; then
        pass "exec: captured $n /bin/true events"
    else
        fail "exec: captured $n of 20 events"
        show_log "$log"
    fi
}

check_open() {
    local log="$LOGS/open.log" n
    start_tracer "$log" open
    if ! wait_for_line "$log" '^TIME'; then
        fail "open: BPF program did not start"
        show_log "$log"
        stop_tracer
        return
    fi
    pass "open: attached"
    ./bench/workload.sh open 20 >/dev/null
    sleep 0.5
    stop_tracer
    n=$(count_lines "$log" '/etc/hosts')
    if [ "$n" -ge 20 ]; then
        pass "open: captured $n /etc/hosts events"
    else
        fail "open: captured $n of 20 events"
        show_log "$log"
    fi
}

check_tcp() {
    local log="$LOGS/tcp.log" connect accept
    start_tracer "$log" tcp
    if ! wait_for_line "$log" '^TIME'; then
        fail "tcp: BPF program did not start"
        show_log "$log"
        stop_tracer
        return
    fi
    pass "tcp: attached"
    ./bench/workload.sh tcp 10 >/dev/null
    sleep 0.5
    stop_tracer
    connect=$(count_lines "$log" ' CONNECT')
    accept=$(count_lines "$log" ' ACCEPT')
    if [ "$connect" -ge 10 ] && [ "$accept" -ge 10 ]; then
        pass "tcp: $connect CONNECT, $accept ACCEPT"
    else
        fail "tcp: $connect CONNECT, $accept ACCEPT (expected >= 10 each)"
        show_log "$log"
    fi
}

check_latency() {
    local log="$LOGS/latency.log" reads
    start_tracer "$log" latency
    if ! wait_for_line "$log" '^SYSCALL'; then
        fail "latency: BPF program did not start"
        show_log "$log"
        stop_tracer
        return
    fi
    pass "latency: attached"
    dd if=/dev/zero of=/dev/null bs=1M count=32 status=none
    ls /etc >/dev/null
    sleep 1.2
    stop_tracer
    reads=$(awk '/^SYSCALL/ {grab=1; next} grab && $1 == "read" {print $2; exit}' "$log")
    reads=${reads:-0}
    if [ "$reads" -gt 0 ]; then
        pass "latency: read count $reads"
    else
        fail "latency: read count 0"
        show_log "$log"
    fi
}

check_filter() {
    local log="$LOGS/filter.log" n
    start_tracer "$log" open --comm zz-no-such-proc
    if ! wait_for_line "$log" '^TIME'; then
        fail "filter: BPF program did not start"
        show_log "$log"
        stop_tracer
        return
    fi
    pass "filter: attached with --comm zz-no-such-proc"
    ./bench/workload.sh open 10 >/dev/null
    sleep 0.5
    stop_tracer
    n=$(count_lines "$log" '/etc/hosts')
    if [ "$n" -eq 0 ]; then
        pass "filter: kernel dropped all non-matching events"
    else
        fail "filter: $n events leaked past --comm"
        show_log "$log"
    fi
}

check_dashboard() {
    local log="$LOGS/dashboard.log"
    if ! command -v script >/dev/null 2>&1 || ! command -v stty >/dev/null 2>&1; then
        skip "dashboard: 'script'/'stty' unavailable for a pty"
        return
    fi
    script -qec "stty rows 30 cols 100; timeout 8 $BIN dashboard" /dev/null < /dev/null >"$log" 2>&1 || true
    for fragment in overview processes pause; do
        if ! grep -q -- "$fragment" "$log" 2>/dev/null; then
            fail "dashboard: pane text '$fragment' missing"
            show_log "$log"
            return
        fi
    done
    if grep -q 'collector stopped' "$log" 2>/dev/null; then
        fail "dashboard: panes rendered but the collector failed"
        show_log "$log"
        return
    fi
    pass "dashboard: panes rendered and collector attached"
}

section "environment"

if [ "$(uname -s)" = Linux ]; then
    pass "platform: $(uname -s) $(uname -r)"
else
    fail "platform: $(uname -s) (tracelet is Linux only)"
fi

if [ -e /sys/kernel/btf/vmlinux ]; then
    pass "kernel BTF available"
else
    fail "kernel BTF missing at /sys/kernel/btf/vmlinux"
fi

for tool in cargo clang pkg-config; do
    if command -v "$tool" >/dev/null 2>&1; then
        pass "tool: $tool"
    else
        fail "tool missing: $tool"
    fi
done

for tool in bpftool script timeout dd; do
    if command -v "$tool" >/dev/null 2>&1; then
        pass "tool: $tool"
    else
        skip "tool missing: $tool (optional)"
    fi
done

TRACEFS=$(tracefs)
if [ -r "$TRACEFS/events" ]; then
    for event in sched/sched_process_exec syscalls/sys_enter_open syscalls/sys_enter_openat syscalls/sys_enter_openat2 sock/inet_sock_set_state; do
        if [ -e "$TRACEFS/events/$event" ]; then
            pass "tracepoint: $event"
        else
            fail "tracepoint missing: $event"
        fi
    done
else
    note "tracefs ($TRACEFS) is root-only here: tracepoints verified by the live checks"
fi

if [ "$PROFILE" = release ]; then
    BUILD_ARGS=(--release)
else
    BUILD_ARGS=()
fi
BIN="$ROOT/target/$PROFILE/tracelet"

if [ "$BUILD" -eq 1 ]; then
    section "build ($PROFILE)"
    if cargo build "${BUILD_ARGS[@]}" >"$LOGS/build.log" 2>&1; then
        pass "cargo build $PROFILE"
    else
        fail "cargo build $PROFILE"
        show_log "$LOGS/build.log"
    fi

    section "tests"
    if cargo test --workspace >"$LOGS/test.log" 2>&1; then
        total=$(awk '/test result: ok/ {s += $4} END {print s + 0}' "$LOGS/test.log")
        pass "cargo test --workspace ($total tests)"
    else
        fail "cargo test --workspace"
        { grep -E '^(error|test result: FAILED|---- )' "$LOGS/test.log" | head -10 | sed 's/^/         /'; } || true
    fi
else
    section "build and tests"
    note "skipped (--no-build)"
fi

if [ -x "$BIN" ]; then
    pass "binary: $BIN"
else
    fail "binary missing: $BIN (rerun without --no-build)"
fi

section "cli surface"

if "$BIN" --version 2>/dev/null | grep -q tracelet; then
    pass "--version reports tracelet"
else
    fail "--version"
fi

for cmd in exec open tcp latency dashboard; do
    if "$BIN" "$cmd" --help >/dev/null 2>&1; then
        pass "help: $cmd"
    else
        fail "help: $cmd"
    fi
done

if "$BIN" bogus-subcommand >/dev/null 2>&1; then
    fail "unknown subcommand accepted"
else
    pass "unknown subcommand rejected"
fi

if "$BIN" tcp --help 2>/dev/null | grep -q 'connect, accept, close'; then
    pass "tcp --event values listed"
else
    fail "tcp --event values missing"
fi

if "$BIN" latency --help 2>/dev/null | grep -q 'read, write, openat'; then
    pass "latency --syscall values listed"
else
    fail "latency --syscall values missing"
fi

section "removed commands"

if "$BIN" top >/dev/null 2>&1; then
    fail "top subcommand should not exist"
else
    pass "top subcommand properly removed"
fi

section "version consistency"

CARGO_VER=$(grep '^version' "$ROOT/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')
BIN_VER=$("$BIN" --version 2>/dev/null | sed 's/tracelet //' || true)
if [ "$CARGO_VER" = "$BIN_VER" ] && [ -n "$CARGO_VER" ]; then
    pass "version consistency: Cargo.toml=$CARGO_VER == binary=$BIN_VER"
else
    fail "version mismatch: Cargo.toml=$CARGO_VER != binary=$BIN_VER"
fi

if bash "$ROOT/scripts/version.sh" self-test; then
    pass "version.sh self-test"
else
    fail "version.sh self-test"
fi

if [ "$(id -u)" -ne 0 ]; then
    section "live checks"
    note "skipped: BPF needs root or CAP_BPF"
    note "rerun as: sudo $0 --no-build"
    note "(--no-build avoids root-owned files in target/)"
else
    section "live checks (root)"
    check_exec
    check_open
    check_tcp
    check_latency
    check_filter
    check_dashboard
fi

section "summary"
printf '  %d passed, %d failed, %d skipped\n' "$PASSED" "$FAILED" "$SKIPPED"

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
