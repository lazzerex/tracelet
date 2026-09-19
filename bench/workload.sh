#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: $0 <exec|open|tcp> <count>" >&2
    exit 2
}

[ "$#" -eq 2 ] || usage
kind=$1
count=$2
case $count in
'' | *[!0-9]*) usage ;;
esac
[ "$count" -gt 0 ] || usage

case $kind in
exec)
    for _ in $(seq 1 "$count"); do /bin/true; done
    ;;
open)
    for _ in $(seq 1 "$count"); do
        exec 3</etc/hosts
        exec 3<&-
    done
    ;;
tcp)
    command -v python3 >/dev/null 2>&1 || {
        echo "python3 is required for the tcp workload" >&2
        exit 1
    }
    ready=$(mktemp)
    python3 - "$count" "$ready" <<'PY' &
import socket, sys

count = int(sys.argv[1])
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 45678))
srv.listen(128)
with open(sys.argv[2], "w") as handle:
    handle.write("ready\n")
for _ in range(count):
    conn, _ = srv.accept()
    conn.close()
srv.close()
PY
    server=$!
    for _ in $(seq 1 200); do
        [ -s "$ready" ] && break
        sleep 0.05
    done
    if [ ! -s "$ready" ]; then
        echo "tcp server did not start" >&2
        kill "$server" 2>/dev/null || true
        rm -f "$ready"
        exit 1
    fi
    rm -f "$ready"
    python3 - "$count" <<'PY'
import socket, sys

count = int(sys.argv[1])
for _ in range(count):
    socket.create_connection(("127.0.0.1", 45678), timeout=10).close()
PY
    wait "$server"
    ;;
*)
    usage
    ;;
esac

echo "workload $kind completed: $count units"