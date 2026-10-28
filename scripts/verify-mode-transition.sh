#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

binary=$(realpath "$1")
test_dir=$(mktemp -d)
daemon_pid=
cleanup() {
  if [[ -n "$daemon_pid" ]]; then
    kill "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
  fi
  "$binary" --detach-policy || true
  rm -rf "$test_dir"
}
trap cleanup EXIT

mountpoint --quiet /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
install -d -m 0700 /sys/fs/bpf/outbound

cat > "$test_dir/enforce.yaml" <<'YAML'
version: v1
settings:
  mode: enforce
  max_ip_entries: 1024
  cover_all_udp: true
allowlist:
  domains: []
  cidrs: ["0.0.0.0/0", "::/0"]
YAML
cat > "$test_dir/audit.yaml" <<'YAML'
version: v1
settings:
  mode: audit
  max_ip_entries: 1024
  cover_all_udp: true
allowlist:
  domains: []
  cidrs: []
YAML

start_daemon() {
  local mode=$1
  "$binary" --config "$test_dir/$mode.yaml" > "$test_dir/$mode.log" 2>&1 &
  daemon_pid=$!
  for _ in {1..40}; do
    if grep -q '"event":"service_started"' "$test_dir/$mode.log"; then
      return 0
    fi
    if ! kill -0 "$daemon_pid" 2>/dev/null; then
      cat "$test_dir/$mode.log" >&2
      return 1
    fi
    sleep 0.25
  done
  cat "$test_dir/$mode.log" >&2
  return 1
}

start_daemon enforce
kill "$daemon_pid"
wait "$daemon_pid"
daemon_pid=
"$binary" --policy-status

start_daemon audit
python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    assert sock.sendto(b"x", ("127.0.0.1", 2218)) == 1
PY
for _ in {1..40}; do
  if grep -q '"decision":"WOULD_BLOCK".*"transport":"UDP".*"destination_port":2218' "$test_dir/audit.log"; then
    "$binary" --policy-status
    exit 0
  fi
  sleep 0.25
done
cat "$test_dir/audit.log" >&2
exit 1
