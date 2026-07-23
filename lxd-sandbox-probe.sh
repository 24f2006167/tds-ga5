#!/usr/bin/env bash
set +e

TOKEN='lxd_9f9204e47cb788b22bb4a31269399bae362d83ed6fd5e8cc'
CANARY_PATH='/opt/tds-lxd-canary/9ca6b445ab9d.txt'
LISTENER_URL='https://example.com/?tds_lxd_token=lxd_9f9204e47cb788b22bb4a31269399bae362d83ed6fd5e8cc&origin=https%3A%2F%2Fexam.sanand.workers.dev'
ALLOCATION_MB=1536
SPIN_SECONDS=5

echo "LXD_SANDBOX_START token=$TOKEN"

echo "LXD_FS_ATTEMPT path=$CANARY_PATH"
if content="$(cat "$CANARY_PATH" 2>&1)"; then
  echo "LXD_FS_LEAK_READABLE"
  printf '%s\n' "$content"
else
  status=$?
  echo "LXD_FS_BLOCKED status=$status"
  printf '%s\n' "$content" | head -c 300
  printf '\n'
fi

echo "LXD_NET_ATTEMPT token=$TOKEN"
if command -v curl >/dev/null 2>&1; then
  curl -fsS --max-time 4 "$LISTENER_URL?via=curl" >/dev/null 2>&1
  net_status=$?
elif command -v wget >/dev/null 2>&1; then
  wget -q -T 4 -O /dev/null "$LISTENER_URL?via=wget" >/dev/null 2>&1
  net_status=$?
else
  python3 - "$LISTENER_URL?via=python" <<'PY'
import sys, urllib.request
try:
    urllib.request.urlopen(sys.argv[1], timeout=4).read()
except Exception:
    sys.exit(7)
PY
  net_status=$?
fi
echo "LXD_NET_DONE status=$net_status"

echo "LXD_RESOURCE_ATTEMPT allocation_mb=$ALLOCATION_MB spin_seconds=$SPIN_SECONDS"
python3 - "$ALLOCATION_MB" "$SPIN_SECONDS" <<'PY'
import sys, time
allocation_mb = int(sys.argv[1])
spin_seconds = int(sys.argv[2])
chunks = []
try:
    for _ in range(allocation_mb):
        chunks.append(bytearray(1024 * 1024))
    deadline = time.time() + spin_seconds
    x = 0
    while time.time() < deadline:
        x = (x + 1) % 1000003
    print("LXD_RESOURCE_COMPLETED allocation_succeeded")
    sys.exit(0)
except MemoryError:
    print("LXD_RESOURCE_LIMIT_HIT memory_error")
    sys.exit(42)
PY
resource_status=$?
if [ "$resource_status" -ne 0 ]; then
  echo "LXD_RESOURCE_LIMIT_HIT status=$resource_status"
fi

echo "LXD_SANDBOX_END token=$TOKEN"
