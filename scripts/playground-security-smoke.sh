#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

PORT="${TARSIER_PLAYGROUND_PORT:-7880}"
HOST="${TARSIER_PLAYGROUND_HOST:-127.0.0.1}"
BASE_URL="http://${HOST}:${PORT}"

MAX_DEPTH="${TARSIER_MAX_DEPTH:-8}"
MAX_TIMEOUT="${TARSIER_MAX_TIMEOUT_SECS:-30}"
MAX_REQUEST_BYTES="${TARSIER_MAX_REQUEST_BYTES:-524288}"

echo "[security] Starting playground with hardened config on ${BASE_URL}"
playground_log="$(mktemp)"
TARSIER_PLAYGROUND_HOST="${HOST}" \
TARSIER_PLAYGROUND_PORT="${PORT}" \
TARSIER_MAX_DEPTH="${MAX_DEPTH}" \
TARSIER_MAX_TIMEOUT_SECS="${MAX_TIMEOUT}" \
TARSIER_MAX_REQUEST_BYTES="${MAX_REQUEST_BYTES}" \
  cargo run -q -p tarsier-playground >"${playground_log}" 2>&1 &
playground_pid=$!

cleanup() {
  if kill -0 "${playground_pid}" >/dev/null 2>&1; then
    kill "${playground_pid}" >/dev/null 2>&1 || true
    wait "${playground_pid}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

python3 - <<'PY' "${BASE_URL}" "${MAX_DEPTH}" "${MAX_REQUEST_BYTES}"
import json
import sys
import time
import urllib.error
import urllib.request

base = sys.argv[1]
max_depth = int(sys.argv[2])
max_request_bytes = int(sys.argv[3])

def fetch(url, method="GET", payload=None, timeout=10):
    body = None
    headers = {}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["content-type"] = "application/json"
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.getcode(), json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, None

# Wait for server ready
for _ in range(80):
    try:
        status, _ = fetch(base + "/api/health")
        if status == 200:
            break
    except Exception:
        time.sleep(0.25)
else:
    raise SystemExit("[security] playground did not become ready")

# 1. Health still works
status, health = fetch(base + "/api/health")
assert status == 200 and health.get("ok"), "[security] health check failed"
print("[security] health endpoint OK")

# 2. Oversized payload
big_payload = "x" * (max_request_bytes + 1024)
req = urllib.request.Request(
    base + "/api/parse",
    data=big_payload.encode("utf-8"),
    method="POST",
    headers={"content-type": "application/json"},
)
try:
    with urllib.request.urlopen(req, timeout=10) as resp:
        raise SystemExit("[security] oversized payload was not rejected")
except urllib.error.HTTPError as e:
    assert e.code == 413, f"[security] expected 413, got {e.code}"
    print("[security] oversized payload correctly rejected (413)")

# 3. Depth over max — should be clamped, not rejected
status, result = fetch(
    base + "/api/run",
    method="POST",
    payload={
        "source": "protocol T { params n, f; }",
        "check": "verify",
        "depth": max_depth + 100,
    },
)
# The request should succeed (depth gets clamped) or fail with a domain error, not a 413/500
assert status in (200, 400), f"[security] depth clamping: expected 200 or 400, got {status}"
print(f"[security] depth clamping works (status={status})")

print("[security] all smoke checks passed")
PY

echo "[security] Playground security smoke passed"
