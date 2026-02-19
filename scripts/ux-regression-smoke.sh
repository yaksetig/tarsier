#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

echo "[ux] CLI smoke: assist"
assist_out="$(mktemp)"
cargo run -q -p tarsier-cli -- assist --kind pbft >"${assist_out}"
if ! grep -q "protocol PBFTTemplate" "${assist_out}"; then
  echo "[ux] assist output did not include PBFT scaffold"
  exit 1
fi

echo "[ux] CLI smoke: lint json"
lint_out="$(mktemp)"
set +e
cargo run -q -p tarsier-cli -- lint examples/pbft_simple.trs --format json >"${lint_out}"
lint_exit=$?
set -e
if [[ "${lint_exit}" -ne 0 && "${lint_exit}" -ne 2 ]]; then
  echo "[ux] lint command failed with unexpected exit code: ${lint_exit}"
  exit 1
fi
python3 - <<'PY' "${lint_out}"
import json
import sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)
if "issues" not in data or not isinstance(data["issues"], list):
    raise SystemExit("lint JSON missing issues array")
PY

echo "[ux] CLI smoke: visualize json"
viz_out="$(mktemp)"
cargo run -q -p tarsier-cli -- visualize examples/reliable_broadcast_buggy.trs \
  --check verify \
  --depth 4 \
  --timeout 30 \
  --format json >"${viz_out}"
python3 - <<'PY' "${viz_out}"
import json
import sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)
for key in ("result", "timeline", "mermaid"):
    if key not in data:
        raise SystemExit(f"visualize JSON missing key: {key}")
PY

PORT="${TARSIER_PLAYGROUND_PORT:-7879}"
HOST="${TARSIER_PLAYGROUND_HOST:-127.0.0.1}"
BASE_URL="http://${HOST}:${PORT}"

echo "[ux] Playground smoke: start server on ${BASE_URL}"
playground_log="$(mktemp)"
TARSIER_PLAYGROUND_HOST="${HOST}" TARSIER_PLAYGROUND_PORT="${PORT}" \
  cargo run -q -p tarsier-playground >"${playground_log}" 2>&1 &
playground_pid=$!

cleanup() {
  if kill -0 "${playground_pid}" >/dev/null 2>&1; then
    kill "${playground_pid}" >/dev/null 2>&1 || true
    wait "${playground_pid}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

python3 - <<'PY' "${BASE_URL}" "${ROOT_DIR}"
import json
import os
import sys
import time
import urllib.error
import urllib.request

base = sys.argv[1]
root = sys.argv[2]

def fetch_json(url, method="GET", payload=None, timeout=30):
    body = None
    headers = {}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["content-type"] = "application/json"
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.getcode(), json.loads(resp.read().decode("utf-8"))

for _ in range(80):
    try:
        status, health = fetch_json(base + "/api/health")
        if status == 200 and health.get("ok") is True:
            break
    except Exception:
        time.sleep(0.25)
else:
    raise SystemExit("playground health check did not become ready")

status, examples = fetch_json(base + "/api/examples")
if status != 200 or not isinstance(examples, list) or len(examples) == 0:
    raise SystemExit("examples endpoint did not return a non-empty list")

status, assist = fetch_json(base + "/api/assist", method="POST", payload={"kind": "pbft"})
if status != 200 or assist.get("ok") is not True:
    raise SystemExit("assist endpoint failed for pbft")

source_path = os.path.join(root, "examples", "pbft_simple.trs")
with open(source_path, "r", encoding="utf-8") as f:
    source = f.read()

status, lint = fetch_json(
    base + "/api/lint",
    method="POST",
    payload={"source": source, "filename": "pbft_simple.trs"},
)
if status != 200 or "issues" not in lint or not isinstance(lint["issues"], list):
    raise SystemExit("lint endpoint failed schema checks")

status, run = fetch_json(
    base + "/api/run",
    method="POST",
    payload={
        "source": source,
        "filename": "pbft_simple.trs",
        "check": "verify",
        "solver": "z3",
        "depth": 4,
        "timeout_secs": 30,
        "soundness": "strict",
        "proof_engine": "kinduction",
        "fairness": "weak",
    },
)
if status != 200 or run.get("ok") is not True:
    raise SystemExit("run endpoint failed")
if "result" not in run or "output" not in run:
    raise SystemExit("run endpoint missing expected fields")
PY

echo "[ux] Playground + CLI usability smoke passed"
