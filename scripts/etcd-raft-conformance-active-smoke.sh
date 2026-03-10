#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HARNESS_SCRIPT="$ROOT_DIR/scripts/etcd-raft-live-harness.sh"
TRACE_FILE="$ROOT_DIR/examples/conformance/active/etcd_raft_faults_basic.json"
REPORT_FILE="${REPORT_FILE:-$(mktemp)}"
EVENTS_FILE="${EVENTS_FILE:-$(mktemp)}"
SERVER_LOG="${SERVER_LOG:-$(mktemp)}"
SEED="${SEED:-11}"
LIVE_TIMEOUT_MS="${LIVE_TIMEOUT_MS:-2000}"
SERVER_PORT="${SERVER_PORT:-19192}"
LIVE_ENDPOINT="http://127.0.0.1:${SERVER_PORT}/active"
KEEP_HARNESS="${KEEP_HARNESS:-0}"

usage() {
  cat <<USAGE
Usage: $(basename "$0") <command>

Commands:
  assert-fixture   Validate deterministic fixture-level trace assertions (no docker required).
  smoke            Run end-to-end active-conformance smoke against live etcd-raft harness.
USAGE
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "required command missing: $cmd" >&2
    exit 2
  fi
}

assert_fixture_contract() {
  python3 - "$TRACE_FILE" "$SEED" <<'PY'
import json
import sys

trace_file = sys.argv[1]
seed = int(sys.argv[2])  # reserved for deterministic ordering checks
_ = seed

doc = json.load(open(trace_file, encoding="utf-8"))
assert doc.get("schema_version") == 1, "fixture schema_version must be 1"
faults = doc.get("faults", [])
assert isinstance(faults, list) and faults, "fixture must include faults"

ticks = sorted({int(f["tick"]) for f in faults})
expected_events = 2 + len(ticks) + len(faults)  # start + stop + tick changes + faults

assert ticks == [1, 2, 3, 4, 5, 6], f"unexpected deterministic tick set: {ticks}"
assert len(faults) == 6, f"unexpected fault count: {len(faults)}"
assert expected_events == 14, f"unexpected total live events: {expected_events}"
print("fixture contract ok")
PY
}

start_mock_live_endpoint() {
  python3 -u - "$SERVER_PORT" "$EVENTS_FILE" <<'PY' >"$SERVER_LOG" 2>&1 &
import http.server
import json
import socketserver
import sys

port = int(sys.argv[1])
events_file = sys.argv[2]

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def _write_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._write_json(200, {"ok": True})
            return
        self._write_json(404, {"error": "not_found"})

    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        raw = self.rfile.read(length)
        payload = json.loads(raw.decode("utf-8") or "{}")
        with open(events_file, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload) + "\n")
        self._write_json(200, {"ok": True})

class ReuseServer(socketserver.TCPServer):
    allow_reuse_address = True

with ReuseServer(("127.0.0.1", port), Handler) as server:
    server.serve_forever()
PY
  SERVER_PID=$!
}

wait_for_mock_endpoint() {
  local deadline=$((SECONDS + 15))
  while ((SECONDS < deadline)); do
    if curl -fsS "http://127.0.0.1:${SERVER_PORT}/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done
  echo "mock live endpoint did not start on port ${SERVER_PORT}" >&2
  return 1
}

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "${SERVER_PID}" >/dev/null 2>&1 || true
    wait "${SERVER_PID}" >/dev/null 2>&1 || true
  fi
  if [[ "$KEEP_HARNESS" != "1" ]]; then
    "$HARNESS_SCRIPT" stop >/dev/null 2>&1 || true
  fi
}

run_smoke() {
  require_cmd cargo
  require_cmd curl
  require_cmd python3
  require_cmd docker

  trap cleanup EXIT

  assert_fixture_contract
  "$HARNESS_SCRIPT" start
  ETCD_ENDPOINT="$("$HARNESS_SCRIPT" endpoint)"
  curl -fsS "${ETCD_ENDPOINT}/health" >/dev/null

  start_mock_live_endpoint
  wait_for_mock_endpoint

  (
    cd "$ROOT_DIR"
    cargo run -q -p tarsier-cli -- conformance-active \
      --trace "$TRACE_FILE" \
      --adapter etcd-raft \
      --seed "$SEED" \
      --format json \
      --live-endpoint "$LIVE_ENDPOINT" \
      --live-timeout-ms "$LIVE_TIMEOUT_MS" \
      --out "$REPORT_FILE"
  ) >/dev/null

  python3 - "$REPORT_FILE" "$EVENTS_FILE" "$SEED" "$LIVE_ENDPOINT" <<'PY'
import json
import sys

report_path, events_path, seed, endpoint = sys.argv[1:]
seed = int(seed)

report = json.load(open(report_path, encoding="utf-8"))
assert report.get("schema_version") == 1, "report schema_version mismatch"
assert report.get("adapter") == "etcd-raft", "adapter mismatch"
assert report.get("seed") == seed, "seed mismatch"

faults = report.get("faults", [])
assert len(faults) == 6, f"expected 6 faults, got {len(faults)}"
ticks = sorted({int(f["tick"]) for f in faults})
expected_events = 2 + len(ticks) + len(faults)

live = report.get("live")
assert isinstance(live, dict), "missing live report"
assert live.get("endpoint") == endpoint, "live endpoint mismatch"
assert live.get("contract") == "tarsier.active.v1", "contract mismatch"
assert int(live.get("events_sent", -1)) == expected_events, "events_sent mismatch"
assert int(live.get("final_tick", -1)) == max(ticks), "final_tick mismatch"

events = [json.loads(line) for line in open(events_path, encoding="utf-8") if line.strip()]
assert len(events) == expected_events, f"expected {expected_events} events, got {len(events)}"
assert events[0].get("op") == "start", "first event must be start"
assert events[0].get("adapter") == "etcd-raft", "start adapter mismatch"
assert events[-1].get("op") == "stop", "last event must be stop"
assert int(events[-1].get("final_tick", -1)) == max(ticks), "stop final_tick mismatch"
assert any(ev.get("op") == "fault" for ev in events), "no fault events observed"
print("live contract assertions ok")
PY

  curl -fsS "${ETCD_ENDPOINT}/health" >/dev/null
  echo "INTEG-04 smoke passed"
}

cmd="${1:-}"
case "$cmd" in
  assert-fixture)
    require_cmd python3
    assert_fixture_contract
    ;;
  smoke)
    run_smoke
    ;;
  *)
    usage
    exit 2
    ;;
esac
