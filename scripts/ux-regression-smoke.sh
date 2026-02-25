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

echo "[ux] CLI smoke: visualize timeline format"
timeline_out="$(mktemp)"
cargo run -q -p tarsier-cli -- visualize examples/reliable_broadcast_buggy.trs \
  --check verify \
  --depth 4 \
  --timeout 30 \
  --format timeline >"${timeline_out}"
if ! grep -q "Step" "${timeline_out}"; then
  echo "[ux] timeline format did not contain step markers"
  exit 1
fi

echo "[ux] CLI smoke: visualize mermaid format"
mermaid_out="$(mktemp)"
cargo run -q -p tarsier-cli -- visualize examples/reliable_broadcast_buggy.trs \
  --check verify \
  --depth 4 \
  --timeout 30 \
  --format mermaid >"${mermaid_out}"
if ! grep -q "sequenceDiagram" "${mermaid_out}"; then
  echo "[ux] mermaid format did not contain sequenceDiagram"
  exit 1
fi

echo "[ux] CLI smoke: visualize markdown format"
markdown_out="$(mktemp)"
cargo run -q -p tarsier-cli -- visualize examples/reliable_broadcast_buggy.trs \
  --check verify \
  --depth 4 \
  --timeout 30 \
  --format markdown >"${markdown_out}"
if ! grep -q "sequenceDiagram" "${markdown_out}" || ! grep -q "Step" "${markdown_out}"; then
  echo "[ux] markdown format should contain both timeline and mermaid"
  exit 1
fi

echo "[ux] CLI smoke: visualize bundle export contract"
bundle_dir="$(mktemp -d)"
cargo run -q -p tarsier-cli -- visualize examples/reliable_broadcast_buggy.trs \
  --check verify \
  --depth 4 \
  --timeout 30 \
  --bundle "${bundle_dir}" >/dev/null
for expected in timeline.txt msc.mermaid report.md trace.json metadata.json; do
  if [[ ! -f "${bundle_dir}/${expected}" ]]; then
    echo "[ux] visualize bundle missing file: ${expected}"
    exit 1
  fi
done
python3 - <<'PY' "${bundle_dir}/metadata.json"
import json
import sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)
for key in ("check", "protocol_file", "result"):
    if key not in data:
        raise SystemExit(f"metadata missing key: {key}")
PY

echo "[ux] CLI smoke: debug-cex non-interactive with filters"
debugcex_out="$(mktemp)"
echo "q" | cargo run -q -p tarsier-cli -- debug-cex examples/reliable_broadcast_buggy.trs \
  --check verify \
  --depth 4 \
  --timeout 30 \
  --filter-sender Sender \
  --filter-auth authenticated >"${debugcex_out}" 2>&1 || true
if ! grep -qi "unsafe\|counterexample\|step\|initial" "${debugcex_out}"; then
  echo "[ux] debug-cex output did not contain expected trace content"
  exit 1
fi

echo "[ux] CLI smoke: scaffold templates completeness"
for kind in pbft hotstuff raft tendermint streamlet casper; do
  scaffold_out="$(mktemp)"
  cargo run -q -p tarsier-cli -- assist --kind "${kind}" >"${scaffold_out}"
  if ! grep -q "protocol" "${scaffold_out}"; then
    echo "[ux] scaffold for ${kind} did not produce a protocol"
    exit 1
  fi
done

echo "[ux] CLI smoke: lint source spans"
lint_span_out="$(mktemp)"
set +e
cargo run -q -p tarsier-cli -- lint examples/pbft_simple.trs --format json >"${lint_span_out}"
lint_span_exit=$?
set -e
if [[ "${lint_span_exit}" -ne 0 && "${lint_span_exit}" -ne 2 ]]; then
  echo "[ux] lint span check failed with unexpected exit code: ${lint_span_exit}"
  exit 1
fi
python3 - <<'PY' "${lint_span_out}"
import json
import sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)
issues = data.get("issues", [])
has_soundness_impact = False
for issue in issues:
    if "severity" not in issue or "code" not in issue or "message" not in issue:
        raise SystemExit("lint issue missing severity/code/message")
    if issue.get("soundness_impact"):
        has_soundness_impact = True
    if issue.get("severity") in ("error", "warn") and issue.get("soundness_impact") is None:
        raise SystemExit("lint warn/error issue missing soundness_impact")
    if "source_span" in issue and issue["source_span"] is not None:
        span = issue["source_span"]
        has_modern = "start" in span and "end" in span
        has_legacy = "start_byte" in span and "end_byte" in span
        if not (has_modern or has_legacy):
            raise SystemExit("lint issue source_span missing start/end byte offsets")
if issues and not has_soundness_impact:
    raise SystemExit("lint issues missing soundness_impact annotations")
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

def fetch_text(url, timeout=30):
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.getcode(), resp.read().decode("utf-8")

for _ in range(80):
    try:
        status, health = fetch_json(base + "/api/health")
        if status == 200 and health.get("ok") is True:
            break
    except Exception:
        time.sleep(0.25)
else:
    raise SystemExit("playground health check did not become ready")

status, app_js = fetch_text(base + "/app.js")
if status != 200:
    raise SystemExit("playground app.js endpoint failed")
for marker in (
    "Variant:",
    "Field:",
    "Auth:",
    "issue.fix",
    "insert_offset",
    "soundness impact:",
    "exportArtifactBundle",
    "markdown_report",
):
    if marker not in app_js:
        raise SystemExit(f"playground app.js missing UX marker: {marker}")

status, index_html = fetch_text(base + "/")
if status != 200:
    raise SystemExit("playground index endpoint failed")
for required in (
    'id="health-pill"',
    'id="run-meta"',
    'id="result-summary"',
    'for="example-select"',
    'for="workflow-select"',
    'for="check-select"',
    'for="assist-kind-select"',
):
    if required not in index_html:
        raise SystemExit(f"playground index missing accessibility contract marker: {required}")
for aria_required in (
    'aria-live="polite"',
    'aria-live="assertive"',
):
    if aria_required not in index_html:
        raise SystemExit(f"playground index missing aria contract: {aria_required}")

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
for issue in lint["issues"]:
    if issue.get("severity") in ("error", "warn") and issue.get("soundness_impact") is None:
        raise SystemExit("playground lint warn/error issue missing soundness_impact")

lint_fix_source = """
protocol MissingCoreSections {
    params n, f;
    role Replica {
        init idle;
        phase idle {}
    }
}
"""
status, lint_fix = fetch_json(
    base + "/api/lint",
    method="POST",
    payload={"source": lint_fix_source, "filename": "missing_core_sections.trs"},
)
if status != 200:
    raise SystemExit("lint endpoint failed on missing-core-sections source")
issues = lint_fix.get("issues", [])
res_issue = next((i for i in issues if i.get("code") == "missing_resilience"), None)
if not res_issue:
    raise SystemExit("missing_resilience issue was not emitted")
res_fix = res_issue.get("fix")
if not isinstance(res_fix, dict) or not res_fix.get("snippet"):
    raise SystemExit("missing_resilience issue missing structured fix snippet")
if "resilience: n = 3*f + 1;" not in res_fix.get("snippet", ""):
    raise SystemExit("missing_resilience fix snippet does not contain resilience clause")
safe_issue = next((i for i in issues if i.get("code") == "missing_safety_property"), None)
if not safe_issue or not isinstance(safe_issue.get("fix"), dict):
    raise SystemExit("missing_safety_property issue missing structured fix snippet")

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

# Verify trace structure when present (counterexample paths)
buggy_path = os.path.join(root, "examples", "reliable_broadcast_buggy.trs")
with open(buggy_path, "r", encoding="utf-8") as f:
    buggy_source = f.read()

print("[ux] playground: trace structure + deliveries")
status, buggy_run = fetch_json(
    base + "/api/run",
    method="POST",
    payload={
        "source": buggy_source,
        "filename": "reliable_broadcast_buggy.trs",
        "check": "verify",
        "solver": "z3",
        "depth": 4,
        "timeout_secs": 30,
        "soundness": "strict",
        "proof_engine": "kinduction",
        "fairness": "weak",
    },
    timeout=60,
)
if status != 200:
    raise SystemExit(f"buggy run failed with status {status}")
trace = buggy_run.get("trace")
if trace is not None:
    if "steps" not in trace or "initial" not in trace:
        raise SystemExit("trace missing steps or initial")
    for step in trace["steps"]:
        for key in ("index", "rule_id", "delta", "kappa", "gamma"):
            if key not in step:
                raise SystemExit(f"trace step missing key: {key}")
        if "deliveries" in step:
            for d in step["deliveries"]:
                for key in ("kind", "sender", "recipient", "payload"):
                    if key not in d:
                        raise SystemExit(f"delivery missing key: {key}")
                if "role" not in d["sender"]:
                    raise SystemExit("delivery sender missing role")
                if "role" not in d["recipient"]:
                    raise SystemExit("delivery recipient missing role")
                if "family" not in d["payload"]:
                    raise SystemExit("delivery payload missing family")
                if "variant" not in d["payload"] or "fields" not in d["payload"]:
                    raise SystemExit("delivery payload missing variant/fields")
                auth = d.get("auth")
                if not isinstance(auth, dict):
                    raise SystemExit("delivery missing auth metadata object")
                for key in ("authenticated_channel", "key_compromised", "provenance"):
                    if key not in auth:
                        raise SystemExit(f"delivery auth missing key: {key}")
    print("[ux] playground: trace structure validated")

# Verify timeline and mermaid are present for counterexample
if "timeline" not in buggy_run or not buggy_run["timeline"]:
    print("[ux] playground: timeline not available (counterexample may not have been found)")
else:
    if "Step" not in buggy_run["timeline"]:
        raise SystemExit("timeline missing Step markers")
    print("[ux] playground: timeline validated")
if "mermaid" not in buggy_run or not buggy_run["mermaid"]:
    print("[ux] playground: mermaid not available")
else:
    if "sequenceDiagram" not in buggy_run["mermaid"]:
        raise SystemExit("mermaid missing sequenceDiagram")
    print("[ux] playground: mermaid validated")
PY

echo "[ux] Playground + CLI usability smoke passed"
