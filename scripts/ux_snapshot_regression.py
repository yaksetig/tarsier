#!/usr/bin/env python3
"""Deterministic UX snapshot regression gate for CLI + playground surfaces.

Usage:
  python3 scripts/ux_snapshot_regression.py
  python3 scripts/ux_snapshot_regression.py --update
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Tuple

ROOT = pathlib.Path(__file__).resolve().parents[1]
SNAPSHOT_PATH = ROOT / "docs" / "ux-regression-snapshots-v1.json"


def run_cmd(cmd: List[str], allow: Tuple[int, ...] = (0,)) -> str:
    env = os.environ.copy()
    env["RUST_LOG"] = "off"
    proc = subprocess.run(
        cmd,
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
    )
    if proc.returncode not in allow:
        raise RuntimeError(
            "command failed: {}\nexit={}\nstdout:\n{}\nstderr:\n{}".format(
                " ".join(cmd), proc.returncode, proc.stdout, proc.stderr
            )
        )
    return proc.stdout


def run_json_cmd(cmd: List[str], allow: Tuple[int, ...] = (0,)) -> Any:
    out = run_cmd(cmd, allow=allow)
    return json.loads(out)


def pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class PlaygroundProc:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.proc: subprocess.Popen[str] | None = None

    def __enter__(self) -> "PlaygroundProc":
        env = os.environ.copy()
        env["TARSIER_PLAYGROUND_HOST"] = self.host
        env["TARSIER_PLAYGROUND_PORT"] = str(self.port)
        env["RUST_LOG"] = "off"
        self.proc = subprocess.Popen(
            ["cargo", "run", "-q", "-p", "tarsier-playground"],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self._wait_ready()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    def _wait_ready(self) -> None:
        base = f"http://{self.host}:{self.port}"
        for _ in range(100):
            try:
                status, payload = fetch_json(f"{base}/api/health")
                if status == 200 and payload.get("ok") is True:
                    return
            except Exception:
                pass
            time.sleep(0.2)
        extra = ""
        if self.proc is not None and self.proc.stdout is not None:
            try:
                extra = self.proc.stdout.read(2000)
            except Exception:
                extra = ""
        raise RuntimeError(f"playground failed to become healthy on {base}. logs:\n{extra}")


def fetch_json(url: str, payload: Dict[str, Any] | None = None) -> Tuple[int, Any]:
    body = None
    headers = {}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["content-type"] = "application/json"
    req = urllib.request.Request(
        url,
        data=body,
        method="POST" if payload is not None else "GET",
        headers=headers,
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.getcode(), json.loads(resp.read().decode("utf-8"))


def issue_projection(issue: Dict[str, Any]) -> Dict[str, Any]:
    span = issue.get("source_span")
    fix = issue.get("fix")
    return {
        "code": issue.get("code"),
        "severity": issue.get("severity"),
        "has_suggestion": bool(issue.get("suggestion")),
        "has_fix": isinstance(fix, dict),
        "has_soundness_impact": bool(issue.get("soundness_impact")),
        "has_span": isinstance(span, dict),
    }


def summarize_trace(trace: Dict[str, Any] | None) -> Dict[str, Any]:
    if not isinstance(trace, dict):
        return {"has_steps": False, "has_deliveries": False, "has_payload_fields": False}
    steps_raw = trace.get("steps")
    if isinstance(steps_raw, int):
        return {
            "has_steps": steps_raw > 0,
            "has_deliveries": int(trace.get("deliveries", 0)) > 0,
            "has_payload_fields": bool(trace.get("deliveries", 0)),
        }
    steps = steps_raw or []
    deliveries = 0
    has_payload_fields = False
    for step in steps:
        step_deliveries = step.get("deliveries") or []
        deliveries += len(step_deliveries)
        for d in step_deliveries:
            payload = d.get("payload") or {}
            if "fields" in payload and "variant" in payload:
                has_payload_fields = True
    return {
        "has_steps": len(steps) > 0,
        "has_deliveries": deliveries > 0,
        "has_payload_fields": has_payload_fields,
    }


def summarize_visualize_result(result: Any) -> str:
    if not isinstance(result, str):
        return "unknown"
    first_line = result.strip().splitlines()[0] if result.strip() else ""
    upper = first_line.upper()
    if "UNSAFE" in upper:
        return "unsafe"
    if "SAFE" in upper:
        return "safe"
    if "UNKNOWN" in upper:
        return "unknown"
    return "other"


def build_snapshot_projection() -> Dict[str, Any]:
    pbft_simple = (ROOT / "examples" / "pbft_simple.trs").read_text(encoding="utf-8")
    rb_buggy = (ROOT / "examples" / "reliable_broadcast_buggy.trs").read_text(encoding="utf-8")

    cli_assist = run_cmd(["cargo", "run", "-q", "-p", "tarsier-cli", "--", "assist", "--kind", "pbft"])
    cli_lint = run_json_cmd(
        [
            "cargo",
            "run",
            "-q",
            "-p",
            "tarsier-cli",
            "--",
            "lint",
            "examples/pbft_simple.trs",
            "--format",
            "json",
        ],
        allow=(0, 2),
    )
    cli_visualize = run_json_cmd(
        [
            "cargo",
            "run",
            "-q",
            "-p",
            "tarsier-cli",
            "--",
            "visualize",
            "examples/reliable_broadcast_buggy.trs",
            "--check",
            "verify",
            "--depth",
            "4",
            "--timeout",
            "30",
            "--format",
            "json",
        ],
    )

    host = "127.0.0.1"
    port = pick_free_port()
    with PlaygroundProc(host, port):
        base = f"http://{host}:{port}"
        _, pg_lint = fetch_json(
            f"{base}/api/lint",
            {
                "source": "protocol MissingCore { params n, f; role R { init s; phase s {} } }",
                "filename": "missing_core.trs",
            },
        )
        _, pg_run = fetch_json(
            f"{base}/api/run",
            {
                "source": rb_buggy,
                "filename": "reliable_broadcast_buggy.trs",
                "check": "verify",
                "solver": "z3",
                "depth": 4,
                "timeout_secs": 30,
                "soundness": "strict",
                "proof_engine": "kinduction",
                "fairness": "weak",
            },
        )
        _, pg_lint_pbft = fetch_json(
            f"{base}/api/lint",
            {
                "source": pbft_simple,
                "filename": "pbft_simple.trs",
            },
        )

    return {
        "schema_version": 1,
        "snapshot_kind": "ux-regression-v1",
        "snapshots": {
            "cli_assist_pbft": {
                "contains_protocol_keyword": "protocol PBFTTemplate" in cli_assist,
                "line_count": len(cli_assist.splitlines()),
            },
            "cli_lint_pbft_simple": {
                "issue_count": len(cli_lint.get("issues", [])),
                "issues": sorted(
                    [issue_projection(i) for i in cli_lint.get("issues", [])],
                    key=lambda x: (x["code"] or "", x["severity"] or ""),
                ),
            },
            "cli_visualize_buggy_verify": {
                "result": summarize_visualize_result(cli_visualize.get("result")),
                "has_timeline_steps": "Step" in (cli_visualize.get("timeline") or ""),
                "has_mermaid_sequence_diagram": "sequenceDiagram"
                in (cli_visualize.get("mermaid") or ""),
                "trace": summarize_trace(cli_visualize.get("trace")),
            },
            "playground_lint_missing_core": {
                "ok": pg_lint.get("ok"),
                "issue_codes": sorted((i.get("code") for i in pg_lint.get("issues", []))),
                "issues": sorted(
                    [issue_projection(i) for i in pg_lint.get("issues", [])],
                    key=lambda x: (x["code"] or "", x["severity"] or ""),
                ),
            },
            "playground_lint_pbft_simple": {
                "ok": pg_lint_pbft.get("ok"),
                "issue_count": len(pg_lint_pbft.get("issues", [])),
                "warn_or_error_with_soundness_impact": all(
                    (i.get("severity") not in ("warn", "error"))
                    or bool(i.get("soundness_impact"))
                    for i in pg_lint_pbft.get("issues", [])
                ),
            },
            "playground_run_buggy_verify": {
                "ok": pg_run.get("ok"),
                "result": pg_run.get("result"),
                "has_timeline_steps": "Step" in (pg_run.get("timeline") or ""),
                "has_mermaid_sequence_diagram": "sequenceDiagram"
                in (pg_run.get("mermaid") or ""),
                "trace": summarize_trace(pg_run.get("trace")),
            },
        },
    }


def pretty_json(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--update", action="store_true", help="write current projection as snapshot")
    args = parser.parse_args()

    actual = build_snapshot_projection()
    if args.update or not SNAPSHOT_PATH.exists():
        SNAPSHOT_PATH.write_text(pretty_json(actual), encoding="utf-8")
        print(f"wrote snapshot: {SNAPSHOT_PATH}")
        return 0

    expected = json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))
    if expected != actual:
        print("UX snapshot mismatch: {}".format(SNAPSHOT_PATH))
        print("Run `python3 scripts/ux_snapshot_regression.py --update` only when changes are intentional.")
        print("\n--- expected")
        print(pretty_json(expected))
        print("--- actual")
        print(pretty_json(actual))
        return 2

    print(f"UX snapshot regression OK: {SNAPSHOT_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
