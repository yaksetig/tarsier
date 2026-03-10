#!/usr/bin/env python3
"""Validate deterministic etcd raft harness compose configuration."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "integration" / "etcd-raft-live" / "docker-compose.yml"

REQUIRED_SNIPPETS = [
    "image: quay.io/coreos/etcd:v3.5.14",
    "--name=node0",
    "--initial-cluster-token=tarsier-integ-02",
    "--initial-cluster=node0=http://etcd-node0:2380",
    "--heartbeat-interval=100",
    "--election-timeout=1000",
    "\"2379:2379\"",
    "\"2380:2380\"",
    "name: tarsier-etcd-node0-data",
]


def main() -> None:
    text = COMPOSE.read_text(encoding="utf-8")
    missing = [snippet for snippet in REQUIRED_SNIPPETS if snippet not in text]
    if missing:
        raise SystemExit(f"config check failed; missing snippets: {missing}")
    print("ok: etcd raft live harness deterministic config is valid")


if __name__ == "__main__":
    main()
