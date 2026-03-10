#!/usr/bin/env python3
"""Validate deterministic CometBFT harness config artifacts."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CFG = ROOT / "integration" / "cometbft-live" / "bootstrap" / "config"


def load(name: str) -> dict:
    path = CFG / name
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def require(cond: bool, msg: str) -> None:
    if not cond:
        raise SystemExit(f"config check failed: {msg}")


def main() -> None:
    genesis = load("genesis.json")
    node_key = load("node_key.json")
    validator_key = load("priv_validator_key.json")
    validator_state = load("priv_validator_state.json")

    require(genesis.get("chain_id") == "tarsier-integ-01", "unexpected chain_id")
    require(genesis.get("genesis_time") == "2026-01-01T00:00:00Z", "unexpected genesis_time")
    validators = genesis.get("validators") or []
    require(len(validators) == 1, "expected exactly one validator")

    validator = validators[0]
    require(
        validator.get("address") == validator_key.get("address"),
        "validator address mismatch",
    )
    require(
        validator.get("pub_key", {}).get("value")
        == validator_key.get("pub_key", {}).get("value"),
        "validator pubkey mismatch",
    )

    require(node_key.get("priv_key", {}).get("type") == "tendermint/PrivKeyEd25519", "bad node key type")
    require(
        validator_key.get("priv_key", {}).get("type") == "tendermint/PrivKeyEd25519",
        "bad validator key type",
    )

    require(validator_state.get("height") == "0", "unexpected validator state height")
    require(validator_state.get("round") == 0, "unexpected validator state round")
    require(validator_state.get("step") == 0, "unexpected validator state step")

    print("ok: cometbft live harness deterministic config is valid")


if __name__ == "__main__":
    main()
