#!/usr/bin/env python3
"""Validate detailed ticket specs for strategic checklist IDs (1.x-10.x)."""

from __future__ import annotations

import sys
from pathlib import Path
import json
import yaml

ROOT = Path(__file__).resolve().parents[1]
CHECKLIST_PATH = ROOT / ".github" / "workflow-data" / "FINAL_COMPLETION_CHECKLIST.json"
TICKETS_PATH = ROOT / ".github" / "workflow-data" / "ITEMS_1_TO_10_TICKETS.yaml"

REQUIRED_KEYS = {
    "id",
    "title",
    "item",
    "deps",
    "scope_paths",
    "acceptance_criteria",
    "acceptance_tests",
    "required_ci_gates",
    "required_docs",
    "blocking_conditions",
    "fail_criteria",
}


def load_checklist_ids() -> list[str]:
    doc = json.loads(CHECKLIST_PATH.read_text(encoding="utf-8"))
    for item in doc.get("items", []):
        if item.get("id") == "ITEMS_1_TO_10":
            return [entry["id"] for entry in item.get("requirements", [])]
    raise RuntimeError("ITEMS_1_TO_10 section not found in FINAL_COMPLETION_CHECKLIST.json")


def main() -> int:
    errors: list[str] = []

    expected_ids = load_checklist_ids()
    expected_set = set(expected_ids)

    tickets_doc = yaml.safe_load(TICKETS_PATH.read_text(encoding="utf-8"))
    tickets = tickets_doc.get("tickets", [])
    if not isinstance(tickets, list):
        errors.append("tickets must be a list")
        tickets = []

    by_id: dict[str, dict] = {}
    for ticket in tickets:
        tid = ticket.get("id")
        if not tid:
            errors.append("ticket missing id")
            continue
        if tid in by_id:
            errors.append(f"duplicate ticket id: {tid}")
            continue
        by_id[tid] = ticket

    for tid in expected_ids:
        if tid not in by_id:
            errors.append(f"missing ticket for checklist id: {tid}")

    for tid in by_id:
        if tid not in expected_set:
            errors.append(f"extra ticket id not in checklist: {tid}")

    for tid, ticket in by_id.items():
        missing_keys = sorted(REQUIRED_KEYS - set(ticket.keys()))
        if missing_keys:
            errors.append(f"{tid}: missing keys: {', '.join(missing_keys)}")
            continue

        for key in (
            "scope_paths",
            "acceptance_criteria",
            "acceptance_tests",
            "required_ci_gates",
            "required_docs",
            "blocking_conditions",
            "fail_criteria",
        ):
            value = ticket.get(key)
            if not isinstance(value, list) or not value:
                errors.append(f"{tid}: {key} must be a non-empty list")

        deps = ticket.get("deps", [])
        if not isinstance(deps, list):
            errors.append(f"{tid}: deps must be a list")
        else:
            for dep in deps:
                if dep not in expected_set:
                    errors.append(f"{tid}: unknown dep id: {dep}")

    print(f"Checklist IDs: {len(expected_ids)}")
    print(f"Detailed tickets: {len(by_id)}")
    print(f"Errors: {len(errors)}")
    if errors:
        for err in errors:
            print(f"  - {err}")
        return 2

    print("Validation OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
