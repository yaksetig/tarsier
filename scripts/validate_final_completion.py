#!/usr/bin/env python3
"""Validate FINAL_COMPLETION_STATUS.json against FINAL_COMPLETION_CHECKLIST.json.

Usage:
  python3 scripts/validate_final_completion.py
  python3 scripts/validate_final_completion.py --strict-evidence
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Dict, List, Tuple

ROOT = pathlib.Path(__file__).resolve().parents[1]
CHECKLIST = ROOT / ".github" / "workflow-data" / "FINAL_COMPLETION_CHECKLIST.json"
STATUS = ROOT / ".github" / "workflow-data" / "FINAL_COMPLETION_STATUS.json"


def load_json(path: pathlib.Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"failed to parse {path}: {exc}") from exc


def collect_ids(checklist: dict) -> Tuple[List[str], Dict[str, List[str]]]:
    global_ids = [r["id"] for r in checklist.get("global_rules", [])]
    item_reqs: Dict[str, List[str]] = {}
    for item in checklist.get("items", []):
        item_reqs[item["id"]] = [r["id"] for r in item.get("requirements", [])]
    return global_ids, item_reqs


def validate(strict_evidence: bool) -> int:
    errors: List[str] = []
    warnings: List[str] = []

    checklist = load_json(CHECKLIST)
    status = load_json(STATUS)

    valid_status = set(checklist.get("status_enum", []))
    if not valid_status:
        errors.append("checklist status_enum is empty")

    global_ids, item_reqs = collect_ids(checklist)

    status_global = status.get("global_rules", {})
    status_items = status.get("items", {})

    # Global rule coverage
    for gid in global_ids:
        if gid not in status_global:
            errors.append(f"missing global rule in status: {gid}")
            continue
        st = status_global[gid].get("status")
        if st not in valid_status:
            errors.append(f"invalid status for {gid}: {st}")
        if strict_evidence and st == "pass":
            ev = status_global[gid].get("evidence", {})
            for key in ("code_refs", "tests", "ci_gates", "docs"):
                if not ev.get(key):
                    errors.append(f"{gid} is pass but evidence.{key} is empty")

    for gid in status_global.keys():
        if gid not in global_ids:
            warnings.append(f"extra global rule in status not in checklist: {gid}")

    # Item + requirement coverage
    for item_id, req_ids in item_reqs.items():
        if item_id not in status_items:
            errors.append(f"missing item in status: {item_id}")
            continue

        item_obj = status_items[item_id]
        item_status = item_obj.get("status")
        if item_status not in valid_status:
            errors.append(f"invalid item status for {item_id}: {item_status}")

        req_map = item_obj.get("requirements", {})
        for rid in req_ids:
            if rid not in req_map:
                errors.append(f"missing requirement in status: {rid}")
                continue
            rst = req_map[rid].get("status")
            if rst not in valid_status:
                errors.append(f"invalid requirement status for {rid}: {rst}")
            if strict_evidence and rst == "pass":
                ev = req_map[rid].get("evidence", {})
                for key in ("code_refs", "tests", "ci_gates", "docs"):
                    if not ev.get(key):
                        errors.append(f"{rid} is pass but evidence.{key} is empty")

        for rid in req_map.keys():
            if rid not in req_ids:
                warnings.append(f"extra requirement in status not in checklist: {rid}")

        # Optional consistency check: item status must match requirement aggregation
        req_statuses = [req_map.get(rid, {}).get("status") for rid in req_ids if rid in req_map]
        if req_statuses:
            if all(s == "pass" for s in req_statuses):
                expected = "pass"
            elif any(s == "in_progress" for s in req_statuses):
                expected = "in_progress"
            elif any(s == "blocked" for s in req_statuses):
                expected = "blocked"
            elif all(s == "not_started" for s in req_statuses):
                expected = "not_started"
            elif any(s == "fail" for s in req_statuses):
                expected = "fail"
            else:
                expected = "in_progress"
            if item_status != expected:
                warnings.append(
                    f"item {item_id} status={item_status} but requirements imply {expected}"
                )

    for item_id in status_items.keys():
        if item_id not in item_reqs:
            warnings.append(f"extra item in status not in checklist: {item_id}")

    # Summary
    total_requirements = sum(len(v) for v in item_reqs.values())
    passed_requirements = 0
    for item_id, req_ids in item_reqs.items():
        req_map = status_items.get(item_id, {}).get("requirements", {})
        passed_requirements += sum(1 for rid in req_ids if req_map.get(rid, {}).get("status") == "pass")

    print(f"Checklist: {CHECKLIST}")
    print(f"Status:    {STATUS}")
    print(f"Requirements passed: {passed_requirements}/{total_requirements}")
    print(f"Errors: {len(errors)}  Warnings: {len(warnings)}")

    if warnings:
        print("\nWarnings:")
        for w in warnings:
            print(f"  - {w}")

    if errors:
        print("\nErrors:")
        for e in errors:
            print(f"  - {e}")
        return 2

    print("Validation OK")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--strict-evidence",
        action="store_true",
        help="Require non-empty code_refs/tests/ci_gates/docs for any status=pass",
    )
    args = parser.parse_args()
    return validate(strict_evidence=args.strict_evidence)


if __name__ == "__main__":
    sys.exit(main())
