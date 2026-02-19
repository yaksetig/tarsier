#!/usr/bin/env python3
"""Refresh or check model_sha256 fields in a cert-suite manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest",
        default="examples/library/cert_suite.json",
        help="Path to cert-suite manifest JSON.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Do not rewrite; exit non-zero if model_sha256 fields are stale/missing.",
    )
    args = parser.parse_args()

    manifest_path = Path(args.manifest).resolve()
    data: dict[str, Any] = json.loads(manifest_path.read_text())
    base_dir = manifest_path.parent
    changed = 0
    missing_files: list[str] = []

    for entry in data.get("entries", []):
        rel = entry.get("file", "")
        entry_path = Path(rel)
        if not entry_path.is_absolute():
            entry_path = (base_dir / entry_path).resolve()
        if not entry_path.exists():
            missing_files.append(str(entry_path))
            continue
        actual = sha256_file(entry_path)
        expected = entry.get("model_sha256")
        if expected != actual:
            changed += 1
            entry["model_sha256"] = actual

    if missing_files:
        print("Missing protocol files referenced by manifest:")
        for item in missing_files:
            print(f"  - {item}")
        return 2

    if args.check:
        if changed > 0:
            print(
                f"model_sha256 drift detected in {changed} entr{'y' if changed == 1 else 'ies'} "
                f"for {manifest_path}"
            )
            return 1
        print(f"model_sha256 checks passed for {manifest_path}")
        return 0

    manifest_path.write_text(json.dumps(data, indent=2) + "\n")
    print(
        f"Updated model_sha256 for {changed} entr{'y' if changed == 1 else 'ies'} "
        f"in {manifest_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
