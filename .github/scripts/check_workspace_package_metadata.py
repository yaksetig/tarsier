#!/usr/bin/env python3
"""Enforce workspace-inherited package metadata for all workspace crates."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MANIFESTS = sorted((ROOT / "crates").glob("*/Cargo.toml")) + [ROOT / "playground" / "Cargo.toml"]
REQUIRED_WORKSPACE_FIELDS = ("homepage", "keywords", "categories")


def check_manifest(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    package_match = re.search(r"(?ms)^\[package\]\n(?P<body>.*?)(?:^\[|\Z)", text)
    if not package_match:
        return [f"{path}: missing [package] table"]

    body = package_match.group("body")
    errors: list[str] = []
    for field in REQUIRED_WORKSPACE_FIELDS:
        pattern = rf"(?m)^\s*{re.escape(field)}\.workspace\s*=\s*true\s*$"
        if not re.search(pattern, body):
            errors.append(
                f"{path}: expected `{field}.workspace = true` in [package]"
            )
    return errors


def main() -> int:
    errors: list[str] = []

    if not MANIFESTS:
        print("ERROR: no manifests found under crates/ or playground/", file=sys.stderr)
        return 2

    for manifest in MANIFESTS:
        errors.extend(check_manifest(manifest))

    if errors:
        print("Workspace metadata contract violations:")
        for err in errors:
            print(f"  - {err}")
        return 1

    print(
        f"Workspace metadata contract passed for {len(MANIFESTS)} manifests "
        f"({', '.join(REQUIRED_WORKSPACE_FIELDS)})."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
