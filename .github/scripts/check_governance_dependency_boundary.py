#!/usr/bin/env python3
"""Ensure governance-only dependencies stay out of the default CLI build."""

from __future__ import annotations

import re
import subprocess
import sys


GOVERNANCE_ONLY = {"ring"}


def parse_package_name(line: str) -> str | None:
    match = re.match(r"^([A-Za-z0-9_.-]+)\s+v", line.strip())
    if match:
        return match.group(1)
    return None


def dependency_set(extra_args: list[str]) -> set[str]:
    cmd = [
        "cargo",
        "tree",
        "-p",
        "tarsier-cli",
        "--depth",
        "1",
        "--prefix",
        "none",
        "--format",
        "{p}",
    ] + extra_args
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise RuntimeError(f"failed command: {' '.join(cmd)}")

    deps: set[str] = set()
    for raw in proc.stdout.splitlines():
        name = parse_package_name(raw)
        if name:
            deps.add(name)
    return deps


def main() -> int:
    try:
        default_deps = dependency_set([])
        governance_deps = dependency_set(["--features", "governance"])
    except RuntimeError as exc:
        print(f"ERROR: {exc}")
        return 1

    leaked = sorted(GOVERNANCE_ONLY.intersection(default_deps))
    if leaked:
        print("ERROR: governance-only dependencies leaked into default tarsier-cli build:")
        for dep in leaked:
            print(f"  - {dep}")
        return 1

    missing = sorted(dep for dep in GOVERNANCE_ONLY if dep not in governance_deps)
    if missing:
        print("ERROR: expected governance dependencies missing from governance feature build:")
        for dep in missing:
            print(f"  - {dep}")
        return 1

    print("Governance dependency boundary OK (default excludes governance-only crates)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
