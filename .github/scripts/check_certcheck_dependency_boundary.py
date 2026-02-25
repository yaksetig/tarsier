#!/usr/bin/env python3
"""Fail if tarsier-certcheck pulls forbidden dependencies (transitively)."""

from __future__ import annotations

import re
import subprocess
import sys


FORBIDDEN = {
    "tarsier-engine",
    "tarsier-ir",
    "tarsier-dsl",
    "tarsier-smt",
    "tarsier-prob",
    "z3",
}


def parse_package_name(line: str) -> str | None:
    # Example:
    #   tarsier-certcheck v0.1.0 (/path)
    #   clap v4.5.57
    match = re.match(r"^([A-Za-z0-9_.-]+)\s+v", line.strip())
    if match:
        return match.group(1)
    return None


def main() -> int:
    cmd = [
        "cargo",
        "tree",
        "-p",
        "tarsier-certcheck",
        "--prefix",
        "none",
        "--format",
        "{p}",
        "--edges",
        "normal,build",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        print("ERROR: failed to compute dependency tree for tarsier-certcheck")
        return proc.returncode

    package_names: set[str] = set()
    for raw in proc.stdout.splitlines():
        name = parse_package_name(raw)
        if name:
            package_names.add(name)

    violating = sorted(FORBIDDEN.intersection(package_names))
    if violating:
        print("ERROR: tarsier-certcheck dependency boundary violated.")
        print("Forbidden crates found in full dependency tree:")
        for name in violating:
            print(f"  - {name}")
        return 1

    print("Certcheck dependency boundary OK (full transitive tree)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
