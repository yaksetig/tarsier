#!/usr/bin/env python3
"""Deterministic ByMC-compatible mock adapter for cross-tool CI scenarios.

This script emulates ByMC CLI output conventions used by the runner:
- safe: prints "property satisfied"
- unsafe: prints "error found" + "counterexample"
"""

from __future__ import annotations

import os
import sys


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: mock_bymc.py <model_file> [--bound N]", file=sys.stderr)
        return 2

    model_file = sys.argv[1]
    name = os.path.basename(model_file).lower()
    if "buggy" in name or "disagreement" in name:
        print("error found")
        print("counterexample trace")
        return 0

    print("property satisfied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
