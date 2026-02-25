#!/usr/bin/env python3
"""Deterministic SPIN-compatible mock adapter for cross-tool CI scenarios.

This script emulates SPIN output conventions used by the runner:
- safe: prints "errors: 0"
- unsafe: prints a generic "error" line
"""

from __future__ import annotations

import os
import sys


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: mock_spin.py <model_file>", file=sys.stderr)
        return 2

    model_file = sys.argv[1]
    name = os.path.basename(model_file).lower()
    if "buggy" in name or "disagreement" in name:
        print("error: assertion violated")
        return 0

    print("errors: 0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
