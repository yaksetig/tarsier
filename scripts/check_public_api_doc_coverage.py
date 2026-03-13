#!/usr/bin/env python3
"""Check rustdoc coverage for externally public Rust API items.

The scan is intentionally lightweight: it walks workspace Rust sources, skips
tests/benches/examples, and counts `pub` items that expose externally visible
APIs. Items documented with `///` or `#[doc = ...]` are considered covered.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path


IGNORED_PATH_PARTS = ("/tests/", "/benches/", "/examples/", "/target/")
IGNORED_FILE_NAMES = {"tests.rs"}
DOC_ATTR_PREFIXES = ("#[doc",)
SKIPPED_ATTR_FRAGMENTS = ("cfg(test)", "cfg(all(test", "cfg(any(test)")

# Count externally public items and methods. Restricted visibilities such as
# `pub(crate)` are excluded because this gate targets the user-visible API.
PUBLIC_ITEM_RE = re.compile(
    r"^pub\s+(?:(?:async|const|unsafe)\s+)*"
    r"(?:fn|struct|enum|trait|type|mod|const|static)\b"
)


@dataclass
class FileCoverage:
    path: Path
    documented: int = 0
    total: int = 0

    @property
    def pct(self) -> float:
        if self.total == 0:
            return 100.0
        return (self.documented / self.total) * 100.0


def should_skip_path(path: Path) -> bool:
    as_posix = path.as_posix()
    if path.name in IGNORED_FILE_NAMES:
        return True
    return any(fragment in as_posix for fragment in IGNORED_PATH_PARTS)


def preceding_doc_and_attrs(lines: list[str], index: int) -> tuple[bool, list[str]]:
    """Return whether an item has docs and the contiguous attribute block above it."""
    attrs: list[str] = []
    has_docs = False
    j = index - 1

    while j >= 0:
        stripped = lines[j].lstrip()
        if stripped == "":
            if attrs or has_docs:
                j -= 1
                continue
            break
        if stripped.startswith("///"):
            has_docs = True
            j -= 1
            continue
        if any(stripped.startswith(prefix) for prefix in DOC_ATTR_PREFIXES):
            has_docs = True
            attrs.append(stripped)
            j -= 1
            continue
        if stripped.startswith("#["):
            attrs.append(stripped)
            j -= 1
            continue
        break

    return has_docs, attrs


def measure_file(path: Path) -> FileCoverage:
    lines = path.read_text(encoding="utf-8").splitlines()
    coverage = FileCoverage(path=path)

    for i, line in enumerate(lines):
        stripped = line.lstrip()
        if not PUBLIC_ITEM_RE.match(stripped):
            continue

        has_docs, attrs = preceding_doc_and_attrs(lines, i)
        if any(fragment in attr for attr in attrs for fragment in SKIPPED_ATTR_FRAGMENTS):
            continue

        coverage.total += 1
        if has_docs:
            coverage.documented += 1

    return coverage


def collect_rust_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for current_root, _, names in os.walk(root):
        for name in names:
            if not name.endswith(".rs"):
                continue
            path = Path(current_root) / name
            if should_skip_path(path):
                continue
            files.append(path)
    return sorted(files)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        default="crates",
        help="Root directory to scan for Rust sources (default: crates).",
    )
    parser.add_argument(
        "--min-pct",
        type=float,
        default=60.0,
        help="Minimum required documented coverage percentage (default: 60).",
    )
    parser.add_argument(
        "--show-worst",
        type=int,
        default=15,
        help="How many lowest-coverage files to print (default: 15).",
    )
    args = parser.parse_args()

    root = Path(args.root).resolve()
    files = collect_rust_files(root)
    if not files:
        print(f"No Rust files found under {root}", file=sys.stderr)
        return 2

    per_file = [measure_file(path) for path in files]
    total = sum(item.total for item in per_file)
    documented = sum(item.documented for item in per_file)
    pct = 100.0 if total == 0 else (documented / total) * 100.0

    print(
        "Public API rustdoc coverage: "
        f"{documented}/{total} items documented ({pct:.1f}%)"
    )

    worst = [item for item in per_file if item.total > 0]
    worst.sort(key=lambda item: (item.pct, -item.total, item.path.as_posix()))
    print("Lowest-coverage files:")
    for item in worst[: args.show_worst]:
        rel = item.path.relative_to(Path.cwd())
        print(
            f"  {item.documented:3}/{item.total:3}  {item.pct:5.1f}%  {rel.as_posix()}"
        )

    if pct + 1e-9 < args.min_pct:
        print(
            f"FAIL: coverage {pct:.1f}% is below required minimum {args.min_pct:.1f}%",
            file=sys.stderr,
        )
        return 1

    print(f"OK: coverage meets minimum {args.min_pct:.1f}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
