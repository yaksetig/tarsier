#!/usr/bin/env python3
"""Verify that release documentation only references files that exist in the repo.

Parses RELEASE_CHECKLIST.md and RELEASE_PROCESS.md for file paths and script
invocations, then checks each referenced path exists.  Exits with code 1 on
any broken reference.

This prevents documentation drift where steps reference scripts/files that
have been moved, renamed, or deleted.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[2]

# Docs to scan.
DOCS = [
    ROOT / "docs" / "RELEASE_CHECKLIST.md",
    ROOT / "docs" / "RELEASE_PROCESS.md",
]

# Patterns that extract repo-relative file paths from markdown.
# Only match paths that contain a `/` (directory component) — bare filenames
# like `cert_suite.json` are prose references, not repo paths.
PATH_PATTERNS = [
    # Backtick-quoted paths with at least one slash: `dir/file.ext`
    re.compile(r"`(\.?/?[a-zA-Z0-9_.-]+/[a-zA-Z0-9_./-]+)`"),
    # Bare paths starting with known directory prefixes (not in backticks)
    re.compile(r"(?:^|[\s(])(\.github/[a-zA-Z0-9_./-]+)", re.MULTILINE),
    re.compile(r"(?:^|[\s(])(scripts/[a-zA-Z0-9_./-]+)", re.MULTILINE),
    re.compile(r"(?:^|[\s(])(docs/[a-zA-Z0-9_./-]+)", re.MULTILINE),
    re.compile(r"(?:^|[\s(])(crates/[a-zA-Z0-9_./-]+)", re.MULTILINE),
    re.compile(r"(?:^|[\s(])(benchmarks/[a-zA-Z0-9_./-]+)", re.MULTILINE),
    re.compile(r"(?:^|[\s(])(examples/[a-zA-Z0-9_./-]+)", re.MULTILINE),
]

# Paths to skip — output directories, artifact names, placeholders.
SKIP_PREFIXES = [
    "artifacts/",
    "certs/",
    "target/",
    "tarsier-x86_64",
    "tarsier-aarch64",
]

# Known file extensions for repo files.
REPO_EXTENSIONS = {
    ".md", ".py", ".sh", ".toml", ".json", ".yml", ".yaml", ".trs",
    ".rs", ".txt", ".lock",
}


def normalize(raw: str) -> str:
    """Normalize a raw path reference to a repo-relative path."""
    # Remove leading ./ prefix (as a string prefix, not per-char)
    if raw.startswith("./"):
        raw = raw[2:]
    # Remove leading / if any
    if raw.startswith("/"):
        raw = raw[1:]
    # Strip trailing punctuation that may come from markdown
    raw = raw.rstrip(")")
    return raw


def is_repo_path(path: str) -> bool:
    """Heuristic: should this normalized path be checked for existence?"""
    for prefix in SKIP_PREFIXES:
        if path.startswith(prefix):
            return False

    # Must have a directory component.
    if "/" not in path:
        return False

    # Must have a recognized extension.
    ext = Path(path).suffix
    if ext not in REPO_EXTENSIONS:
        return False

    # Skip URLs.
    if "://" in path:
        return False

    # Skip glob patterns (*.ext).
    if "*" in path:
        return False

    return True


def extract_paths(text: str) -> set[str]:
    """Extract candidate file paths from markdown text."""
    paths: set[str] = set()
    for pattern in PATH_PATTERNS:
        for match in pattern.finditer(text):
            raw = match.group(1)
            clean = normalize(raw)
            if is_repo_path(clean):
                paths.add(clean)
    return paths


def main() -> int:
    errors: list[str] = []
    total = 0

    for doc_path in DOCS:
        if not doc_path.exists():
            errors.append(f"missing doc: {doc_path.relative_to(ROOT)}")
            continue

        text = doc_path.read_text(encoding="utf-8")
        doc_name = str(doc_path.relative_to(ROOT))
        paths = extract_paths(text)
        total += len(paths)

        for ref_path in sorted(paths):
            full = ROOT / ref_path
            if not full.exists():
                errors.append(f"{doc_name}: references `{ref_path}` which does not exist")

    if errors:
        print("Release doc reference check FAILED:")
        for err in errors:
            print(f"  - {err}")
        return 1

    print(f"Release doc reference check passed ({total} paths verified).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
