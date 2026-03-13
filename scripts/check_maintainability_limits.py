#!/usr/bin/env python3
"""Guard against oversized production Rust files and functions.

The check is diff-aware: it compares the current working tree to a git base
revision and fails when a change introduces a new oversized production module or
grows an already-oversized module/function beyond a small allowance.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path


WORKSPACE_ROOTS = ("crates", "playground")
IGNORED_PATH_PARTS = ("/tests/", "/benches/", "/examples/", "/target/")
IGNORED_FILE_NAMES = {"tests.rs"}
MAX_FILE_LINES = 1500
MAX_EXISTING_OVERSIZED_FILE_GROWTH = 25
MAX_FUNCTION_LINES = 250
MAX_EXISTING_OVERSIZED_FUNCTION_GROWTH = 10

FUNCTION_RE = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?"
    r"(?:(?:async|const|unsafe|extern(?:\s+\"[^\"]+\")?)\s+)*"
    r"fn\s+([A-Za-z_][A-Za-z0-9_]*)\b"
)


@dataclass(frozen=True)
class FunctionSpan:
    key: str
    name: str
    start_line: int
    line_count: int


def run_git(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=Path.cwd(),
        text=True,
        capture_output=True,
        check=check,
    )


def existing_roots() -> list[str]:
    return [root for root in WORKSPACE_ROOTS if Path(root).exists()]


def is_production_rust_path(path_str: str) -> bool:
    path = Path(path_str)
    if path.suffix != ".rs":
        return False
    if path.name in IGNORED_FILE_NAMES:
        return False
    as_posix = path.as_posix()
    if any(fragment in as_posix for fragment in IGNORED_PATH_PARTS):
        return False
    return any(as_posix == root or as_posix.startswith(f"{root}/") for root in WORKSPACE_ROOTS)


def changed_files(base: str) -> list[Path]:
    roots = existing_roots()
    diff = run_git("diff", "--name-only", "--diff-filter=ACMR", base, "--", *roots)
    tracked = {line.strip() for line in diff.stdout.splitlines() if line.strip()}

    untracked_proc = run_git("ls-files", "--others", "--exclude-standard", "--", *roots)
    untracked = {line.strip() for line in untracked_proc.stdout.splitlines() if line.strip()}

    paths = tracked | untracked
    return sorted(Path(path) for path in paths if is_production_rust_path(path))


def read_base_file(base: str, path: Path) -> str | None:
    proc = run_git("show", f"{base}:{path.as_posix()}", check=False)
    if proc.returncode != 0:
        return None
    return proc.stdout


def strip_non_code(text: str) -> str:
    result: list[str] = []
    i = 0
    block_comment_depth = 0
    in_line_comment = False
    in_string = False
    raw_string_hashes: int | None = None

    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""

        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
                result.append(ch)
            else:
                result.append(" ")
            i += 1
            continue

        if block_comment_depth > 0:
            if ch == "/" and nxt == "*":
                block_comment_depth += 1
                result.extend((" ", " "))
                i += 2
                continue
            if ch == "*" and nxt == "/":
                block_comment_depth -= 1
                result.extend((" ", " "))
                i += 2
                continue
            result.append("\n" if ch == "\n" else " ")
            i += 1
            continue

        if in_string:
            if ch == "\\":
                result.append(" ")
                if i + 1 < len(text):
                    result.append(" ")
                    i += 2
                else:
                    i += 1
                continue
            result.append("\n" if ch == "\n" else " ")
            if ch == '"':
                in_string = False
            i += 1
            continue

        if raw_string_hashes is not None:
            if ch == '"' and text.startswith("#" * raw_string_hashes, i + 1):
                result.append(" ")
                result.extend(" " for _ in range(raw_string_hashes))
                i += 1 + raw_string_hashes
                raw_string_hashes = None
                continue
            result.append("\n" if ch == "\n" else " ")
            i += 1
            continue

        if ch == "/" and nxt == "/":
            in_line_comment = True
            result.extend((" ", " "))
            i += 2
            continue
        if ch == "/" and nxt == "*":
            block_comment_depth = 1
            result.extend((" ", " "))
            i += 2
            continue

        if ch == "r":
            j = i + 1
            while j < len(text) and text[j] == "#":
                j += 1
            if j < len(text) and text[j] == '"':
                raw_string_hashes = j - (i + 1)
                result.extend(" " for _ in range(j - i + 1))
                i = j + 1
                continue
        if ch == "b" and nxt == "r":
            j = i + 2
            while j < len(text) and text[j] == "#":
                j += 1
            if j < len(text) and text[j] == '"':
                raw_string_hashes = j - (i + 2)
                result.extend(" " for _ in range(j - i + 1))
                i = j + 1
                continue

        if ch == '"':
            in_string = True
            result.append(" ")
            i += 1
            continue

        result.append(ch)
        i += 1

    return "".join(result)


def collect_functions(text: str) -> dict[str, FunctionSpan]:
    sanitized_lines = strip_non_code(text).splitlines()
    functions: dict[str, FunctionSpan] = {}
    name_occurrences: dict[str, int] = defaultdict(int)
    line_count = len(sanitized_lines)
    i = 0

    while i < line_count:
        match = FUNCTION_RE.match(sanitized_lines[i])
        if not match:
            i += 1
            continue

        name = match.group(1)
        start_idx = i
        j = i
        found_body = False
        balance = 0
        bodyless = False

        while j < line_count:
            line = sanitized_lines[j]
            semicolon = line.find(";")
            opening = line.find("{")
            if not found_body:
                if semicolon != -1 and (opening == -1 or semicolon < opening):
                    bodyless = True
                    break
                if opening == -1:
                    j += 1
                    continue
                found_body = True
            balance += line.count("{") - line.count("}")
            if found_body and balance <= 0:
                occurrence = name_occurrences[name]
                name_occurrences[name] += 1
                key = f"{name}#{occurrence}"
                functions[key] = FunctionSpan(
                    key=key,
                    name=name,
                    start_line=start_idx + 1,
                    line_count=j - start_idx + 1,
                )
                i = j + 1
                break
            j += 1

        if bodyless:
            i = start_idx + 1
            continue
        if not found_body or balance > 0:
            i = start_idx + 1

    return functions


def pluralize(count: int, singular: str, plural: str) -> str:
    return singular if count == 1 else plural


def describe_delta(current: int, previous: int | None) -> str:
    if previous is None:
        return f"new at {current} lines"
    delta = current - previous
    if delta == 0:
        return f"unchanged at {current} lines"
    sign = "+" if delta > 0 else ""
    return f"{previous} -> {current} lines ({sign}{delta})"


def file_failures(paths: list[Path], base: str) -> tuple[list[str], list[str]]:
    failures: list[str] = []
    notices: list[str] = []

    for path in paths:
        current_text = path.read_text(encoding="utf-8")
        current_lines = len(current_text.splitlines())
        previous_text = read_base_file(base, path)
        previous_lines = None if previous_text is None else len(previous_text.splitlines())

        if current_lines <= MAX_FILE_LINES:
            continue

        if previous_lines is None:
            failures.append(
                f"{path.as_posix()}: oversized new file ({current_lines} lines > {MAX_FILE_LINES})"
            )
            continue
        if previous_lines <= MAX_FILE_LINES:
            failures.append(
                f"{path.as_posix()}: crossed file limit ({describe_delta(current_lines, previous_lines)}; "
                f"limit {MAX_FILE_LINES})"
            )
            continue

        growth = current_lines - previous_lines
        if growth > MAX_EXISTING_OVERSIZED_FILE_GROWTH:
            failures.append(
                f"{path.as_posix()}: oversized file grew too much ({describe_delta(current_lines, previous_lines)}; "
                f"budget +{MAX_EXISTING_OVERSIZED_FILE_GROWTH})"
            )
        elif growth > 0:
            notices.append(
                f"{path.as_posix()}: oversized file changed slightly ({describe_delta(current_lines, previous_lines)})"
            )

    return failures, notices


def function_failures(paths: list[Path], base: str) -> tuple[list[str], list[str]]:
    failures: list[str] = []
    notices: list[str] = []

    for path in paths:
        current_text = path.read_text(encoding="utf-8")
        current_functions = collect_functions(current_text)
        previous_text = read_base_file(base, path)
        previous_functions = {} if previous_text is None else collect_functions(previous_text)

        for key, function in current_functions.items():
            if function.line_count <= MAX_FUNCTION_LINES:
                continue

            previous = previous_functions.get(key)
            previous_lines = None if previous is None else previous.line_count
            location = f"{path.as_posix()}:{function.start_line} {function.name}"

            if previous_lines is None:
                failures.append(
                    f"{location}: oversized new function ({function.line_count} lines > {MAX_FUNCTION_LINES})"
                )
                continue
            if previous_lines <= MAX_FUNCTION_LINES:
                failures.append(
                    f"{location}: crossed function limit ({describe_delta(function.line_count, previous_lines)}; "
                    f"limit {MAX_FUNCTION_LINES})"
                )
                continue

            growth = function.line_count - previous_lines
            if growth > MAX_EXISTING_OVERSIZED_FUNCTION_GROWTH:
                failures.append(
                    f"{location}: oversized function grew too much "
                    f"({describe_delta(function.line_count, previous_lines)}; "
                    f"budget +{MAX_EXISTING_OVERSIZED_FUNCTION_GROWTH})"
                )
            elif growth > 0:
                notices.append(
                    f"{location}: oversized function changed slightly "
                    f"({describe_delta(function.line_count, previous_lines)})"
                )

    return failures, notices


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--base",
        default="HEAD",
        help="Git revision to compare against (default: HEAD).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        run_git("rev-parse", "--verify", args.base)
    except subprocess.CalledProcessError as exc:
        print(exc.stderr.strip() or f"Unknown git base '{args.base}'", file=sys.stderr)
        return 2

    paths = changed_files(args.base)
    print(
        "Maintainability guard: "
        f"{len(paths)} changed production Rust {pluralize(len(paths), 'file', 'files')} "
        f"checked against {args.base}"
    )

    if not paths:
        print("OK: no changed production Rust files matched the maintainability scan")
        return 0

    failures: list[str] = []
    notices: list[str] = []

    file_issues, file_notices = file_failures(paths, args.base)
    function_issues, function_notices = function_failures(paths, args.base)
    failures.extend(file_issues)
    failures.extend(function_issues)
    notices.extend(file_notices)
    notices.extend(function_notices)

    if notices:
        print("Notes:")
        for notice in notices:
            print(f"  - {notice}")

    if failures:
        print("FAIL: maintainability limits violated")
        for failure in failures:
            print(f"  - {failure}")
        print(
            "Thresholds: "
            f"files <= {MAX_FILE_LINES} lines "
            f"(existing oversized files may grow by at most +{MAX_EXISTING_OVERSIZED_FILE_GROWTH}); "
            f"functions <= {MAX_FUNCTION_LINES} lines "
            f"(existing oversized functions may grow by at most +{MAX_EXISTING_OVERSIZED_FUNCTION_GROWTH})."
        )
        return 1

    print("OK: no changed production Rust files/functions exceeded maintainability limits")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
