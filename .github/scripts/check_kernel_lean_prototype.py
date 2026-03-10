#!/usr/bin/env python3
"""Validate Lean prototype artifact sync and theorem check."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ARTIFACT = ROOT / "artifacts" / "kernel-semantics" / "kernel_semantics_v1.json"
LEAN_MODULE = ROOT / "artifacts" / "kernel-semantics" / "lean" / "KernelSemanticsV1.lean"
EXPORTER = ROOT / ".github" / "scripts" / "export_kernel_semantics_lean.py"


def fail(message: str) -> int:
    print(f"Kernel Lean prototype check FAILED: {message}", file=sys.stderr)
    return 1


def run_checked(cmd: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)
    if proc.returncode != 0:
        joined = " ".join(cmd)
        raise RuntimeError(
            f"command failed ({joined})\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    return proc


def main() -> int:
    if not ARTIFACT.exists():
        return fail(f"artifact not found: {ARTIFACT}")
    if not LEAN_MODULE.exists():
        return fail(f"Lean module not found: {LEAN_MODULE}")
    if not EXPORTER.exists():
        return fail(f"exporter script not found: {EXPORTER}")

    try:
        with tempfile.TemporaryDirectory(prefix="kernel-lean-prototype-") as tmpdir:
            regenerated = Path(tmpdir) / "KernelSemanticsV1.lean"
            run_checked(
                [
                    sys.executable,
                    str(EXPORTER),
                    "--artifact",
                    str(ARTIFACT),
                    "--out",
                    str(regenerated),
                ],
                cwd=ROOT,
            )
            expected = LEAN_MODULE.read_text(encoding="utf-8")
            actual = regenerated.read_text(encoding="utf-8")
            if expected != actual:
                return fail(
                    "committed Lean module is out of sync with "
                    f"{ARTIFACT}. Regenerate via {EXPORTER}."
                )
    except RuntimeError as err:
        return fail(str(err))

    lean = shutil.which("lean")
    if not lean:
        return fail("Lean binary not found in PATH")

    try:
        run_checked([lean, str(LEAN_MODULE)], cwd=ROOT)
    except RuntimeError as err:
        return fail(str(err))

    print("Kernel Lean prototype check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
