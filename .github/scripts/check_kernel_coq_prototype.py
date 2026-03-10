#!/usr/bin/env python3
"""Validate Coq prototype artifact sync and theorem check."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ARTIFACT = ROOT / "artifacts" / "kernel-semantics" / "kernel_semantics_v1.json"
COQ_MODULE = ROOT / "artifacts" / "kernel-semantics" / "coq" / "KernelSemanticsV1.v"
EXPORTER = ROOT / ".github" / "scripts" / "export_kernel_semantics_coq.py"


def fail(message: str) -> int:
    print(f"Kernel Coq prototype check FAILED: {message}", file=sys.stderr)
    return 1


def run_checked(cmd: list[str], cwd: Path | None = None) -> None:
    proc = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)
    if proc.returncode != 0:
        joined = " ".join(cmd)
        raise RuntimeError(
            f"command failed ({joined})\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--skip-coqc",
        action="store_true",
        help="Skip coqc invocation (useful for local checks when Coq is unavailable).",
    )
    args = parser.parse_args()

    if not ARTIFACT.exists():
        return fail(f"artifact not found: {ARTIFACT}")
    if not COQ_MODULE.exists():
        return fail(f"Coq module not found: {COQ_MODULE}")
    if not EXPORTER.exists():
        return fail(f"exporter script not found: {EXPORTER}")

    try:
        with tempfile.TemporaryDirectory(prefix="kernel-coq-prototype-") as tmpdir_str:
            tmpdir = Path(tmpdir_str)
            regenerated = tmpdir / "KernelSemanticsV1.v"
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

            expected = COQ_MODULE.read_text(encoding="utf-8")
            actual = regenerated.read_text(encoding="utf-8")
            if expected != actual:
                return fail(
                    "committed Coq module is out of sync with "
                    f"{ARTIFACT}. Regenerate via {EXPORTER}."
                )

            if not args.skip_coqc:
                coqc = shutil.which("coqc")
                if not coqc:
                    return fail("coqc binary not found in PATH")
                run_checked([coqc, "-q", str(regenerated)], cwd=tmpdir)
    except RuntimeError as err:
        return fail(str(err))

    if args.skip_coqc:
        print("Kernel Coq prototype sync check passed (coqc skipped).")
    else:
        print("Kernel Coq prototype check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
