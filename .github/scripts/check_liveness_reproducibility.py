#!/usr/bin/env python3
"""Pinned-environment reproducibility gate for unbounded fair-liveness artifacts.

Runs fair-liveness certification twice with identical inputs and requires
stable certificate metadata + obligation hashes across runs.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run_certify(out_dir: Path) -> dict:
    cmd = [
        "cargo",
        "run",
        "-p",
        "tarsier-cli",
        "--features",
        "governance",
        "--",
        "certify-fair-liveness",
        "examples/library/pbft_liveness_safe_ci.trs",
        "--fairness",
        "weak",
        "--k",
        "8",
        "--timeout",
        "120",
        "--out",
        str(out_dir),
    ]
    subprocess.run(cmd, cwd=ROOT, check=True, text=True)

    cert_path = out_dir / "certificate.json"
    if not cert_path.exists():
        raise RuntimeError(f"missing certificate metadata: {cert_path}")
    metadata = json.loads(cert_path.read_text(encoding="utf-8"))

    obligations = []
    for obligation in metadata.get("obligations", []):
        file_name = obligation["file"]
        smt_path = out_dir / file_name
        if not smt_path.exists():
            raise RuntimeError(f"missing obligation file: {smt_path}")
        obligations.append(
            {
                "name": obligation["name"],
                "expected": obligation["expected"],
                "file": file_name,
                "sha256_meta": obligation.get("sha256"),
                "sha256_file": sha256_file(smt_path),
            }
        )
    obligations.sort(key=lambda o: (o["name"], o["expected"], o["file"]))

    return {
        "kind": metadata.get("kind"),
        "proof_engine": metadata.get("proof_engine"),
        "induction_k": metadata.get("induction_k"),
        "solver_used": metadata.get("solver_used"),
        "soundness": metadata.get("soundness"),
        "fairness": metadata.get("fairness"),
        "committee_bounds": metadata.get("committee_bounds", []),
        "bundle_sha256": metadata.get("bundle_sha256"),
        "obligations": obligations,
    }


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="tarsier-live-repro-"))
    try:
        run_a = work / "run-a"
        run_b = work / "run-b"
        run_a.mkdir(parents=True, exist_ok=True)
        run_b.mkdir(parents=True, exist_ok=True)

        cert_a = run_certify(run_a)
        cert_b = run_certify(run_b)

        if cert_a != cert_b:
            raise RuntimeError(
                "fair-liveness certificate artifacts are not reproducible under identical inputs"
            )

        print("[PASS] fair-liveness reproducibility gate")
        print(
            f"        proof_engine={cert_a['proof_engine']} k/frame={cert_a['induction_k']} "
            f"bundle_sha256={cert_a['bundle_sha256']}"
        )
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
