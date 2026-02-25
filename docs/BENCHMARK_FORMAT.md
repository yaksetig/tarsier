# Benchmark Report Format (v1)

This document defines the public benchmark report contract emitted by
`benchmarks/run_library_bench.py` and replayed by
`benchmarks/replay_library_bench.py`.

Machine-readable schema: `docs/benchmark-report-schema-v1.json`

## Scope

The format is intended for:

- reproducible benchmark replay;
- CI/regression gating;
- external consumers that compare protocol-level outcomes across revisions.

## Top-Level Fields

Required top-level keys:

- `schema_version` (must be `1`)
- `started_at_utc`, `finished_at_utc`
- `config`
- `environment`
- `summary`
- `performance_gate`
- `scale_band_gate`
- `replay`
- `runs`

## Deterministic Replay Contract

`replay` defines deterministic equivalence metadata:

- `harness`: replay tool path
- `plan_sha256`: hash over replay-driving inputs (config + ordered protocol list + protocol hashes)
- `result_sha256`: hash over canonical functional results
- `deterministic_fields`: fields that must match across identical replay
- `nondeterministic_fields`: fields intentionally excluded from replay equivalence

Each run entry includes:

- `protocol`
- `protocol_sha256` (required for source-fidelity checks)
- functional result fields (`overall`, `ok`, `run_is_valid`, `expectations`, layer verdicts)

## Replay Harness

Run deterministic replay from a prior report:

```bash
python3 benchmarks/replay_library_bench.py \
  --report benchmarks/results/ci-library-smoke.json \
  --max-protocols 1 \
  --skip-build \
  --out-report benchmarks/results/ci-library-smoke-replay.json \
  --out-comparison benchmarks/results/ci-library-smoke-replay-compare.json
```

Exit status:

- `0`: deterministic replay projection matches baseline
- `2`: mismatch (or invalid baseline report)

The comparison artifact includes mismatch paths and replay/baseline hashes.

## Reproducibility Requirements

For governance-grade benchmark claims, all of the following are required:

1. Pinned runtime environment (OS + Rust + solvers)
2. Verified protocol file hashes (`runs[].protocol_sha256`)
3. Same benchmark config (mode/solver/depth/k/timeout/soundness/fairness)
4. Same replay selection policy (`require_pass`, `require_expectations`)

## Pinned Environment Requirements

Pinned benchmark jobs in CI use:

- OS: `ubuntu-22.04`
- Rust: `1.92.0`
- Z3: `4.12.5`
- cvc5: `1.1.2`

Verification gate:

```bash
./.github/scripts/verify_pinned_env.sh
```

Do not publish or compare benchmark deltas as authoritative unless the pinned
environment gate has passed.

## Versioning Policy

- `schema_version` is exact-match (no forward-compat acceptance).
- Any incompatible field or semantic change requires:
  1. schema update (`docs/benchmark-report-schema-v1.json`)
  2. doc update (this file)
  3. harness update (`benchmarks/replay_library_bench.py`)
  4. CI gate update
