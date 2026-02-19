# Library Benchmarks

Run deterministic `analyze` passes across the protocol library:

```bash
python3 benchmarks/run_library_bench.py --mode standard --depth 8 --timeout 120
```

By default, the benchmark checks run integrity (analysis completed and emitted JSON), not protocol correctness. To require all models to be overall PASS:

```bash
python3 benchmarks/run_library_bench.py --mode standard --require-pass
```

To enforce manifest verdict expectations (`verify`, `liveness`, `fair_liveness`, `prove`, `prove_fair`):

```bash
python3 benchmarks/run_library_bench.py --mode proof --require-expectations
```

Useful variants:

```bash
# Fast bug-finding profile
python3 benchmarks/run_library_bench.py --mode quick --depth 6

# Proof-mode profile
python3 benchmarks/run_library_bench.py --mode proof --k 16 --timeout 180

# Proof-mode profile with strict manifest expectation checks
python3 benchmarks/run_library_bench.py --mode proof --k 16 --timeout 180 --require-expectations

# Audit profile with explicit output file
python3 benchmarks/run_library_bench.py --mode audit --out benchmarks/results/audit.json

# CI-style perf gate (fails on significant regressions)
python3 benchmarks/run_library_bench.py --mode quick --depth 4 --timeout 90 \
  --samples 3 \
  --perf-budget benchmarks/budgets/ci-quick-smoke-budget.json \
  --out benchmarks/results/ci-library-smoke.json

# Large faithful/crypto-heavy suite
python3 benchmarks/run_library_bench.py --mode quick --depth 4 --timeout 120 \
  --samples 3 \
  --protocols benchmarks/protocols-large.txt \
  --perf-budget benchmarks/budgets/large-smoke-budget.json \
  --out benchmarks/results/ci-library-large-smoke.json
```

Inputs:
- Default: `examples/library/cert_suite.json` (full canonical corpus with family/class metadata).
- Optional override: `--protocols benchmarks/protocols.txt`.
  - Large-model subset: `--protocols benchmarks/protocols-large.txt`.

Outputs:
- JSON report with per-protocol status, timing, embedded `analyze` report, and family/class summaries.
- Optional `performance_gate` section when `--perf-budget` is provided. It reports
  significant per-protocol/total regressions, hard-limit offenders, and pass/fail status.
- Default path: `benchmarks/results/library-bench-<timestamp>.json`.

Performance budget format:
- `baseline.total_elapsed_ms`, `baseline.protocol_elapsed_ms`: tracked baseline timings.
- `thresholds.*`: significant-regression thresholds (percent + absolute-ms, plus minimum protocol count).
- `hard_limits.*`: absolute ceilings for single-protocol and total elapsed time.
- Optional bootstrap significance:
  - `statistics.enabled=true`, `statistics.confidence`, `statistics.bootstrap_samples`, `statistics.min_samples`.
  - `baseline.protocol_elapsed_samples_ms[protocol]` lists baseline samples used for solver-backed significance checks.
