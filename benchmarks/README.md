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
- Format contract: `docs/BENCHMARK_FORMAT.md` + `docs/benchmark-report-schema-v1.json`.
- Optional `performance_gate` section when `--perf-budget` is provided. It reports
  significant per-protocol/total regressions, hard-limit offenders, and pass/fail status.
- Default path: `benchmarks/results/library-bench-<timestamp>.json`.
- CI trend artifacts: `library-benchmark-smoke` and `library-benchmark-large` upload benchmark JSON artifacts on every run, enabling historical regression triage over time.

Deterministic replay:

```bash
python3 benchmarks/replay_library_bench.py \
  --report benchmarks/results/ci-library-smoke.json \
  --max-protocols 1 \
  --skip-build \
  --out-report benchmarks/results/ci-library-smoke-replay.json \
  --out-comparison benchmarks/results/ci-library-smoke-replay-compare.json
```

Pinned-environment requirement for publishable comparisons:

```bash
./.github/scripts/verify_pinned_env.sh
```

Quantitative golden ranges:
- Manifest: `benchmarks/quantitative-golden-ranges.json`
- Gate test: `cargo test -p tarsier-engine quantitative_golden_range_manifest_entries_hold -- --exact --nocapture`
- CI coverage: included in `cargo test --all-targets` (build-test job).

Performance budget format:
- `baseline.total_elapsed_ms`, `baseline.protocol_elapsed_ms`: tracked baseline timings.
- `thresholds.*`: significant-regression thresholds (percent + absolute-ms, plus minimum protocol count).
- `hard_limits.*`: absolute ceilings for single-protocol and total elapsed time.
- Statistical regression thresholding (bootstrap significance testing):
  - `statistics.enabled=true`, `statistics.confidence`, `statistics.bootstrap_samples`, `statistics.min_samples`.
  - `baseline.protocol_elapsed_samples_ms[protocol]` lists baseline samples used for solver-backed significance checks.
  - When enabled, per-protocol regressions are only flagged if the bootstrap 95% CI
    lower bound exceeds the threshold — eliminating single-run noise.
  - Each regressed protocol entry includes `statistics.delta_ci_ms` (CI bounds),
    `statistics.confidence`, and `statistics.significant` decision.
  - Unit tests: `python3 benchmarks/test_statistical_regression.py` (CI gate in `build-test` job).

Scale behavior bands:
- `scale_bands.bands`: defines computational-cost tiers with `min_ms`/`max_ms` ranges.
  - `small` (0–100 ms): simple protocols, low state space.
  - `medium` (100–500 ms): moderate complexity, faithful models without crypto QC.
  - `large` (500–2000 ms): crypto-heavy faithful models with QC witnesses.
- `scale_bands.protocol_bands`: maps each protocol to its expected band.
- At runtime, the `scale_band_gate` checks each protocol's observed median against its
  declared band and fails if any protocol falls outside its range.
- Budget consistency: `.github/scripts/check_benchmark_budgets.py` validates that all
  baselines have band assignments, bands don't overlap, and baseline medians fall within
  declared ranges.

## Cross-Tool Benchmark Runner

Run normalized verification scenarios across multiple tools (Tarsier, ByMC, SPIN)
and produce an apples-to-apples comparison report:

```bash
# Run across tarsier and bymc (default tools)
python3 benchmarks/cross_tool_runner.py \
  --manifest benchmarks/cross_tool_scenarios/scenario_manifest.json \
  --tools tarsier,bymc \
  --out benchmarks/results/cross-tool-report.json

# Run across all three tools
python3 benchmarks/cross_tool_runner.py \
  --tools tarsier,bymc,spin \
  --out benchmarks/results/cross-tool-all.json

# Run only external-tool adapters (deterministic CI path)
python3 benchmarks/cross_tool_runner.py \
  --tools bymc,spin \
  --bymc-binary "$(python3 -c 'import sys; print(sys.executable)')" \
  --spin-binary "$(python3 -c 'import sys; print(sys.executable)')" \
  --out benchmarks/results/cross-tool-external-only.json
```

Each scenario in the manifest specifies:
- Protocol property and expected verdict
- Normalized assumptions (fault model, resilience bound, network model)
- Per-tool model files and invocation parameters

The default scenario manifest includes deterministic ByMC/SPIN-compatible
adapters via:
- `benchmarks/mock_tools/mock_bymc.py`
- `benchmarks/mock_tools/mock_spin.py`

This keeps cross-tool execution reproducible in CI. For real tool runs, replace
the scenario `command_template` entries and pass real binaries through
`--bymc-binary` / `--spin-binary`.

Output report normalizes:
- Verdicts to a common vocabulary: `safe`, `unsafe`, `timeout`, `unknown`, `error`
- Assumptions to uniform fields: `fault_model`, `fault_bound`, `network_model`, `message_loss`
- Timing metrics per tool per scenario for direct comparison
- Agreement tracking: whether all tools with verdicts agree

Report schema: `docs/cross-tool-benchmark-report-schema-v1.json`

Scenario manifest: `benchmarks/cross_tool_scenarios/scenario_manifest.json`

Tests: `python3 -m unittest benchmarks/test_cross_tool_runner.py -v`

### Mock vs Real External Tool Execution

Each tool entry in the scenario manifest includes an `execution_mode` field:

- **`mock`**: The tool is invoked via a deterministic mock adapter
  (`benchmarks/mock_tools/mock_bymc.py`, `benchmarks/mock_tools/mock_spin.py`).
  Mock mode is used in CI for reproducible verdicts without requiring external
  tool binaries.

- **`real`**: The tool is invoked with the actual binary. Use this when running
  against a real ByMC or SPIN installation. Swap `command_template` entries and
  pass real binaries through `--bymc-binary` / `--spin-binary`.

The `execution_mode` is propagated into each per-tool result in the report, and
a summary of modes used appears in the top-level `tools.execution_modes` section.
The CI verdict parity gate (`check_cross_tool_verdict_parity.py`) only flags
disagreements between non-mock tools as failures.

All `.ta` model files in the corpus must be real threshold automaton models (not
placeholders). The CI contract check (`check_cross_tool_benchmark_contract.py`)
enforces that each `.ta` file has at least 5 non-empty lines, contains no
`placeholder` comments, and has non-empty `specifications`.

### Running with Real ByMC

The cross-tool runner supports real [ByMC](https://github.com/konnov/bymc)
verification via Docker. The default CI path uses mock adapters; real mode is
opt-in.

```bash
# 1. Build the ByMC Docker image (one-time, requires Docker)
bash benchmarks/bymc/build-docker.sh

# 2. Run with real ByMC
python3 benchmarks/cross_tool_runner.py \
  --skip-build \
  --tools bymc \
  --bymc-binary benchmarks/bymc/run_bymc.sh \
  --bymc-mode real \
  --out /tmp/cross-tool-real.json

# 3. Verify verdict parity
python3 .github/scripts/check_cross_tool_verdict_parity.py /tmp/cross-tool-real.json
```

The `--bymc-mode` flag controls which command template is used:
- `mock` (default): Uses `command_template` from the manifest (mock adapter)
- `real`: Uses `command_template_real` from the manifest (real ByMC binary)

The wrapper script `benchmarks/bymc/run_bymc.sh` auto-detects whether to use a
local `verifypa-schema` installation or the Docker image. See
`benchmarks/bymc/README.md` for setup details and troubleshooting.
