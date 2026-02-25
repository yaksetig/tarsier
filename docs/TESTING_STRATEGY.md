# Testing Strategy

This document defines what each test layer guarantees and what it does not.

## 1) Corpus Regression (deterministic)

Purpose:
- Prevent known protocol/library regressions.
- Preserve expected verdict classes for fixed models.

Characteristics:
- Inputs come from `examples/library/*.trs` and other fixed fixtures.
- Strong for regression prevention.
- Weak for discovering unseen parser/lowering/encoding interactions.

Typical gate:
- `cargo test --all-targets`
- `./scripts/certify-corpus.sh`

## 2) Property-Based Randomized Pipeline Tests

Purpose:
- Exercise the full verification pipeline on generated inputs:
  `parse -> lower -> encode -> solve`.
- Catch bug classes not covered by corpus-only sweeps.

Suite:
- Integration: `crates/tarsier-engine/tests/property_pipeline_proptest.rs`
- Unit: `crates/tarsier-engine/src/property_pipeline_unit_tests.rs`

Guaranteed checks:
- Randomized safe-model generation remains `SAFE`.
- Metamorphic invariants:
  - alpha-renaming invariance for quantified variable names,
  - equivalent rule-ordering invariance,
  - deterministic compilation fingerprint invariance for identical source.
- Negative bug-catch property:
  - a generated buggy mutant must be reported `UNSAFE`.

## 3) Reproducibility + Shrinking

Repro controls:
- CI fixed seed:
  - `PROPTEST_RNG_ALGORITHM=cc`
  - `PROPTEST_RNG_SEED=246813579`
  - `PROPTEST_CASES=48`
- Nightly stress seeds run larger case counts in
  `.github/workflows/nightly-property-tests.yml`.

Failure artifacts:
- Proptest persistence (shrinking replay):
  `proptest-regressions/*`.
- Additional JSON artifacts with minimized case + payload:
  `target/property-test-failures/*`
  (or `TARSIER_PROPTEST_ARTIFACT_DIR` in CI).

## 4) CI Contract

PR CI gate:
- `.github/workflows/ci.yml` step `Property Testing Gate`
- Enforces fixed seed and minimum case count before running tests.

Nightly (non-blocking PR gate):
- `.github/workflows/nightly-property-tests.yml`
- Multi-seed stress run for higher randomized coverage.

## 5) UX Regression Contracts (CLI + Playground)

Purpose:
- Prevent regressions in beginner/pro user flows.
- Keep output/report contracts stable for CI/governance automation.
- Enforce baseline accessibility markers in the playground UI.

Suite:
- `./scripts/beginner-ux-smoke.sh`
- `./scripts/ux-regression-smoke.sh`
- `python3 scripts/ux_snapshot_regression.py`

Guaranteed checks:
- Canonical beginner flow remains discoverable (`assist -> analyze -> visualize`).
- Playground API + UI flow (`assist`, `lint`, `run`, timeline, mermaid) remains functional.
- Lint JSON keeps `source_span` + `soundness_impact` and structured `fix` fields.
- Visualization/export contract remains stable (JSON/Markdown/timeline/mermaid/bundle metadata).
- Accessibility sanity markers remain present (`aria-live` status regions, labeled key controls).

CI gates:
- `.github/workflows/ci.yml` job `beginner-ux-gate`
- `.github/workflows/ci.yml` job `ux-usability-regression`
- `.github/workflows/ci.yml` job `ux-snapshot-regression`

## 6) Foundational Unit Coverage (low-latency)

Purpose:
- Keep core utility logic and output formatting behavior stable.
- Catch regressions in parser/formatter/helper paths before integration tests.

Scope:
- Counterexample extraction helpers (message metadata parsing, auth provenance, equivocation labeling, POR trace annotations).
- Compositional contract reporting helpers (error text + result shaping).
- TUI state helpers (step/config selection, status-line rendering).
- SMT helper types (`sorts`, `terms`, `solver` defaults and typed model accessors).
- IR property extraction helpers (agreement/invariant extraction edge cases).

Recommended local loop:
- `cargo test -p tarsier-ir`
- `cargo test -p tarsier-smt`
- `cargo test -p tarsier-engine counterexample::tests:: --lib`
- `cargo test -p tarsier-engine compositional::tests:: --lib`
- `cargo test -p tarsier-cli tui::tests:: --bin tarsier`

Quality bar:
- Unit tests in this layer should be deterministic, avoid solver/network subprocesses, and complete in seconds.
- Assertions should check semantic behavior (verdict labels, event kinds, field mappings), not only string presence.

## 7) Coverage Tracking (LLVM)

Purpose:
- Track line-level coverage trends over time with a reproducible toolchain.
- Preserve machine-readable artifacts for regression analysis and CI baselining.

CI gate:
- `.github/workflows/ci.yml` job `coverage-llvm`
- Produces:
  - `artifacts/coverage/lcov.info`
  - `artifacts/coverage/summary.txt`
  - workflow summary table from `cargo llvm-cov report --summary-only`
- Enforces minimum workspace line coverage via
  `.github/scripts/check_llvm_coverage_threshold.py`
  (configured by `LLVM_COV_MIN_LINE_PERCENT` in CI).

Local loop:
- Install once: `cargo install cargo-llvm-cov --locked`
- Run workspace coverage:
  - `cargo llvm-cov --workspace --all-targets --summary-only`
- Emit LCOV for external tooling:
  - `cargo llvm-cov --workspace --all-targets --lcov --output-path artifacts/coverage/lcov.info`

Quality bar:
- Coverage jobs should remain deterministic and artifact-stable across identical commits.
- Use coverage deltas to prioritize low-level helper tests (especially result/report-shaping paths), not to replace semantic regression tests.

## 8) Fuzzing Gate

Purpose:
- Continuously exercise parser/lowering/encoding and proof-kernel paths against malformed inputs.
- Catch panic/OOM/crash classes outside deterministic corpus tests.

CI gate:
- `.github/workflows/ci.yml` job `fuzz-gate` (blocking PR gate).
- Matrix targets: `fuzz_parse`, `fuzz_lower`, `fuzz_encode`, `fuzz_proof_kernel`.

Nightly stress:
- `.github/workflows/fuzz.yml` runs longer scheduled fuzzing sweeps and uploads crash artifacts on failure.

## 9) Benchmark Regression Gates

Purpose:
- Detect statistically significant performance regressions, not just smoke-test completion.

CI gates:
- `.github/workflows/ci.yml` jobs:
  - `library-benchmark-smoke`
  - `library-benchmark-large`
  - `performance-gate`
- Each benchmark run uses `--perf-budget ...` and enforces `performance_gate.passed == true`.

Quality bar:
- Benchmark reports must preserve schema compatibility and include deterministic replay metadata.
- Regressions must be triaged with artifact evidence before budget thresholds are relaxed.
