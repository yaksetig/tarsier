# Performance & Tuning Guide

This document describes scale limits, optimization impact, fallback behavior, and tuning recommendations for the tarsier toolchain.

## 1. Scale Limits by Network Mode

The effective network abstraction determines the state-space footprint and therefore the practical scale limit:

| Network Mode | Max Locations | Max Shared Vars | Max Message Counters | Typical Use Case |
|---|---|---|---|---|
| `classic` | ~200 | ~500 | ~500 | Most BFT protocols; default after fallback |
| `identity_selective` | ~150 | ~150 | ~150 | Protocols with identity-scoped equivocation |
| `cohort_selective` | ~150 | ~200 | ~200 | Protocols with cohort-based voting |
| `process_selective` | ~50 | ~50 | ~50 | Small-instance enumeration (n ≤ 7–10) |

These are approximate limits for a 60-second timeout with the Z3 solver. PDR and k-induction may handle slightly larger state spaces than BMC for the same timeout.

## 2. Optimization Impact

Tarsier applies several optimizations automatically. Typical impact ranges observed on the library corpus:

### Structural Hashing (Assertion Deduplication)
- **Mechanism:** Canonical term keys deduplicate logically identical SMT assertions before encoding.
- **Impact:** 30–70% assertion dedup rate on multi-role protocols with symmetric rules.
- **Diagnostics:** `smt_profiles[].assertion_dedup_rate` in JSON output.

### Symmetry Reduction
- **Mechanism:** Cube deduplication in PDR exploits role symmetry to prune equivalent states.
- **Impact:** 10–40% prune rate when multiple roles have identical transition structure.
- **Diagnostics:** `smt_profiles[].symmetry_prune_rate` in JSON output.
- **Applied vs skipped:** `symmetry_candidates=0` indicates no eligible symmetry candidates were observed for that run (effectively skipped); non-zero candidates with non-zero pruned count indicates active pruning.

### Incremental Solving
- **Mechanism:** Push/pop scope management and base-clause caching across BMC depth steps.
- **Impact:** 2–4x speedup on deeper BMC checks (depth > 4) by reusing learned clauses.
- **Diagnostics:** `smt_profiles[].incremental_depth_steps`, `incremental_decl_hits`, `incremental_assertion_hits` in JSON output.

### Partial-Order Reduction (POR)
- **Mechanism:** Static pruning (stutter elimination, commutative dedup, guard domination) plus dynamic ample sets in PDR.
- **Impact:** 5–20% rule reduction on multi-role protocols with independent transitions.
- **Diagnostics:** `lowerings[].por_effective_rule_count`, `smt_profiles[].por_dynamic_ample_queries` in JSON output.
- **Soundness:** See SEMANTICS.md Section 6.6 for the formal argument.

## 3. Fallback Behavior

When a protocol's faithful network abstraction exceeds execution budget limits, tarsier applies a mode lattice fallback:

```
process_selective → cohort_selective → identity_selective → classic
```

### Budget Parameters

The fallback is controlled by `PipelineExecutionControls`:
- `max_locations` — maximum locations before fallback triggers
- `max_shared_vars` — maximum shared variables before fallback triggers
- `max_message_counters` — maximum message counters before fallback triggers
- `floor` — the coarsest abstraction allowed (default: `Classic`)

### Fallback States

Each lowering reports one of three states:
- **`not_applied`** — the requested network mode fits within budget.
- **`applied`** — a coarser mode was used; `fallback_steps` indicates how many levels were traversed.
- **`exhausted`** — the floor mode was reached and the protocol still exceeds budget; verification proceeds but results may be less precise.

### Fast-Fail Reporting

When fallback is exhausted, the CLI emits a warning. JSON reports include the `network_fallback_state` field in `abstractions.lowerings[]`.

## 4. Tuning Recommendations

### Depth Selection

- **BMC verify:** Start with depth 4–6 for most protocols. Increase to 8–10 for protocols with long critical paths (e.g., multi-phase commit).
- **Liveness:** Depth 3–5 typically suffices to find fairness-violating cycles.
- **Round sweep:** Use `round-sweep` to empirically determine the minimum depth at which the verdict stabilizes.

### Engine Selection

| Engine | Best For | Trade-off |
|---|---|---|
| BMC (`verify`) | Quick bug-finding, bounded safety | Cannot prove unbounded safety |
| k-induction (`prove --engine kinduction`) | Unbounded safety with simple invariants | May fail on complex protocols requiring auxiliary lemmas |
| PDR (`prove --engine pdr`) | Unbounded safety with automatic invariant discovery | Slower per iteration but often finds proofs that k-induction misses |

### Portfolio Mode

Use `--portfolio` when both Z3 and CVC5 are available. The overhead is minimal (parallel execution) and the merge policy picks the strongest result. Portfolio mode is especially valuable for `prove` commands where one solver may find an invariant the other cannot.

### CEGAR Iterations

The default maximum refinement count (typically 8–12 iterations) suffices for most protocols. Increase `--max-refinements` only if the CEGAR report shows "refinement budget exhausted" with promising elimination trends.

### Timeout Guidance

- **Interactive use:** 30–60 seconds covers the library corpus at depth 4.
- **CI/batch:** 120–300 seconds for deeper checks or larger protocols.
- **Proof search:** PDR and k-induction may benefit from 300–600 seconds on complex protocols.
- **Enforcement path:** `PipelineOptions.timeout_secs` is propagated to solver backends (Z3/CVC5 process timeout) and to pipeline-level deadline budgeting; timeout-triggered exits are reported as `Unknown` with timeout reason codes.

### Guardrails for Unbounded Fair-Liveness

- `--timeout <secs>` bounds wall-clock proof search for `prove-fair`.
- `--liveness-memory-budget-mb <MiB>` bounds RSS usage for unbounded fair-liveness proof search.
- If the memory guardrail triggers, `prove-fair` returns `unknown` with `reason_code=memory_budget_exceeded` in machine-readable output.

### Memory Considerations

- Z3's memory usage scales with assertion count. Structural hashing helps, but protocols with >1000 shared variables may require 4–8 GB.
- Use `--format json` with `tarsier analyze` to inspect the effective footprint before committing to a long verification run.
- Proof-effort diagnostics are emitted in JSON via:
  - `phase_profiles[]` (`parse`/`lower`/`encode`/`solve`/`check` elapsed time + RSS snapshot)
  - `smt_profiles[]` (encode/solve call counts, incremental reuse, symmetry, POR metrics)

## 5. Unbounded Liveness Benchmark Cases

The regression suite includes hard unbounded fair-liveness cases for canonical
BFT families. These are intended to prevent silent regressions in convergence
and counterexample-finding behavior:

- `examples/library/pbft_core.trs` — expected `fair_cycle_found` under weak fairness.
- `examples/library/hotstuff_chained.trs` — expected `fair_cycle_found` under weak fairness.
- `examples/library/tendermint_locking.trs` — expected `fair_cycle_found` under weak fairness.

These expectations are exercised in
`crates/tarsier-engine/tests/integration_tests.rs` via:

- `benchmark_liveness_pbft_core_weak_fairness_finds_cycle`
- `benchmark_liveness_hotstuff_chained_weak_fairness_finds_cycle`
- `benchmark_liveness_tendermint_locking_weak_fairness_finds_cycle`

## 6. Pinned-Environment Reproducibility

CI performance benchmark jobs (`library-benchmark-smoke`, `library-benchmark-large`) run on pinned
`ubuntu-22.04` with pinned Rust/Python/solver versions and a mandatory `verify_pinned_env.sh` gate
before benchmarks execute.

This ensures performance artifacts are generated under a reproducible environment contract
(`rustc=1.92.0`, `z3=4.12.5`, `cvc5=1.1.2`, `os=ubuntu-22.04`) rather than floating runner/toolchain versions.
