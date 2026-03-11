# Liveness Corpus Coverage Matrix (LCORPUS-01)

Date: 2026-03-11  
Task: `LCORPUS-01` (Phase 4)  
Scope: audit existing liveness examples and document a feature-by-family coverage matrix.

## Method

- Scanned `examples/**/*.trs` for `property ...: liveness`.
- Included both top-level `examples/` and `examples/library/`.
- Extracted:
  - protocol family (from file naming);
  - timing signals (`timing: partial_synchrony`, timeout guards, clock declarations);
  - temporal operators in liveness formulas (`<>`, `~>`, `X`, `U`, `W`, `R`);
  - quantifier shape (`forall`/`exists`, multi-quantifier presence).
- Cross-checked fairness expectations from `examples/library/cert_suite.json`.

## Inventory (Current Liveness Examples)

Total liveness `.trs` files found: **12**

| File | Family | Key Liveness Signals |
|---|---|---|
| `examples/pbft_faithful_liveness.trs` | PBFT | partial synchrony |
| `examples/library/pbft_liveness_safe_ci.trs` | PBFT | partial synchrony, safe CI anchor |
| `examples/library/pbft_liveness_buggy_ci.trs` | PBFT | partial synchrony, buggy CI anchor |
| `examples/library/reliable_broadcast_safe_live.trs` | Reliable Broadcast | safe liveness pair |
| `examples/library/reliable_broadcast_live_buggy.trs` | Reliable Broadcast | buggy liveness pair |
| `examples/temporal_liveness.trs` | Temporal benchmark | `~>`, `<>` |
| `examples/library/temporal_liveness_counterexample.trs` | Temporal benchmark | `~>`, `<>` counterexample |
| `examples/library/minimmit_safe_faithful.trs` | BFT variants | partial synchrony, timeout guard |
| `examples/library/phoenixx_safe_faithful.trs` | BFT variants | partial synchrony |
| `examples/library/casper_ffg_like.trs` | Casper/FFG | partial synchrony |
| `examples/crypto_objects.trs` | Crypto-object demo | `<>` |
| `examples/library/trivial_live.trs` | Other | trivial live sanity |

## Coverage Matrix (Features x Protocol Families)

Values are counts of files in each family that contain the feature.

| Family | Files | Partial synchrony | Timeout guard | Clock decl | `<>` | `~>` | `X` | `U` | `W` | `R` | `exists` quantifier | Multi-quantifier |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| PBFT | 3 | 3 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Reliable Broadcast | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Temporal benchmark | 2 | 0 | 0 | 0 | 2 | 2 | 0 | 0 | 0 | 0 | 0 | 0 |
| BFT variants | 2 | 2 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Casper/FFG | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Crypto-object demo | 1 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Other | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

## Fairness Coverage (From `cert_suite.json`)

Liveness/fair-liveness manifest coverage is currently concentrated in:

- `pbft_liveness_safe_ci.trs` (weak fairness expected);
- `pbft_liveness_buggy_ci.trs` (weak fairness expected);
- `trivial_live.trs` (weak fairness expected);
- `temporal_liveness_counterexample.trs` (no explicit fairness override in manifest).

Observed gap: no manifest-backed **strong fairness** liveness anchors in the example corpus.

## Findings

1. **Temporal operator coverage in examples is narrow**:
   - only `<>` and `~>` are present in corpus examples;
   - no corpus examples using `X`, `U`, `W`, `R`.
2. **Quantifier coverage is minimal**:
   - no `exists` quantifier usage in corpus examples;
   - no multi-quantifier liveness examples.
3. **Timing/clock coverage is partial**:
   - partial synchrony is present (6/12), but clock declarations are absent in liveness corpus;
   - only one liveness example includes a timeout guard.
4. **Feature coverage is uneven across families**:
   - PBFT and RB have safe/buggy liveness pairs;
   - newer feature families (DAG, FIFO, reconfiguration) do not yet have liveness-focused examples.
5. **Fairness profile in manifest is mostly weak-only**:
   - no strong-fairness corpus anchors in `cert_suite`.

## Recommended Follow-up Inputs for LCORPUS-02

Add at least six liveness examples to close the highest-value gaps:

1. strong-fairness safe/buggy pair;
2. temporal `X/U/W/R` operator examples (safe + bug);
3. existential and multi-quantifier liveness examples;
4. clock-driven liveness example with explicit `clock` + timeout progression;
5. reconfiguration liveness example;
6. DAG/FIFO liveness example.

