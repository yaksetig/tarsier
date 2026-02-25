# Interpretation Matrix: Legacy vs Faithful Semantics

This document is the single canonical reference for understanding how Tarsier's network abstraction modes relate to the protocol-faithful target semantics. It reconciles the counter-abstraction limitations described in `docs/PARAMETERIZED_VERIFICATION.md` with the faithful network modes described in `docs/SEMANTICS.md`.

## Terminology

| Term | Meaning |
|------|---------|
| **Classic** (legacy) | `network: classic` — role-scoped counter channels. The original and default network mode. |
| **Faithful modes** | `network: identity_selective`, `cohort_selective`, or `process_selective` — sender+recipient-scoped delivery candidates. |
| **Faithful target** | The idealized protocol semantics with per-process identities, per-recipient packets, and sender-authenticated delivery (`SEMANTICS.md` Section 2.1). |
| **Over-approximation** | The abstraction admits more behaviors than the faithful target. `SAFE` transfers; `UNSAFE` may be spurious. |
| **Instance-exact** | The abstraction produces exactly the same reachable states as the faithful target for a specific instance size. Both `SAFE` and `UNSAFE` transfer. |

## Network Mode Comparison

| Property | Classic | Identity-Selective | Cohort-Selective | Process-Selective |
|----------|---------|-------------------|------------------|-------------------|
| Channel granularity | `cnt_M@Role[fields]` | `cnt_M@Recipient<-Sender[fields]` | `cnt_M@Role#cohort[fields]` | `cnt_M@Role#pid[fields]` |
| Sender tracking | None (role-aggregate) | Per-sender identity budget | Per-cohort partition | Per-process pid |
| Recipient coupling | None | Per-recipient delivery | Per-role cohort | Per-process pid |
| `received distinct` | Not supported | Exact sender-set count | Approximate | Exact |
| Equivocation control | `full` only (default) | `full` or `none` | `full` or `none` | `full` or `none` |
| Authentication | Not modeled | `auth: signed` | `auth: signed` | `auth: signed` |
| Relationship to faithful | Conditional over-approx | Over-approximation | Over-approximation | Instance-exact |

## Soundness Transfer Rules

### When does `SAFE` transfer to the faithful target?

| Mode | Transfers? | Conditions |
|------|-----------|------------|
| Classic | Yes, conditionally | Monotone guards only (`>=`, `>`); `equivocation: full`; no `received distinct` guards |
| Identity-selective | Yes | `auth: signed`; Byzantine model; sender budgets >= faithful-target budgets |
| Cohort-selective | Yes | Cohort partitioning is coarser than per-process (inherent over-approximation) |
| Process-selective | Yes (exact) | `pid in [0, n-1]`; `auth: signed` |

### When does `UNSAFE` transfer to the faithful target?

| Mode | Transfers? | Notes |
|------|-----------|-------|
| Classic | Not guaranteed | Classic admits traces impossible under sender-scoped faithful delivery |
| Identity-selective | Conditional | Trace must be validated against faithful packet semantics |
| Cohort-selective | Not guaranteed | Cohort-level traces may not map to per-process schedules |
| Process-selective | Yes (exact) | Same conditions as SAFE |

*Source: `SEMANTICS.md` Section 6.4, Theorems 1-3.*

## Counter-Abstraction Limitations and How Faithful Modes Address Them

The following limitations were originally documented in `PARAMETERIZED_VERIFICATION.md`. Each is annotated with which faithful modes address it and to what degree.

### Limitation 1: No per-process state within a location

> All processes in the same location are indistinguishable. The abstraction tracks *how many* processes are in each location, not *which* ones.

| Mode | Status |
|------|--------|
| Classic | Limitation applies fully |
| Identity-selective | Partially addressed — sender identities are tracked per-variant, but recipients in the same location still see the same aggregate |
| Cohort-selective | Partially addressed — cohort partitions provide coarse sub-role grouping |
| Process-selective | **Fully addressed** — each pid is a distinct identity with per-process channels; instance-exact for bounded pid domain |

### Limitation 2: Global adversary injection

> Byzantine message injections are modeled globally — the adversary injects messages that affect all counters uniformly.

| Mode | Status |
|------|--------|
| Classic | Limitation applies fully |
| Identity-selective | **Addressed** — adversary injection is sender-budget-coupled; per-recipient selective delivery |
| Cohort-selective | Partially addressed — cohort-scoped adversary delivery |
| Process-selective | **Fully addressed** — per-process adversary activation with static faulty-sender set |

### Limitation 3: Disagreement requires different locations

> For a safety violation like agreement to be detected, processes must be in different decided locations.

This is inherent to the threshold-automata model and applies equally to all modes. It is not a limitation but a correct modeling property: if a protocol has only one decision state, agreement is trivially safe.

### Limitation 4: Finite-domain local variables

> Local variables must have finite domains (bool, bounded nat/int, enums).

This applies equally to all modes. It is a fundamental property of counter abstraction, not specific to network semantics.

### Limitation 5: No liveness without fairness

> Pure BMC cannot prove liveness properties.

This applies equally to all modes. Use `fair-liveness` or `prove-fair` with appropriate fairness assumptions.

## Worked Examples: Where Legacy and Faithful Diverge

### Example 1: Equivocation-sensitive safety (PBFT)

**Setup:** PBFT three-phase commit with `n > 3*t`.

**Classic mode** (`pbft_simple_safe.trs`):
```trs
adversary { model: byzantine; bound: f; }
when received >= 2*t+1 Prepare => { goto committed; }
```
- Uses aggregate `received >= threshold` — counts all messages, regardless of sender.
- `equivocation: full` (default) — the adversary can inject arbitrary messages.
- **Result: SAFE** — the over-approximation is sound because guards are monotone.

**Faithful mode** (`pbft_simple_safe_faithful.trs`):
```trs
adversary {
    model: byzantine; bound: f;
    auth: signed; network: identity_selective;
    delivery: per_recipient; faults: per_recipient;
    equivocation: none;
}
identity Replica: role key replica_key;
channel Prepare: authenticated;
equivocation Prepare: none;
when received distinct >= 2*t+1 Prepare => { goto committed; }
```
- Uses `received distinct` — counts messages from distinct senders.
- `equivocation: none` — a sender cannot send conflicting payloads.
- **Result: SAFE** — tighter modeling, same verdict.

**Where they diverge:** If we change to `equivocation: full` in the faithful model (`pbft_crypto_qc_bug_faithful.trs`), the result becomes **UNSAFE** — full equivocation allows the adversary to split QC-forming messages, breaking safety. The classic model cannot detect this because it has no sender tracking.

### Example 2: Strict mode property shape divergence

**Setup:** `temporal_liveness_counterexample.trs` — a protocol with only a liveness property, no safety property.

**Classic mode (strict):** Rejects with an error — strict mode requires an explicit safety property for `verify`.

**Faithful mode (permissive overlay):** Falls back to default liveness property evaluation. **Result: SAFE** (vacuously).

**Why this matters:** This is a regression sentinel in the test suite (`differential_regression_classic_vs_faithful_corpus()`). It ensures that the toolchain correctly distinguishes between strict and permissive property requirements.

### Example 3: Sender-specific guard under classic

**Setup:** A protocol using `received distinct >= 2*t+1 Vote`.

**Classic mode:** Cannot model `received distinct` — the guard falls back to aggregate counting. If the protocol's safety depends on distinct-sender semantics, classic may report SAFE even when the faithful model is UNSAFE (classic admits more behaviors that happen to satisfy the safety property for the wrong reasons), or report UNSAFE for traces that cannot actually occur under sender-scoped delivery.

**Identity-selective mode:** Correctly models `received distinct` with exact sender-set counting (`sum_{sender} ite(counter(sender) > 0, 1, 0)`). Verdict is faithful to the protocol semantics.

**Takeaway:** Use faithful modes whenever `received distinct` guards appear. Strict mode enforces this by requiring proper identity/auth declarations when distinct-sender guards are used.

## Choosing the Right Mode

| Your protocol uses... | Recommended mode | Why |
|----------------------|-----------------|-----|
| Only aggregate thresholds (`>= k`) | Classic | Simplest, fastest; over-approximation is sound for monotone guards |
| `received distinct` guards | Identity-selective or process-selective | Classic cannot model sender-set counting |
| `equivocation: none` assumption | Identity-selective or process-selective | Classic only supports `equivocation: full` |
| Crypto objects (`certificate`, `threshold_signature`) | Identity-selective | Crypto non-forgeability requires sender-scoped delivery |
| Per-process identity reasoning | Process-selective | Instance-exact; `pid` variable gives per-process channels |
| Omission or crash faults only | Classic is usually sufficient | Omission/crash don't involve sender equivocation |

## Cross-Tool Comparison

Tarsier's `export-ta` command exports threshold automata in ByMC `.ta` format,
including real specification sections derived from the protocol's safety property:

- **Agreement (single decision value):** Stability spec — `[](loc_d > 0 -> [](loc_d >= 0))`.
- **Agreement (multiple decision values):** Mutual exclusion — `[]((loc_a > 0 && loc_b > 0) -> false)` for each conflicting pair.
- **Invariant:** Bad-set mutual exclusion — `[]((loc_i > 0 && loc_j > 0 && ...) -> false)`.

The cross-tool benchmark runner (`benchmarks/cross_tool_runner.py`) executes
normalized scenarios across Tarsier, ByMC, and SPIN, producing an
apples-to-apples comparison report. Each tool entry tracks `execution_mode`
(mock vs real) for transparency.

See `benchmarks/README.md` for usage details and
`benchmarks/cross_tool_scenarios/scenario_manifest.json` for the scenario corpus.

## Cross-References

- **Formal semantics and transfer theorems:** `docs/SEMANTICS.md` Sections 2-6
- **Counter-abstraction foundations:** `docs/PARAMETERIZED_VERIFICATION.md`
- **DSL syntax for faithful features:** `docs/LANGUAGE_REFERENCE.md` Section 13
- **Example protocol pairs (minimal vs faithful):** `docs/EXAMPLE_CATALOG.md` Variant Groups
- **Differential regression tests:** `crates/tarsier-engine/tests/integration_tests.rs`
- **Cross-tool benchmark runner:** `benchmarks/cross_tool_runner.py`
