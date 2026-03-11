# CEGAR Liveness Gap Report (CEGAR-01)

Date: 2026-03-11  
Task: `CEGAR-01` (Phase 4)  
Scope: Audit current CEGAR loop and identify safety-specific assumptions that must change for liveness-focused refinement.

## Executive Summary

The repository already contains a fair-liveness CEGAR pipeline (`prove_fair_liveness_with_cegar*`), but the refinement model is still mostly safety-style:

- refinements are adversary-assumption tightenings (`equivocation/auth/network/values`);
- evidence signals are derived from counter-message artifacts, not lasso structure;
- replay uses full re-prove under stronger assumptions instead of lasso realizability checking.

This means the current flow can filter spurious witnesses in practice, but it does not yet implement the intended `CEGAR-02/03` semantics:

1. extract abstract fair lassos as first-class counterexample objects;  
2. check abstract lasso realizability against concrete semantics;  
3. synthesize liveness-specific refinement predicates from failed realizability.

## Audit Inputs

- `crates/tarsier-engine/src/pipeline/verification/cegar.rs`
- `crates/tarsier-engine/src/pipeline/verification/orchestration.rs`
- `crates/tarsier-engine/src/pipeline/verification/fair_pdr.rs`
- `crates/tarsier-engine/src/result.rs`

## Current CEGAR Architecture (as implemented)

### 1. Baseline witness stage

- Bounded safety CEGAR entrypoint: `verify_with_cegar_report` / `verify_with_cegar`.
- Unbounded safety CEGAR entrypoint: `prove_safety_with_cegar_report` / `prove_safety_with_cegar`.
- Unbounded fair-liveness CEGAR entrypoint: `prove_fair_liveness_with_cegar_report` / `prove_fair_liveness_with_cegar`.

For fair-liveness, baseline witness is `UnboundedFairLivenessResult::FairCycleFound { depth, loop_start, trace }`.

### 2. Signal extraction

- `cegar_trace_signals_from_trace` inspects `Trace` and active `gamma` counters.
- Signature parsing relies on message-counter naming (`cnt_<Msg>@...`).
- Signals currently captured:
  - conflicting variants,
  - cross-recipient delivery,
  - sign-abstract values,
  - identity-scoped channels.

### 3. Refinement planning

- `cegar_atomic_refinements` + `cegar_trace_generated_refinements`.
- Refinement kinds are global/per-message adversary/channel changes:
  - `GlobalEquivocationNone`,
  - `GlobalAuthSigned`,
  - `GlobalValuesExact`,
  - `GlobalNetworkIdentitySelective`,
  - `GlobalNetworkProcessSelective`,
  - per-message auth/equivocation tightenings.
- Plan ranking is signal/score driven with optional UNSAT-core seed:
  - `cegar_refinement_plan_with_signals`,
  - `cegar_unsat_core_seed`.

### 4. Stage replay and classification

- Each stage clones the program, applies refinement, reruns proof.
- For fair-liveness:
  - `FairCycleFound` => witness treated as concrete under monotone restriction.
  - `LiveProved` => baseline fair-cycle considered eliminated.
  - `NotProved` / `Unknown` => inconclusive.
- Stage/post-run analysis:
  - `cegar_stage_counterexample_analysis_unbounded_fair`,
  - `cegar_stage_eliminated_traces_unbounded_fair`.

## Safety-Specific Assumptions Still Present

### A. Refinement vocabulary is adversary-centric, not liveness-state-centric

- `CegarRefinementKind` encodes assumption tightening only.
- Missing: predicates over lasso-state relations (loop invariants, ranking witnesses, fairness-monitor discriminators, kappa/gamma linear separators).

Impact:
- effective for network/abstraction artifacts,
- insufficient when spuriousness arises from fair-cycle abstraction itself.

### B. Witness evidence ignores fair-cycle structure

- Signal extraction consumes counter traces and message-counter naming.
- No extraction of:
  - loop backbone features (entry/loop SCC properties),
  - acceptance obligation progression,
  - fairness monitor activation/arming patterns,
  - cycle-local state equalities/inequalities.

Impact:
- refinement targeting is biased toward communication abstractions,
- weak guidance for cycle-specific false positives.

### C. No explicit abstract-lasso realizability check

- Current loop reruns full `prove_fair_liveness_*` under stronger assumptions.
- Missing dedicated “given abstract lasso L, can concrete model realize L?” check.

Impact:
- elimination reason is indirect (stage result changed),
- cannot isolate exactly which lasso segment/constraint is spurious.

### D. Spurious-cycle diagnosis is verdict-level, not transition-level

- `LiveProved` is treated as elimination; `Unknown/NotProved` as inconclusive.
- No transition-by-transition failure explanation (guard mismatch, fairness obligation mismatch, epoch/timing mismatch).

Impact:
- refinement synthesis has less actionable conflict data,
- harder to generate minimal differentiating predicates.

## Liveness-Aware Components Already in Place

These are strong foundations for `CEGAR-02/03`:

- fair-cycle result and lasso trace surface in result types (`UnboundedFairLivenessResult::FairCycleFound`);
- dedicated fair-liveness CEGAR report path (`prove_fair_liveness_with_cegar_report`);
- stage-level audit schema already includes:
  - `model_changes`,
  - `eliminated_traces`,
  - `counterexample_analysis`,
  - `termination` metadata;
- monotone replay logic and refinement-core shrinking already reusable.

## Required Changes for CEGAR-02 (Abstract Lasso Extraction)

### Proposed deliverables

1. Introduce a first-class liveness witness structure:
   - `LivenessCegarWitness` (prefix + loop + fairness obligations + provenance).
2. Extend `fair_pdr` to emit extracted abstract lasso artifacts directly (not only `Trace`).
3. Persist witness artifact in CEGAR report stage-0 payload.
4. Add fixture tests for deterministic lasso extraction shape.

### Minimal insertion points

- `fair_pdr.rs`: lasso recovery / fair-cycle found return path.
- `result.rs`: extend fair-cycle payload metadata (without breaking existing JSON schema contracts).
- `orchestration.rs`: baseline-stage capture and report emission.

## Required Changes for CEGAR-03 (Liveness Refinement)

### Proposed deliverables

1. Implement `check_lasso_realizability(...)`:
   - input: abstract witness + concrete model;
   - output: realizable / spurious + failing obligations.
2. On spurious witness, synthesize discriminating predicates:
   - start with linear templates over `kappa/gamma` and fairness monitor flags.
3. Extend `CegarRefinementKind` with liveness-state predicates:
   - initially as opaque predicate atoms attached to SMT side-conditions.
4. Add stage diagnostics:
   - failing loop edge index,
   - failed fairness clause,
   - generated predicate provenance.

### Minimal insertion points

- new module in verification pipeline for lasso realizability check.
- `cegar.rs`:
  - add liveness predicate atoms and scoring.
- `orchestration.rs`:
  - route fair-cycle stages through realizability before deciding elimination/confirmation.

## Sequenced Implementation Plan (for Phase-4 follow-up tasks)

1. `CEGAR-02`: witness extraction and report plumbing only (no new refinement logic).  
2. `CEGAR-03`: realizability checker + predicate synthesis + staged diagnostics.  
3. `CEGAR-04`: integration test where baseline fair cycle is spurious and eliminated by synthesized predicate.

## Risks

- Schema drift risk in CEGAR JSON reports if witness payload is added without versioning discipline.
- Fair-PDR performance risk if realizability checks are run naively per stage without incremental reuse.
- Potential overlap with Agent-2 PDR work in shared fair-liveness internals; coordinate via board `BLOCKED/RELEASE` protocol for `fair_pdr.rs` changes.

## Acceptance for CEGAR-01

This task is complete when:

- current CEGAR liveness path is documented with concrete code references,
- safety-specific assumptions are explicitly identified,
- downstream implementation path for `CEGAR-02/03` is sequenced and actionable.
