# GST / Timing Model Gap Report (GST-01)

Date: 2026-03-11  
Task: `GST-01` (Phase 4)  
Scope: Audit current timing/clock semantics across DSL -> IR -> SMT/verification, and define a concrete GST modeling proposal for follow-on tasks (`GST-02/03/04`).

## Executive Summary

The repository already has meaningful timing primitives:

- protocol clocks (`clock`, `timeout`, `tick`, `reset`);
- partial-synchrony switches (`adversary { timing: partial_synchrony; gst: ...; }`);
- fair-liveness post-GST gating in both bounded lasso and unbounded fair-PDR paths.

However, the current GST semantics are still fragmented:

1. timing is modeled as loose adversary key/value items, not a first-class timing block;
2. post-GST delivery guarantees are mode-dependent and incomplete (not uniformly enforced in classic network mode);
3. bounded-delay-after-GST semantics (`Delta`) are not encoded;
4. GST is represented as a parameter only, not as a dedicated existential stabilization point in bounded encodings.

This means timing support is usable, but not yet a full first-class partial-synchrony model as intended by the phase-4 chain (`GST-02 -> GST-03 -> GST-04`).

## Audit Inputs

- DSL / parser:
  - `crates/tarsier-dsl/src/grammar.pest`
  - `crates/tarsier-dsl/src/ast.rs`
  - `crates/tarsier-dsl/src/parser/mod.rs`
- IR / lowering:
  - `crates/tarsier-ir/src/threshold_automaton.rs`
  - `crates/tarsier-ir/src/lowering/mod.rs`
  - `crates/tarsier-ir/src/lowering/tests.rs`
- SMT / verification:
  - `crates/tarsier-smt/src/encoder/mod.rs`
  - `crates/tarsier-engine/src/pipeline/verification/smt_helpers.rs`
  - `crates/tarsier-engine/src/pipeline/verification/fair_pdr.rs`

## Current Behavior by Layer

### 1. DSL / Parser

What exists:

- `clock <name>;` declarations.
- `when timeout <clock> <cmp> <linear_expr> => ...` guards.
- `tick <clock> [by expr];` and `reset <clock>;` actions.
- Partial synchrony configured via adversary entries:
  - `timing: partial_synchrony;`
  - `gst: <ident>;`

Important detail:

- `adversary_item` grammar is `ident : ident ;` (key/value atoms), so timing is not a structured object.
- Known adversary keys include `timing` and `gst`.

### 2. IR / Lowering

What exists:

- `ThresholdAutomatonSemantics` stores:
  - `timing_model: TimingModel::{Asynchronous, PartialSynchrony}`
  - `gst_param: Option<ParamId>`
- Lowering maps adversary keys `timing` and `gst` into these fields.
- Guardrail exists:
  - `timing: partial_synchrony` without `gst` is rejected.
- Clocks lower into:
  - per-rule `clock_guards: Vec<ClockGuard>`
  - per-rule `clock_updates: Vec<ClockUpdate>`

### 3. SMT Transition Encoding

What exists:

- Global logical time variable:
  - `time_0 = 0`
  - `time_{k+1} = time_k + 1`
- Clock variables:
  - `clk_{k,c}` with non-negativity and rule-based updates.
- Partial synchrony constraints (selected paths):
  - For selective network settings, post-GST delivery equalities are added in faithful cases.
  - For lossy modes, post-GST drop is forced to zero (`net_drop = 0`).

### 4. Fair-Liveness (Bounded + Unbounded)

What exists:

- Bounded fair lasso (`build_fair_lasso_encoding`):
  - requires loop start to be post-GST (`gst <= time(loop_start)`).
  - fairness antecedent includes post-GST gating.
- Unbounded fair PDR:
  - monitor arm (`choose`) is constrained to post-GST.
  - fairness-enable tracking is gated by post-GST.

This is the strongest currently-implemented integration point for GST.

## Identified Gaps

### Gap A: No first-class timing DSL construct

Current timing is encoded through `adversary` key/value entries. This blocks richer timing semantics (explicit GST mode, delay bounds, timing-scope options) without overloading unrelated adversary fields.

### Gap B: Post-GST delivery semantics are not uniform

Post-GST reliability is conditionally enforced and depends on network/fault mode combinations. In particular, classic message-network paths do not get a uniform "post-GST reliable delivery" constraint family.

Result: two specs both marked `timing: partial_synchrony` can receive materially different post-GST semantics depending on other switches, which is surprising and hard to reason about.

### Gap C: No bounded-delay (`Delta`) encoding

There is no explicit finite-delivery-bound variable/constraint after GST. Current constraints enforce selected post-GST restrictions (for example `drop=0`), but not a first-class bounded-delay contract.

### Gap D: GST is parameter-only, not an explicit stabilization point in bounded encodings

Current bounded/lasso semantics reference `gst` via parameter variables. The intended GST-03 direction ("existential GST point with bounded post-GST delivery") is not yet represented as an explicit stabilization step object.

### Gap E: GST uses static parameter references even when parameters can vary by step

Epoch/time-varying parameter support exists elsewhere (`param_var_at_step`), but GST constraints currently read static `param_var(gst_pid)` paths in timing guards. That prevents clean composition with reconfiguration-style step-varying semantics.

### Gap F: Clock model is global and can over-constrain concurrent updates

Clocks are protocol-level integers. If multiple rules that touch the same clock fire in one step, constraints imply a single shared `clk_{k+1,c}` value must satisfy each fired-rule update implication, which can force unintended equalities. This is acceptable for v1 abstraction but should be explicit in timing semantics documentation.

## Concrete Semantics Proposal (for GST-02/03/04)

### GST-02 (DSL/IR): Introduce first-class timing block

Add:

```trs
timing {
    model: partial_synchrony;   // async | partial_synchrony
    gst: gst;                   // parameter or existential mode (v1: parameter)
    delay_bound: 1;             // optional v1 default
}
```

IR target (v1-minimal):

- `TimingSpec { model, gst_source, delay_bound_opt }`
- preserve backward compatibility by lowering legacy adversary keys into this structure.

### GST-03 (SMT): Add explicit GST-step semantics in bounded encodings

For depth `K`, add `gst_step` with:

- `0 <= gst_step <= K`
- `post_gst(k) := gst_step <= time_k`

Compatibility bridge:

- if user provides `gst: <param>`, constrain `gst_step = p_gst` (or `p_gst_k` in epoch-aware paths).

Post-GST network v1 contract (uniform baseline):

- `post_gst(k) -> net_drop_{k,m} = 0`
- `post_gst(k) -> net_deliver_{k,m} = net_pending_{k,m} + net_send_{k,m} + net_forge_{k,m}`
  - with existing honest-sender gates preserved where authentication/byzantine semantics require it.

This gives a deterministic, mode-independent baseline for partial synchrony in v1.

### GST-04 (verification integration): enforce post-GST proof scope consistently

Keep current fair-lasso / fair-PDR gating, but route all post-GST checks through the same `post_gst(k)` predicate family from GST-03.

Required consistency points:

- lasso loop-start post-GST constraint;
- fairness enablement post-GST gating;
- monitor arm post-GST gating;
- witness extraction metadata includes chosen GST step.

## Test and Acceptance Additions (Derived from Gaps)

1. DSL compatibility:
   - parse/lower both legacy adversary timing keys and new `timing { ... }`.
2. Encoding consistency:
   - partial synchrony + classic network emits post-GST delivery constraints.
3. Bounded GST-step:
   - `gst_step` declared and constrained for fair-lasso and k-induction contexts.
4. Epoch compatibility:
   - when GST parameter is time-varying, timing constraints use step-aware parameter references.
5. Fairness integration:
   - lasso and fair-PDR use the same `post_gst` predicate family.

## Sequenced Follow-On Plan

1. `GST-02`: parser/AST/IR timing block + lowering bridge from legacy adversary keys.
2. `GST-03`: SMT `gst_step` + uniform post-GST delivery constraints.
3. `GST-04`: unify fair-lasso/fair-PDR post-GST gating through shared predicate construction.

## Acceptance for GST-01

This task is complete when:

- current timing/GST behavior is documented across DSL, IR, SMT, and fair-liveness paths;
- concrete semantic gaps are identified with implementation implications;
- a scoped, sequential semantics proposal is provided for `GST-02/03/04`.
