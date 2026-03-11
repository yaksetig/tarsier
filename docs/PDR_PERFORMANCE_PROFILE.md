# PDR Performance Profile (PDR-01)

> Profiling analysis of the fair PDR/IC3 engine identifying top bottlenecks.

## Methodology

Static analysis of `crates/tarsier-engine/src/pipeline/verification/fair_pdr.rs`
(~1,700 lines) and `smt_helpers.rs`, examining every solver interaction point,
data structure operation, and scaling factor.

Liveness examples examined:
- `examples/library/pbft_liveness_safe_ci.trs` (4 params, 2 phases, GST)
- `examples/library/pbft_liveness_buggy_ci.trs` (buggy variant)
- `examples/library/reliable_broadcast_safe_live.trs` (3 phases)
- `examples/library/reliable_broadcast_live_buggy.trs` (buggy variant)
- `examples/library/temporal_liveness_counterexample.trs` (temporal LTL)
- `examples/library/trivial_live.trs` (minimal baseline)
- `examples/pbft_faithful_liveness.trs` (full PBFT with view change)
- `examples/temporal_liveness.trs` (temporal operators)

## Bottleneck #1: Solver Rebuild Per Query (Critical)

**Location**: `fair_query_bad_in_frame()` (line 911), `fair_predecessor_query()` (line 955), `fair_can_push()`, `fair_try_generalize_cube_with_unsat_core()` (line 1037)

**Problem**: Every SMT query follows the pattern:
```
solver.reset()
fair_declare_all(solver, &artifacts.declarations)    // re-declare all vars
fair_assert_all(solver, &artifacts.state_assertions)  // re-assert all constraints
fair_assert_frame(solver, frame, &state_vars)         // re-assert frame cubes
solver.assert(&query_specific_term)                   // the actual query
solver.check_sat()
```

The declarations and state assertions are **identical** across all queries within
a frame level. Only the frame cubes and query-specific term change.

**Impact**: For a protocol with L locations, V shared vars, R rules, and C clocks:
- Declarations per rebuild: `2*(L + V + C + 1) + 4*R + temporal_vars`
- State assertions per rebuild: `~2*(L + V + C) + 6*R + temporal_constraints`
- A single frame iteration with B bad cubes and P predecessor queries costs
  `(B + P) * (declarations + state_assertions)` redundant work.

**Fix**: Use incremental solving with push/pop:
1. Assert declarations + state assertions once at solver creation.
2. `push()` before frame-specific + query-specific assertions.
3. `pop()` after each query.
4. Only re-push frame cubes when advancing to a new frame level.

**Expected speedup**: 2-5x on protocols with >10 rules, based on Z3 incremental
solving benchmarks. The declaration/assertion phase often dominates for small
queries where Z3 solves in <10ms but setup takes >50ms.

## Bottleneck #2: Monitor Variable Explosion (High)

**Location**: `build_unbounded_fair_pdr_artifacts()` (lines 351-420)

**Problem**: For each rule R, the monitor creates 4 variables per step:
- `mon_ce(step, rule)` — continuously/ever enabled
- `mon_fired(step, rule)` — ever fired
- Plus bit-domain constraints (2 per variable: `>= 0`, `<= 1`)

For a protocol with 24 rules (e.g., PBFT):
- 96 monitor variables per step (ce + fired for step 0 and 1)
- 192 domain constraints
- Plus snap variables for kappa, gamma, clocks

**Impact**: Monitor variables dominate state_vars_pre/post, making cube
extraction expensive and generalization harder (more literals to drop).

**Fix (symmetry reduction)**: Group symmetric rules into fairness classes.
Rules with identical guard structure (same source location, same threshold
comparison) can share a single fairness monitor. For PBFT with 4 phases ×
3 message types, this could reduce from 24 monitors to 4-6 fairness classes.

**Expected improvement**: 30-50% reduction in monitor variable count for
typical multi-phase protocols.

## Bottleneck #3: Term Renaming (Medium)

**Location**: `rename_state_vars_in_term()` (lines 751-826)

**Problem**: Full recursive AST walk for every term being renamed. Used in
`build_fair_pdr_invariant_certificate()` to create post-state versions of
invariant terms. No caching or hash-consing.

**Impact**: Medium — only called during certificate construction, not on the
hot path. However, for large transition relations with deeply nested terms,
this can take non-trivial time.

**Fix**: Use hash-consing for SmtTerm (shared interning of subterms) so
renaming is O(1) per unique subterm. This is a larger architectural change
that benefits the entire SMT pipeline.

## Bottleneck #4: Cube Subsumption Checking (Low-Medium)

**Location**: `FairPdrFrame::insert()` (lines 174-189)

**Problem**: When inserting a cube, iterates over all existing cubes to check
subsumption in both directions. For a frame with N cubes, insertion is O(N * |cube|).

**Impact**: Low for most protocols (frame sizes are typically <100 cubes).
Becomes significant if PDR explores a large state space.

**Fix**: Index cubes by their first literal for faster subsumption filtering.

## Bottleneck #5: Cube Generalization Conservatism (Medium)

**Location**: `fair_try_generalize_cube_with_unsat_core()` (line 1037)

**Problem**: Generalization only uses UNSAT cores when the solver supports
`supports_assumption_unsat_core()`. Falls back to no generalization otherwise.
Even with UNSAT core support, only drops literals that the core proves
unnecessary — no iterative literal-dropping or ternary simulation.

**Impact**: Larger cubes mean more specific blocking clauses, which means:
- More cubes needed per frame to block all bad states
- Slower convergence (more frames before fixpoint)
- More memory for frame storage

**Fix**: Add iterative literal-dropping generalization:
1. For each literal in the cube, try removing it.
2. If the predecessor query is still UNSAT without that literal, keep it removed.
3. Iterate until no more literals can be dropped.
This is standard IC3 practice (Bradley 2011).

## Summary

| Bottleneck | Severity | Effort | Expected Speedup |
|-----------|----------|--------|-----------------|
| Solver rebuild per query | Critical | Medium | 2-5x |
| Monitor variable explosion | High | Medium-High | 30-50% fewer vars |
| Term renaming | Medium | High (architectural) | Minor |
| Cube subsumption | Low-Medium | Low | Marginal |
| Cube generalization | Medium | Medium | Faster convergence |

## Recommended Priority

1. **PDR-02**: Incremental solving (push/pop) — highest ROI
2. **PDR-04**: Iterative cube generalization — improves convergence
3. **PDR-03**: Fairness class symmetry — reduces variable count
4. Term renaming / subsumption — lower priority, higher effort
