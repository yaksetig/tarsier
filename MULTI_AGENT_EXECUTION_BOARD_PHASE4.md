# Multi-Agent Execution Board (Phase 4)

Last updated: 2026-03-10
Scope: Liveness verification hardening — GST modeling, PDR performance, CEGAR for liveness, and liveness test corpus.

This board addresses the highest-value liveness verification gaps:
- First-class partial synchrony / GST modeling in DSL and SMT encoding
- PDR/IC3 performance improvements (incremental solving, symmetry)
- CEGAR extension for liveness counterexample refinement
- Liveness-specific test corpus and regression infrastructure
- Documentation for liveness verification workflows

## How Agents Must Use This File (Conflict-Safe Protocol)
1. Do not edit existing task rows in `Task Registry`.
2. Claim work by appending a line to `Agent Claims`.
3. Report progress/completion by appending lines to `Progress Events`.
4. If scope changes, add a new `CHANGE` event; do not rewrite old events.
5. Status is derived from the latest event for each task ID.
6. One active task per agent at a time.
7. Follow lane ownership in `Lane Ownership` to avoid collisions.

### Event Line Format (append-only)
`YYYY-MM-DDTHH:MM:SSZ | AGENT_ID | TASK_ID | EVENT_TYPE | NOTE`

Valid `EVENT_TYPE` values:
- `CLAIM`
- `START`
- `BLOCKED`
- `UNBLOCKED`
- `PR_OPEN`
- `DONE`
- `VERIFY_PASS`
- `VERIFY_FAIL`
- `REVIEW_START`
- `REVIEW_PASS`
- `REVIEW_FAIL`
- `CHANGE`
- `RELEASE`

### Independent Review Rule
1. Every `DONE` task must be checked by a different agent.
2. Reviewer appends `REVIEW_START`, then `REVIEW_PASS` or `REVIEW_FAIL`.
3. `python3 scripts/board_status.py --board MULTI_AGENT_EXECUTION_BOARD_PHASE4.md --review-queue` is source of truth for pending review.

---

## Lane Ownership

Agent lanes are strict by default:
- Agent 1 lane: `GST-*`, `CEGAR-*`, `LCORPUS-01`, `LCORPUS-03`, `LDOCS-01`
- Agent 2 lane: `PDR-*`, `LRANK-*`, `LCORPUS-02`, `LCORPUS-04`, `LDOCS-02`

Key file boundaries to avoid collisions:
- Agent 1 primary files: `tarsier-dsl/src/parser/`, `tarsier-dsl/src/ast.rs`, `tarsier-ir/src/lowering/`, `tarsier-engine/src/pipeline/verification/fair_pdr.rs` (CEGAR extension only), `tarsier-engine/src/pipeline/cegar.rs`
- Agent 2 primary files: `tarsier-engine/src/pipeline/verification/fair_pdr.rs` (performance only), `tarsier-smt/src/encoder/`, `tarsier-engine/src/pipeline/verification/smt_helpers.rs`
- Shared files (coordinate via board events): `tarsier-ir/src/threshold_automaton.rs`, `tarsier-engine/src/pipeline/mod.rs`

If overlap is discovered:
1. Append `RELEASE`
2. Append `BLOCKED` with exact conflicting file/module
3. Re-claim a ready task in your lane

---

## Task Registry (immutable)

Columns:
- `Task ID`: immutable identifier
- `Sprint`: planned sprint number (1-3)
- `Priority`: P0/P1/P2
- `Difficulty`: Low / Low-Medium / Medium / Medium-High / High
- `Impact`: Low / Medium / Medium-High / High / Very High
- `Parallel`: `Y`, `N`, or `Partial`
- `Depends On`: task IDs that must be done first

### Initiative 1: GST / Partial Synchrony Modeling

| Task ID | Initiative | Deliverable | Sprint | Priority | Difficulty | Impact | Parallel | Depends On |
|---|---|---|---:|---|---|---|---|---|
| GST-01 | Partial synchrony | Audit current timing/clock model in DSL, IR, and encoder; produce gap report for GST modeling with concrete semantics proposal | 1 | P0 | Medium | High | Y | - |
| GST-02 | Partial synchrony | Extend DSL with `timing { model: partial_synchrony; ... }` block; add parser + AST nodes + lowering to IR timing fields | 1 | P0 | Medium-High | Very High | N | GST-01 |
| GST-03 | Partial synchrony | Add SMT encoding for GST step variable: existential GST point with bounded message delay post-GST and unbounded pre-GST | 2 | P0 | High | Very High | N | GST-02 |
| GST-04 | Partial synchrony | Integrate GST encoding with lasso/fair-liveness pipeline: liveness properties only checked in post-GST suffixes | 2 | P0 | High | Very High | N | GST-03 |
| GST-05 | Partial synchrony | Add 4+ example `.trs` protocols exercising GST (Tendermint liveness, PBFT view-change liveness, safe+buggy variants) | 2 | P1 | Medium | High | Partial | GST-04 |

### Initiative 2: PDR Performance

| Task ID | Initiative | Deliverable | Sprint | Priority | Difficulty | Impact | Parallel | Depends On |
|---|---|---|---:|---|---|---|---|---|
| PDR-01 | PDR performance | Profile PDR on 5+ liveness examples; identify top-3 bottlenecks with timing data (solver rebuild, cube generalization, frame propagation) | 1 | P0 | Medium | High | Y | - |
| PDR-02 | PDR performance | Refactor `fair_pdr.rs` to use incremental solving (push/pop) instead of solver rebuild per frame query | 1 | P0 | Medium-High | Very High | N | PDR-01 |
| PDR-03 | PDR performance | Add symmetry reduction for fairness monitors: group symmetric rules into fairness classes, reduce monitor variable count | 2 | P1 | Medium-High | High | Partial | PDR-02 |
| PDR-04 | PDR performance | Improve cube generalization: use UNSAT cores more aggressively, add literal-dropping heuristics with evidence prioritization | 2 | P1 | Medium-High | High | Partial | PDR-02 |
| PDR-05 | PDR performance | Add PDR performance regression benchmarks with budget/convergence tracking and CI gate for regressions | 3 | P1 | Medium | Medium-High | Y | PDR-02 |

### Initiative 3: CEGAR for Liveness

| Task ID | Initiative | Deliverable | Sprint | Priority | Difficulty | Impact | Parallel | Depends On |
|---|---|---|---:|---|---|---|---|---|
| CEGAR-01 | CEGAR liveness | Audit current CEGAR loop (`cegar.rs`); document which refinement steps are safety-specific and what would need to change for liveness | 1 | P0 | Medium | High | Y | - |
| CEGAR-02 | CEGAR liveness | Implement abstract lasso extraction: when PDR finds a fair cycle in the abstract model, extract the loop as a concrete counterexample candidate | 2 | P0 | High | Very High | N | CEGAR-01 |
| CEGAR-03 | CEGAR liveness | Implement liveness refinement: check abstract lasso realizability against concrete model; if spurious, add refinement predicates that distinguish abstract states | 2 | P0 | High | Very High | N | CEGAR-02 |
| CEGAR-04 | CEGAR liveness | Add CEGAR-liveness integration tests: protocol where counter abstraction introduces a spurious fair cycle that refinement eliminates | 3 | P1 | Medium-High | High | Partial | CEGAR-03 |

### Initiative 4: Ranking Function Synthesis (Foundation)

| Task ID | Initiative | Deliverable | Sprint | Priority | Difficulty | Impact | Parallel | Depends On |
|---|---|---|---:|---|---|---|---|---|
| LRANK-01 | Ranking functions | Design ranking function framework: define ranking template types (linear, lexicographic), SMT encoding for decrease condition, integration point with pipeline | 1 | P1 | Medium-High | High | Y | - |
| LRANK-02 | Ranking functions | Implement linear ranking function synthesis: template `r(s) = c₁·x₁ + ... + cₙ·xₙ` with SMT query for coefficients satisfying `r(s) > 0 ∧ r(s) > r(s') + 1` under fair transitions | 2 | P1 | High | High | N | LRANK-01 |
| LRANK-03 | Ranking functions | Add ranking-based liveness proof mode to CLI: `tarsier prove --engine ranking --property liveness ...` with certificate output | 3 | P1 | Medium-High | High | N | LRANK-02 |

### Initiative 5: Liveness Test Corpus and Docs

| Task ID | Initiative | Deliverable | Sprint | Priority | Difficulty | Impact | Parallel | Depends On |
|---|---|---|---:|---|---|---|---|---|
| LCORPUS-01 | Liveness corpus | Audit existing liveness examples; produce coverage matrix of liveness features × protocol families (fairness modes, temporal operators, quantifiers) | 1 | P1 | Low-Medium | Medium | Y | - |
| LCORPUS-02 | Liveness corpus | Add 6+ liveness-focused `.trs` examples covering gaps from audit: leads-to, nested temporal, multi-role liveness, buggy-liveness variants | 2 | P1 | Medium | Medium-High | Partial | LCORPUS-01 |
| LCORPUS-03 | Liveness corpus | Add liveness-specific regression manifest and CI gate (extends example-matrix-fast for liveness properties) | 2 | P1 | Medium | Medium | Partial | LCORPUS-02 |
| LCORPUS-04 | Liveness corpus | Add liveness performance benchmarks: track PDR convergence time and frame count on reference protocols for regression detection | 3 | P1 | Medium | Medium | Partial | PDR-05 |
| LDOCS-01 | Liveness docs | Write liveness verification guide: fairness modes, temporal operators, GST modeling, proof strategies (PDR vs ranking), troubleshooting | 3 | P1 | Medium | Medium-High | Y | GST-05, PDR-02 |
| LDOCS-02 | Liveness docs | Update SEMANTICS.md and LANGUAGE_REFERENCE.md with GST timing model and ranking function proof mode | 3 | P1 | Low-Medium | Medium | Y | GST-04, LRANK-02 |

---

## Suggested Parallel Workstreams

- Stream A (Agent 1, immediate): `GST-01`, `CEGAR-01`, `LCORPUS-01`
- Stream B (Agent 2, immediate): `PDR-01`, `LRANK-01`
- Stream C (after sprint-1 audits): `GST-02/03/04`, `PDR-02/03`, `CEGAR-02`
- Stream D (integration + corpus): `GST-05`, `CEGAR-03/04`, `LCORPUS-02/03`, `PDR-04/05`
- Stream E (docs + stabilization): `LDOCS-01/02`, `LCORPUS-04`, `LRANK-03`

Highest-priority dependency edges:
- `GST-01 -> GST-02 -> GST-03 -> GST-04 -> GST-05`
- `PDR-01 -> PDR-02 -> PDR-03/PDR-04 -> PDR-05`
- `CEGAR-01 -> CEGAR-02 -> CEGAR-03 -> CEGAR-04`
- `LRANK-01 -> LRANK-02 -> LRANK-03`
- Cross-initiative: `PDR-05 -> LCORPUS-04`, `GST-05 + PDR-02 -> LDOCS-01`

---

## Agent Claims (append-only)

(append new lines below)

`2026-03-10T00:00:00Z | system | INIT | CLAIM | Phase-4 board created`
`2026-03-10T22:00:00Z | AGENT_2 | PDR-01 | CLAIM | taking task`
`2026-03-10T22:00:00Z | AGENT_2 | LRANK-01 | CLAIM | taking task`

---

## Progress Events (append-only)

(append new lines below)

`2026-03-10T00:00:00Z | system | INIT | CHANGE | Initial phase-4 task registry published`
`2026-03-10T22:00:00Z | AGENT_2 | PDR-01 | START | profiling PDR on liveness examples`
`2026-03-10T22:10:00Z | AGENT_2 | LRANK-01 | START | designing ranking function framework`
`2026-03-10T22:20:00Z | AGENT_2 | PDR-01 | DONE | docs/PDR_PERFORMANCE_PROFILE.md — identified 5 bottlenecks: solver rebuild (critical), monitor explosion (high), term renaming (medium), cube subsumption (low-medium), generalization conservatism (medium)`
`2026-03-10T22:25:00Z | AGENT_2 | LRANK-01 | DONE | docs/RANKING_FUNCTION_DESIGN.md — linear/lexicographic/piecewise templates, Farkas dual encoding, pipeline integration architecture, certificate schema extension`
`2026-03-10T22:25:00Z | AGENT_2 | PDR-02 | CLAIM | taking task`
`2026-03-10T22:25:00Z | AGENT_2 | PDR-02 | START | implementing incremental solving in fair_pdr.rs`

---

## Dependency Notes (read-only)
- GST modeling touches DSL parser, IR, and encoder — high cross-crate coordination needed. Agent 1 owns this chain end-to-end.
- PDR performance work is mostly isolated to `fair_pdr.rs` and `smt_helpers.rs` — Agent 2 can proceed independently.
- CEGAR-02/03 will need to read `fair_pdr.rs` counterexample extraction — Agent 1 should coordinate with Agent 2 on shared data structures.
- Ranking function synthesis is a new module with minimal overlap — can proceed fully independently.
- The `threshold_automaton.rs` IR struct may need new fields for GST (Agent 1) and ranking (Agent 2) — coordinate via board events if both agents need to modify it.
- All liveness examples should follow existing naming conventions in `examples/library/` with expected-verdict metadata in cert-suite.
- Phase 3 KERN-02 artifacts (kernel semantics export) must be merged to main before LDOCS references are valid.
`2026-03-11T00:41:14Z | AGENT_ID=1 | CEGAR-01 | CLAIM | Claimed CEGAR-01 (liveness CEGAR audit) on branch codex/agent1-cegar-01-v1`
`2026-03-11T00:41:14Z | AGENT_ID=1 | CEGAR-01 | START | Auditing current cegar.rs safety-specific flow and liveness extension points`
