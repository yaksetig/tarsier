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
`2026-03-11T00:44:42Z | AGENT_ID=1 | CEGAR-01 | PR_OPEN | Branch codex/agent1-cegar-01-v2 commit 88294d0; PR https://github.com/yaksetig/tarsier/pull/new/codex/agent1-cegar-01-v2`
`2026-03-11T00:44:42Z | AGENT_ID=1 | CEGAR-01 | DONE | Completed CEGAR liveness audit report docs/CEGAR_LIVENESS_GAP_REPORT.md; commit 88294d0; checks: python3 scripts/board_status.py --board MULTI_AGENT_EXECUTION_BOARD_PHASE4.md`
`2026-03-11T01:02:54Z | AGENT_ID=1 | CEGAR-02 | CLAIM | Claimed CEGAR-02 on branch codex/agent1-cegar-02-v1`
`2026-03-11T01:02:54Z | AGENT_ID=1 | CEGAR-02 | START | Implementing abstract lasso witness extraction and stage-0 CEGAR report plumbing for fair-liveness`
`2026-03-11T01:12:37Z | AGENT_ID=1 | CEGAR-02 | PR_OPEN | Branch codex/agent1-cegar-02-v1 commit 44f0c20; PR https://github.com/yaksetig/tarsier/pull/new/codex/agent1-cegar-02-v1`
`2026-03-11T01:12:37Z | AGENT_ID=1 | CEGAR-02 | DONE | Implemented abstract lasso witness extraction + CEGAR stage report/CLI JSON wiring; commit 44f0c20; checks: cargo test -p tarsier-engine lasso_witness_extraction -- --nocapture; cargo test -p tarsier-engine prove_fair_liveness_with_cegar_report_exposes_controls_and_machine_readable_status -- --nocapture; cargo test -p tarsier-cli --no-run`
`2026-03-11T01:13:41Z | AGENT_ID=1 | CEGAR-03 | CLAIM | Claimed CEGAR-03 on branch codex/agent1-cegar-03-v1`
`2026-03-11T01:13:41Z | AGENT_ID=1 | CEGAR-03 | START | Implementing fair-liveness lasso realizability checks and spurious-cycle-driven predicate refinement`
`2026-03-11T01:24:26Z | AGENT_ID=1 | CEGAR-03 | PR_OPEN | Branch codex/agent1-cegar-03-v1 commit 0026f86; PR https://github.com/yaksetig/tarsier/pull/new/codex/agent1-cegar-03-v1`
`2026-03-11T01:24:26Z | AGENT_ID=1 | CEGAR-03 | DONE | Implemented fair-liveness lasso realizability replay and signal-driven refinement candidates in CEGAR loops; commit 0026f86; checks: cargo test -p tarsier-engine liveness_realizability_atoms_filter_existing_and_prioritize_signal_atoms -- --nocapture; cargo test -p tarsier-engine prove_fair_liveness_with_cegar_report_exposes_controls_and_machine_readable_status -- --nocapture`
`2026-03-11T01:25:09Z | AGENT_ID=1 | CEGAR-04 | CLAIM | Claimed CEGAR-04 on branch codex/agent1-cegar-04-v1`
`2026-03-11T01:25:09Z | AGENT_ID=1 | CEGAR-04 | START | Adding fair-liveness CEGAR integration test where a baseline abstract lasso is eliminated by realizability replay refinements`
`2026-03-11T01:37:36Z | AGENT_ID=1 | CEGAR-04 | PR_OPEN | Branch codex/agent1-cegar-04-v1 commit d5bf688; PR https://github.com/yaksetig/tarsier/pull/new/codex/agent1-cegar-04-v1`
`2026-03-11T01:37:36Z | AGENT_ID=1 | CEGAR-04 | DONE | Added fair-liveness CEGAR integration test covering baseline fair-cycle witness becoming inconclusive under realizability replay with added predicates; commit d5bf688; checks: cargo test -p tarsier-engine prove_fair_liveness_with_cegar_report_replay_marks_baseline_cycle_inconclusive -- --nocapture; cargo test -p tarsier-engine prove_fair_liveness_with_cegar_report_exposes_controls_and_machine_readable_status -- --nocapture`
`2026-03-11T01:53:48Z | AGENT_ID=1 | GST-01 | CLAIM | Claimed GST-01 on branch codex/agent1-gst-lcorpus-01-v1`
`2026-03-11T01:53:48Z | AGENT_ID=1 | GST-01 | START | Auditing timing/clock semantics across DSL, IR, and SMT encoder for GST partial synchrony gaps`
`2026-03-11T01:54:47Z | AGENT_ID=1 | GST-01 | PR_OPEN | Branch codex/agent1-gst-lcorpus-01-v1 commit f589b38; PR https://github.com/yaksetig/tarsier/pull/new/codex/agent1-gst-lcorpus-01-v1`
`2026-03-11T01:54:47Z | AGENT_ID=1 | GST-01 | DONE | Published timing/GST audit and semantics proposal at docs/GST_TIMING_GAP_REPORT.md; commit f589b38; checks: python3 scripts/board_status.py --board MULTI_AGENT_EXECUTION_BOARD_PHASE4.md`
`2026-03-11T01:55:01Z | AGENT_ID=1 | LCORPUS-01 | CLAIM | Claimed LCORPUS-01 on branch codex/agent1-gst-lcorpus-01-v1`
`2026-03-11T01:55:01Z | AGENT_ID=1 | LCORPUS-01 | START | Building liveness feature coverage matrix across existing protocol examples`
`2026-03-11T01:55:54Z | AGENT_ID=1 | LCORPUS-01 | PR_OPEN | Branch codex/agent1-gst-lcorpus-01-v1 commit 986bde2; PR https://github.com/yaksetig/tarsier/pull/new/codex/agent1-gst-lcorpus-01-v1`
`2026-03-11T01:55:54Z | AGENT_ID=1 | LCORPUS-01 | DONE | Published liveness example corpus matrix at docs/LIVENESS_CORPUS_COVERAGE_MATRIX.md; commit 986bde2; checks: rg -n --glob 'examples/**/*.trs' 'property\\s+.*:\\s*liveness'; python3 scripts/board_status.py --board MULTI_AGENT_EXECUTION_BOARD_PHASE4.md`
`2026-03-11T02:02:44Z | AGENT_ID=1 | GST-02 | CLAIM | Claimed GST-02 on branch codex/agent1-gst-02-v1`
`2026-03-11T02:02:44Z | AGENT_ID=1 | GST-02 | START | Implementing first-class timing block in DSL/AST/parser with lowering bridge from legacy adversary timing keys`


running 1 test
test parser::tests::resolve_imports_merges_timing_when_missing ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 152 filtered out; finished in 0.00s


running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 85 filtered out; finished in 0.00s


running 1 test
test lowering::tests::lower_first_class_timing_block_to_ir_semantics ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 346 filtered out; finished in 0.00s


running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 11 filtered out; finished in 0.00s


running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 30 filtered out; finished in 0.00s


running 1 test
test lowering::tests::lower_rejects_conflicting_legacy_and_first_class_timing_models ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 346 filtered out; finished in 0.00s


running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 11 filtered out; finished in 0.00s


running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 30 filtered out; finished in 0.00s


running 1 test
test lowering::tests::lower_rejects_partial_synchrony_without_gst ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 346 filtered out; finished in 0.00s


running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 11 filtered out; finished in 0.00s


running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 30 filtered out; finished in 0.00s
2026-03-11T02:19:32Z | AGENT_ID=1 | GST-02 | PR_OPEN | Branch codex/agent1-gst-02-v1 commit f53261c; PR https://github.com/yaksetig/tarsier/pull/new/codex/agent1-gst-02-v1
2026-03-11T02:19:32Z | AGENT_ID=1 | GST-02 | DONE | Added first-class timing DSL block (model/gst) + AST/parser/import merge + lowering bridge with legacy adversary timing/gst compatibility/conflict checks; commit f53261c; checks: cargo test -p tarsier-dsl parse_first_class_timing_block -- --nocapture; cargo test -p tarsier-dsl resolve_imports_merges_timing_when_missing -- --nocapture; cargo test -p tarsier-ir lower_first_class_timing_block_to_ir_semantics -- --nocapture; cargo test -p tarsier-ir lower_rejects_conflicting_legacy_and_first_class_timing_models -- --nocapture; cargo test -p tarsier-ir lower_rejects_partial_synchrony_without_gst -- --nocapture; cargo check --workspace
2026-03-11T02:20:32Z | AGENT_ID=1 | GST-03 | CLAIM | Claimed GST-03 on branch codex/agent1-gst-02-v1
2026-03-11T02:20:32Z | AGENT_ID=1 | GST-03 | START | Implementing SMT gst_step existential and post-GST predicate wiring in bounded/k-induction encoders
2026-03-11T02:25:09Z | AGENT_ID=1 | GST-03 | PR_OPEN | Branch codex/agent1-gst-02-v1 commit b8f4ce3; PR https://github.com/yaksetig/tarsier/pull/new/codex/agent1-gst-02-v1
2026-03-11T02:25:09Z | AGENT_ID=1 | GST-03 | DONE | Added existential gst_step variable and post-GST predicate wiring in BMC + k-induction SMT encoders, including gst_step=param bridge when gst param exists and updated encoder tests; commit b8f4ce3; checks: cargo test -p tarsier-smt omission_partial_sync_encodes_drop_and_post_gst_delivery -- --nocapture; cargo test -p tarsier-smt partial_synchrony_faithful_channels_force_honest_post_gst_delivery -- --nocapture; cargo test -p tarsier-smt kinduction_omission_partial_sync_encodes_drop_bound_and_post_gst_delivery -- --nocapture; cargo check --workspace
2026-03-11T02:27:03Z | AGENT_ID=1 | GST-04 | CLAIM | Claimed GST-04 on branch codex/agent1-gst-04-v1
2026-03-11T02:27:03Z | AGENT_ID=1 | GST-04 | START | Unifying fair-lasso and fair-PDR post-GST gating onto shared gst_step predicate family
2026-03-11T02:33:13Z | AGENT_ID=1 | GST-04 | PR_OPEN | Branch codex/agent1-gst-04-v1 commit a06520b; PR https://github.com/yaksetig/tarsier/pull/new/codex/agent1-gst-04-v1
2026-03-11T02:33:13Z | AGENT_ID=1 | GST-04 | DONE | Unified fair-lasso and unbounded fair-PDR post-GST gating onto shared gst_step predicate helper (pdr_post_gst_guard_at_step) and updated helper tests/format checks; commit a06520b; checks: cargo check --workspace; cargo test -p tarsier-engine --test liveness_tests fair_liveness_partial_synchrony_ignores_pre_gst_only_cycles -- --nocapture; cargo test -p tarsier-engine --test timed_liveness_matrix timed_trivial_live_bounded_no_fair_cycle -- --nocapture
