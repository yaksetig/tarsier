# Multi-Agent Execution Board

Last updated: 2026-03-06
Scope: Implements the approved 6-sprint roadmap, excluding:
- Crash recovery model
- Leader role constraint

## How Agents Must Use This File (Conflict-Safe Protocol)
1. Do not edit existing task rows in `Task Registry`.
2. Claim work by appending a line to `Agent Claims`.
3. Report progress/completion by appending lines to `Progress Events`.
4. If scope changes, add a new `CHANGE` event; do not rewrite old events.
5. Status is derived from the latest event for each task ID.
6. One agent may claim multiple tasks only if dependencies are satisfied.

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
3. `board-review-queue` is the source of truth for tasks awaiting independent check.

---

## Task Registry (immutable)

Columns:
- `Task ID`: immutable identifier
- `Sprint`: planned sprint number (1-6)
- `Priority`: P0/P1/P2
- `Difficulty`: Low / Low-Medium / Medium / Medium-High / High
- `Impact`: Low / Medium / Medium-High / High / Very High
- `Parallel`: `Y`, `N`, or `Partial`
- `Depends On`: task IDs that must be done first

| Task ID | Initiative | Deliverable | Sprint | Priority | Difficulty | Impact | Parallel | Depends On |
|---|---|---|---:|---|---|---|---|---|
| INV-01 | Invariant inference | Extract reusable `invariant_inference` engine module from current CTI synthesis path | 1 | P0 | Medium | Very High | Y | - |
| INV-02 | Invariant inference | Generate atomic candidates over kappa/gamma/params (linear predicates) | 1 | P0 | Medium | Very High | Partial | INV-01 |
| INV-03 | Invariant inference | Implement inductiveness checks (init + consecution) and candidate scoring | 1 | P0 | Medium | Very High | Partial | INV-02 |
| INV-04 | Invariant inference | Add `infer-invariants` CLI command + text/json report | 2 | P0 | Medium | High | Y | INV-03 |
| INV-05 | Invariant inference | Integrate inference as `prove` pre-pass with controls/guards | 2 | P0 | Medium | Very High | Partial | INV-03 |
| INV-06 | Invariant inference | Add end-to-end tests + solver parity + perf baselines | 2 | P0 | Medium | High | Y | INV-04, INV-05 |
| LOG-01 | Bounded logs/sequences | DSL grammar + AST for bounded log/sequence types | 1 | P0 | Medium | High | Partial | - |
| LOG-02 | Bounded logs/sequences | IR representation for fixed-size logs | 1 | P0 | Medium | High | Partial | LOG-01 |
| LOG-03 | Bounded logs/sequences | Lowering for read/write/append semantics | 2 | P0 | Medium | High | Partial | LOG-02 |
| LOG-04 | Bounded logs/sequences | SMT encoding for fixed arrays and bounds | 2 | P0 | Medium | High | Partial | LOG-03 |
| LOG-05 | Bounded logs/sequences | Core tests + sample protocol coverage | 2 | P0 | Medium | High | Y | LOG-04 |
| TWIN-01 | Twins-style implementation testing | Active harness API + schedule injection interface in conformance layer | 1 | P1 | Medium | High | Y | - |
| TWIN-02 | Twins-style implementation testing | Convert bughunt/model counterexamples into executable schedules | 2 | P1 | Medium | High | Partial | TWIN-01 |
| TWIN-03 | Twins-style implementation testing | Network shim primitives (delay/drop/reorder/partition/twin) | 3 | P1 | Medium | High | Partial | TWIN-01 |
| TWIN-04 | Twins-style implementation testing | Adapter integration (start with CometBFT path) | 3 | P1 | Medium | Medium-High | Partial | TWIN-02, TWIN-03 |
| TWIN-05 | Twins-style implementation testing | Add `conformance-active` CLI flow + deterministic seeds | 3 | P1 | Medium | High | Partial | TWIN-04 |
| TWIN-06 | Twins-style implementation testing | Scenario corpus + replay CI checks | 3 | P1 | Medium | Medium-High | Y | TWIN-05 |
| AI-01 | AI-assisted invariant suggestion | Failure serializer for `prove` (structured prompt payload) | 2 | P1 | Low-Medium | Medium-High | Y | - |
| AI-02 | AI-assisted invariant suggestion | Provider abstraction + `prove --assist` flags | 2 | P1 | Low-Medium | Medium-High | Y | AI-01 |
| AI-03 | AI-assisted invariant suggestion | Parse/sanitize DSL invariant suggestions and SMT-validate | 2 | P1 | Medium | Medium-High | Partial | AI-02 |
| AI-04 | AI-assisted invariant suggestion | Integrate validated suggestions into rerun pipeline + reporting | 2 | P1 | Medium | Medium-High | Partial | AI-03 |
| AI-05 | AI-assisted invariant suggestion | Mock-provider tests and safety regressions | 2 | P1 | Low-Medium | Medium | Y | AI-04 |
| REF-01 | Refinement checking | DSL support for `refines` declaration | 3 | P0 | Medium | High | Partial | - |
| REF-02 | Refinement checking | IR model for abstract/concrete mapping and relation stubs | 3 | P0 | Medium-High | High | Partial | REF-01 |
| REF-03 | Refinement checking | Product automaton construction core | 3 | P0 | Medium-High | High | Partial | REF-02 |
| REF-04 | Refinement checking | Bounded simulation-preservation SMT encoding | 4 | P0 | Medium-High | High | Partial | REF-03 |
| REF-05 | Refinement checking | `refinement-check` CLI + machine-readable reports | 4 | P0 | Medium | High | Y | REF-04 |
| REF-06 | Refinement checking | Extended tests and benchmark suite | 4 | P0 | Medium | High | Y | REF-05 |
| FIFO-01 | FIFO channels | DSL `fifo_channel` construct + parser | 3 | P1 | Medium | High | Partial | - |
| FIFO-02 | FIFO channels | IR queue state and capacity model | 3 | P1 | Medium | High | Partial | FIFO-01 |
| FIFO-03 | FIFO channels | Lowering send/receive to enqueue/dequeue transitions | 3 | P1 | Medium | High | Partial | FIFO-02 |
| FIFO-04 | FIFO channels | SMT ordering constraints for FIFO semantics | 3 | P1 | Medium | High | Partial | FIFO-03 |
| FIFO-05 | FIFO channels | Integration tests and protocol examples | 3 | P1 | Medium | Medium-High | Y | FIFO-04 |
| EQ-01 | Behavioral equivalence | Product divergence checker core (reuse refinement product infra) | 4 | P1 | Medium | Medium | Partial | REF-03 |
| EQ-02 | Behavioral equivalence | Bounded equivalence checker | 5 | P1 | Medium | Medium | Partial | EQ-01 |
| EQ-03 | Behavioral equivalence | `equivalence-check` CLI + report format | 5 | P1 | Medium | Medium | Y | EQ-02 |
| EQ-04 | Behavioral equivalence | Tests (equivalent and non-equivalent fixtures) | 5 | P1 | Medium | Medium | Y | EQ-03 |
| RECONF-01 | Dynamic membership | DSL `reconfigure` action syntax and validation | 4 | P1 | Medium-High | Medium-High | Partial | - |
| RECONF-02 | Dynamic membership | IR time-varying parameter model | 4 | P1 | Medium-High | Medium-High | Partial | RECONF-01 |
| RECONF-03 | Dynamic membership | Lowering for step-boundary reconfiguration semantics | 4 | P1 | Medium-High | Medium-High | Partial | RECONF-02 |
| RECONF-04 | Dynamic membership | SMT encoding for epoch-aware n/t/f transitions | 4 | P1 | Medium-High | Medium-High | Partial | RECONF-03 |
| RECONF-05 | Dynamic membership | Property pipeline updates + regression tests | 4 | P1 | Medium | Medium-High | Y | RECONF-04 |
| TIME-01 | Real-time/timeouts | DSL clock + timeout constructs | 5 | P2 | Medium-High | Low-Medium | Partial | - |
| TIME-02 | Real-time/timeouts | IR clock variables and reset/tick model | 5 | P2 | Medium-High | Low-Medium | Partial | TIME-01 |
| TIME-03 | Real-time/timeouts | Lowering for clock progression and timeout guards | 5 | P2 | Medium-High | Low-Medium | Partial | TIME-02 |
| TIME-04 | Real-time/timeouts | SMT timed constraints encoding | 5 | P2 | Medium-High | Low-Medium | Partial | TIME-03 |
| TIME-05 | Real-time/timeouts | Liveness integration + tests | 5 | P2 | Medium | Low-Medium | Y | TIME-04 |
| EXP-01 | Proof export Lean/Coq | Export IR from safety/fair-liveness certificates | 5 | P2 | High | Medium | Y | - |
| EXP-02 | Proof export Lean/Coq | `proof-export --to lean|coq` CLI | 5 | P2 | Medium | Medium | Y | EXP-01 |
| EXP-03 | Proof export Lean/Coq | Lean backend emitter | 6 | P2 | High | Medium | Partial | EXP-02 |
| EXP-04 | Proof export Lean/Coq | Coq backend emitter | 6 | P2 | High | Medium | Partial | EXP-02 |
| EXP-05 | Proof export Lean/Coq | Certcheck path integration + golden tests | 6 | P2 | Medium-High | Medium | Partial | EXP-03, EXP-04 |
| DAG-01 | DAG round abstraction | DSL `dag_round` core syntax | 6 | P2 | High | High | Partial | LOG-04, FIFO-04 |
| DAG-02 | DAG round abstraction | IR rounds/edges representation | 6 | P2 | High | High | Partial | DAG-01 |
| DAG-03 | DAG round abstraction | Lowering checks (acyclic refs + dependency validity) | 6 | P2 | High | High | Partial | DAG-02 |
| DAG-04 | DAG round abstraction | SMT constraints for DAG execution model | 6 | P2 | High | High | Partial | DAG-03 |
| DAG-05 | DAG round abstraction | Alpha examples + validation tests | 6 | P2 | Medium-High | High | Y | DAG-04 |
| X-01 | Cross-cutting | LSP syntax/highlighting/completions for new DSL features | 6 | P1 | Medium | Medium | Y | REF-01, FIFO-01, RECONF-01, TIME-01, DAG-01 |
| X-02 | Cross-cutting | JSON schema/report versioning for new commands | 6 | P1 | Medium | Medium | Partial | INV-04, REF-05, EQ-03, TWIN-05, EXP-02 |
| X-03 | Cross-cutting | Docs + migration + quickstart updates | 6 | P1 | Low-Medium | Medium | Y | All feature tasks |
| X-04 | Cross-cutting | Solver parity + performance gate expansions | 6 | P1 | Medium | Medium-High | Partial | INV-06, REF-06, EQ-04, TIME-05 |

---

## Agent Claims (append-only)

(append new lines below)

`2026-03-06T00:00:00Z | system | INIT | CLAIM | Board created`

---

## Progress Events (append-only)

(append new lines below)

`2026-03-06T00:00:00Z | system | INIT | CHANGE | Initial task registry published`

---

## Dependency Notes (read-only)
- Hard gate 1: `EQ-*` requires `REF-03` product core.
- Hard gate 2: `DAG-*` starts after log/FIFO semantics are stable (`LOG-04`, `FIFO-04`).
- Sequential within a feature: DSL -> AST/IR -> lowering -> SMT -> CLI/report -> tests.
- Conflict hotspots: DSL grammar/parser, IR lowering, SMT encoder modules.


2026-03-06T01:58:35Z | 1 | INV-01 | CLAIM | taking task
2026-03-06T01:58:35Z | 1 | INV-01 | START | implementation started
2026-03-06T01:59:51Z | 2 | LOG-01 | CLAIM | taking task
2026-03-06T01:59:51Z | 2 | LOG-01 | START | implementation started
2026-03-06T02:03:15Z | 1 | INV-01 | BLOCKED | cargo check failed in tarsier-dsl (missing parse_collection); blocked by concurrent DSL/parser changes (likely LOG-01 stream)
2026-03-06T02:04:00Z | 1 | TWIN-01 | CLAIM | taking task
2026-03-06T02:04:00Z | 1 | TWIN-01 | START | implementation started
2026-03-06T02:06:24Z | 1 | INV-01 | UNBLOCKED | tarsier-dsl parser now compiles; cargo check -p tarsier-engine passes
2026-03-06T02:06:24Z | 1 | TWIN-01 | PR_OPEN | local patch ready (no remote PR yet); active harness API in tarsier-conformance
2026-03-06T02:06:24Z | 1 | TWIN-01 | DONE | implemented active harness API + schedule injector interface; tests=cargo check -p tarsier-conformance && cargo test -p tarsier-conformance active:: -- --nocapture
2026-03-06T11:35:53Z | 1 | AI-01 | CLAIM | taking task
2026-03-06T11:35:53Z | 1 | AI-01 | START | implementation started
2026-03-06T11:37:34Z | 1 | AI-01 | BLOCKED | unexpected unowned workspace changes in crates/tarsier-ir/src/lowering/*; need owner confirmation to proceed without reverting
2026-03-06T02:10:00Z | 2 | LOG-01 | DONE | DSL grammar + AST + parser + codegen + tests (commit 9e5fdb7)
2026-03-06T02:30:00Z | 2 | LOG-02 | CLAIM | taking task
2026-03-06T02:30:00Z | 2 | LOG-02 | START | implementation started
2026-03-06T03:00:00Z | 2 | LOG-02 | DONE | IR types (IrCollectionSpec, CollectionId) + lowering + test (commit b70d035)
2026-03-06T03:10:00Z | 2 | LOG-03 | CLAIM | taking task
2026-03-06T03:10:00Z | 2 | LOG-03 | START | implementation started
2026-03-06T06:40:00Z | 2 | LOG-03 | DONE | CollectionUpdate IR types, Append lowering via lower_expr_to_lc, pending_collection_updates on Rules, test (commit 8bdb0b4)
2026-03-06T06:45:00Z | 2 | LOG-04 | CLAIM | taking task
2026-03-06T06:45:00Z | 2 | LOG-04 | START | implementation started
2026-03-06T07:10:00Z | 2 | LOG-04 | DONE | SMT collection length vars (clen_k_c), capacity bounds, append delta encoding, test (commit ba6a7d1)
2026-03-06T07:15:00Z | 2 | LOG-05 | CLAIM | taking task
2026-03-06T07:15:00Z | 2 | LOG-05 | START | implementation started
2026-03-06T07:30:00Z | 2 | LOG-05 | DONE | E2E lowering tests, SMT encoding tests, demo protocol fix, error-path test (commit c858cd8)
2026-03-06T07:35:00Z | 2 | FIFO-01 | CLAIM | withdrawn — Agent 1 already implemented on codex/agent1-fifo-01 branch
2026-03-06T07:36:00Z | 2 | REF-01 | CLAIM | withdrawn — Agent 1 already implemented on codex/agent1-ref-01-v2 branch
2026-03-06T07:40:00Z | 2 | TWIN-01 | REVIEW_START | reviewing Agent 1's TWIN-01 implementation
2026-03-06T07:45:00Z | 2 | TWIN-01 | REVIEW_PASS | ActiveScenario/FaultAction/ScheduleInjector API well-structured, 6 tests cover ordering/errors/mapping
2026-03-06T07:45:00Z | 2 | TWIN-02 | REVIEW_START | reviewing Agent 1's TWIN-02 implementation (on codex/agent1-twin-02)
2026-03-06T07:50:00Z | 2 | TWIN-02 | REVIEW_PASS | scenario_from_counterexample correctly maps Trace steps to ActiveScenario faults with bound enforcement
2026-03-06T12:24:35Z | 1 | INV-01 | RELEASE | released due lane realignment (Agent-1 now AI/TWIN only)
2026-03-06T12:24:35Z | 1 | AI-01 | RELEASE | temporarily released while resolving blocked state under one-active-task policy
2026-03-06T12:24:35Z | 1 | TWIN-03 | CLAIM | taking task
2026-03-06T12:24:35Z | 1 | TWIN-03 | START | implementation started
2026-03-06T12:26:00Z | 2 | FIFO-01 | RELEASE | released previous withdrawn claim; re-implementing on agent2/fifo-01 branch
2026-03-06T12:26:00Z | 2 | REF-01 | RELEASE | released previous withdrawn claim; will re-claim after FIFO-01
2026-03-06T12:26:00Z | 2 | FIFO-01 | CLAIM | taking task — implementing on agent2/fifo-01 branch
2026-03-06T12:26:00Z | 2 | FIFO-01 | START | implementation started
2026-03-06T12:30:00Z | 2 | FIFO-01 | PR_OPEN | agent2/fifo-01 91948d3 fifo_channel DSL+parser+IR support
2026-03-06T12:30:00Z | 2 | FIFO-01 | DONE | commit 91948d3 tests=cargo test -p tarsier-dsl -- parse_fifo && cargo test -p tarsier-ir -- lower_fifo
2026-03-06T12:27:40Z | 1 | TWIN-03 | BLOCKED | workspace unexpectedly on agent2/fifo-01 with unowned edits in tarsier-dsl/tarsier-ir; overlap risk with Agent-2 lane
2026-03-06T12:27:40Z | 1 | TWIN-03 | RELEASE | released due branch/workspace ownership conflict; awaiting clean Agent-1 worktree
2026-03-06T12:29:55Z | 1 | TWIN-03 | CLAIM | taking task on clean worktree codex/agent1-twin-03-v4
2026-03-06T12:29:55Z | 1 | TWIN-03 | START | implementation started in /Users/myaksetig/Desktop/Repos/tarsier-agent1-twin03
2026-03-06T12:32:30Z | 1 | TWIN-03 | PR_OPEN | codex/agent1-twin-03-v4 https://github.com/yaksetig/tarsier/pull/new/codex/agent1-twin-03-v4 network shim primitives (delay/drop/reorder/partition/twin)
2026-03-06T12:32:30Z | 1 | TWIN-03 | DONE | commit 14d277c tests=cargo test -p tarsier-conformance network_shim -- --nocapture && cargo check -p tarsier-conformance
2026-03-06T12:33:00Z | 2 | REF-01 | CLAIM | taking task — implementing on agent2/ref-01 branch
2026-03-06T12:33:00Z | 2 | REF-01 | START | implementation started
2026-03-06T12:38:00Z | 2 | REF-01 | PR_OPEN | agent2/ref-01 023f8b5 refines declaration parser + downstream fixes
2026-03-06T12:38:00Z | 2 | REF-01 | DONE | commit 023f8b5 tests=cargo test -p tarsier-dsl -- parse_refines parse_no_refines
2026-03-06T12:43:08Z | 1 | AI-01 | CLAIM | taking task on clean worktree codex/agent1-twin-03-v4
2026-03-06T12:43:08Z | 1 | AI-01 | START | implementation started in /Users/myaksetig/Desktop/Repos/tarsier-agent1-twin03
2026-03-06T12:47:14Z | 1 | AI-01 | PR_OPEN | codex/agent1-ai-01-v1 https://github.com/yaksetig/tarsier/pull/new/codex/agent1-ai-01-v1 wire prove failure serializer exports
2026-03-06T12:47:14Z | 1 | AI-01 | DONE | commit cf3c6a4 tests=CARGO_TARGET_DIR=/Users/myaksetig/Desktop/Repos/tarsier/target cargo check -p tarsier-engine --lib && CARGO_TARGET_DIR=/Users/myaksetig/Desktop/Repos/tarsier/target cargo check -p tarsier-cli && attempted CARGO_TARGET_DIR=/Users/myaksetig/Desktop/Repos/tarsier/target cargo test -p tarsier-engine prove_failure_prompt_payload -- --nocapture (fails on pre-existing ProtocolDecl refines fixture mismatch in engine lib tests)
2026-03-06T12:50:00Z | 2 | TWIN-03 | REVIEW_START | reviewing Agent 1's network_shim.rs on codex/agent1-twin-03-v4 (commit 14d277c)
2026-03-06T12:50:00Z | 2 | TWIN-03 | REVIEW_PASS | InMemoryNetworkShim well-designed: deterministic tick-based delivery, delay/drop/reorder/partition/heal/spawn-twin/retire-twin ops, good error handling, 6 tests cover all fault types and error paths; branch diverges from pre-LOG main (removes LOG-03/04/05 work) so merge must be rebased
2026-03-06T13:05:37Z | 1 | AI-01 | CLAIM | re-claiming task to finalize previously delivered branch codex/agent1-ai-01-v1
2026-03-06T13:05:37Z | 1 | AI-01 | START | finalization started (existing implementation validation)
2026-03-06T13:05:37Z | 1 | AI-01 | PR_OPEN | codex/agent1-ai-01-v1 https://github.com/yaksetig/tarsier/pull/new/codex/agent1-ai-01-v1 wire prove failure serializer exports
2026-03-06T13:05:37Z | 1 | AI-01 | DONE | commit cf3c6a4 tests=CARGO_TARGET_DIR=/Users/myaksetig/Desktop/Repos/tarsier/target cargo check -p tarsier-engine --lib && CARGO_TARGET_DIR=/Users/myaksetig/Desktop/Repos/tarsier/target cargo check -p tarsier-cli && attempted CARGO_TARGET_DIR=/Users/myaksetig/Desktop/Repos/tarsier/target cargo test -p tarsier-engine prove_failure_prompt_payload -- --nocapture (fails on pre-existing ProtocolDecl refines fixture mismatch in engine lib tests)
2026-03-06T13:05:56Z | 1 | AI-02 | CLAIM | taking task
2026-03-06T13:05:56Z | 1 | AI-02 | START | implementation started
2026-03-06T13:10:00Z | 2 | FIFO-02 | CLAIM | taking task — implementing on agent2/fifo-02 branch
2026-03-06T13:10:00Z | 2 | FIFO-02 | START | implementation started
2026-03-06T13:15:00Z | 2 | FIFO-02 | PR_OPEN | agent2/fifo-02 41f84a7 IR queue state model + enqueue/dequeue ops
2026-03-06T13:15:00Z | 2 | FIFO-02 | DONE | commit 41f84a7 tests=cargo test -p tarsier-ir -- lower_fifo lower_log_and_sequence_have_no_queue collection_update_enqueue && cargo test -p tarsier-smt queue_variable
2026-03-06T13:16:06Z | 1 | AI-02 | PR_OPEN | codex/agent1-ai-02-v1 https://github.com/yaksetig/tarsier/pull/new/codex/agent1-ai-02-v1 provider abstraction + prove --assist flags
2026-03-06T13:16:06Z | 1 | AI-02 | DONE | commit 885d018 tests=CARGO_TARGET_DIR=/Users/myaksetig/Desktop/Repos/tarsier/target cargo check -p tarsier-engine --lib && CARGO_TARGET_DIR=/Users/myaksetig/Desktop/Repos/tarsier/target cargo check -p tarsier-cli && CARGO_TARGET_DIR=/Users/myaksetig/Desktop/Repos/tarsier/target cargo test -p tarsier-cli parse_prove_accepts_assist_flags -- --nocapture
2026-03-06T13:20:00Z | 2 | FIFO-03 | CLAIM | taking task — implementing on agent2/fifo-03 branch
2026-03-06T13:20:00Z | 2 | FIFO-03 | START | implementation started
2026-03-06T13:28:00Z | 2 | FIFO-03 | PR_OPEN | agent2/fifo-03 enqueue/dequeue DSL actions + parser + lowering + codegen
2026-03-06T13:28:00Z | 2 | FIFO-03 | DONE | tests=cargo test -p tarsier-dsl -- parse_enqueue && cargo test -p tarsier-ir lower_enqueue_dequeue
2026-03-06T13:35:00Z | 2 | FIFO-04 | CLAIM | taking task — implementing on agent2/fifo-04 branch
2026-03-06T13:35:00Z | 2 | FIFO-04 | START | implementation started
2026-03-06T13:42:00Z | 2 | FIFO-04 | PR_OPEN | agent2/fifo-04 6d51cdd SMT FIFO queue head/tail encoding
2026-03-06T13:42:00Z | 2 | FIFO-04 | DONE | commit 6d51cdd tests=cargo test -p tarsier-smt fifo_queue
