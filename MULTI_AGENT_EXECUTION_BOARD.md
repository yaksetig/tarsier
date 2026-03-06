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
2026-03-06T02:07:23Z | 2 | LOG-01 | DONE | commit=9e5fdb7 tests=cargo test -p tarsier-dsl -- parse_log_declaration parse_sequence_declaration parse_append_action parse_index_access_expr parse_len_expr
2026-03-06T02:07:46Z | 1 | AI-01 | CLAIM | taking task
2026-03-06T02:07:46Z | 1 | AI-01 | START | implementation started
2026-03-06T02:08:01Z | 2 | TWIN-01 | REVIEW_START | reviewing TWIN-01 active harness API
2026-03-06T02:08:27Z | 2 | TWIN-01 | REVIEW_PASS | validated; tests=cargo test -p tarsier-conformance (3 active tests pass, 64 total pass)
2026-03-06T02:08:01Z | 2 | LOG-02 | CLAIM | taking task
2026-03-06T02:08:01Z | 2 | LOG-02 | START | implementation started
2026-03-06T02:12:28Z | 1 | AI-01 | BLOCKED | build blocked in tarsier-ir lowering (missing lower_linear_expr); dependent on concurrent DSL/IR stream stabilization (likely LOG-01)
2026-03-06T02:13:08Z | 1 | TWIN-02 | CLAIM | taking task
2026-03-06T02:13:08Z | 1 | TWIN-02 | START | implementation started
2026-03-06T02:16:40Z | 1 | TWIN-02 | PR_OPEN | branch=codex/agent1-twin-02 commit=0b916df local patch ready (no remote PR yet)
2026-03-06T02:16:40Z | 1 | TWIN-02 | DONE | commit=0b916df tests=cargo check -p tarsier-conformance && cargo test -p tarsier-conformance active:: -- --nocapture
2026-03-06T02:17:48Z | 1 | TWIN-03 | CLAIM | taking task
2026-03-06T02:17:48Z | 1 | TWIN-03 | START | implementation started
2026-03-06T02:21:43Z | 1 | TWIN-03 | PR_OPEN | branch=codex/agent1-twin-03 commit=6035785 local patch ready (no remote PR yet)
2026-03-06T02:21:43Z | 1 | TWIN-03 | DONE | commit=6035785 tests=cargo fmt --package tarsier-conformance && cargo check -p tarsier-conformance && cargo test -p tarsier-conformance network_shim:: -- --nocapture && cargo test -p tarsier-conformance
