# Multi-Agent Execution Board (Phase 3)

Last updated: 2026-03-10
Scope: Quality hardening and production-readiness closure for post-phase-2 codebase.

This board addresses the current highest-value remaining gaps:
- Engine panic/unwrap hardening in production paths
- Real implementation integration testing (CometBFT + etcd-raft)
- Reconfiguration epoch reasoning closure (audit + gap fixes)
- Codegen semantic validation (model vs generated runtime behavior)
- Example corpus and docs completeness
- CI enforcement for mutation + ByMC parity
- Playground deployment path
- Formal proof roadmap/prototypes for proof kernel soundness

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
3. `python3 scripts/board_status.py --board MULTI_AGENT_EXECUTION_BOARD_PHASE3.md --review-queue` is source of truth for pending review.

---

## Lane Ownership

Agent lanes are strict by default:
- Agent 1 lane: `INTEG-*`, `CODEGEN-*`, `PLAY-*`, `DOCS-01`, `DOCS-03`, `EXAMPLE-02`, `EXAMPLE-03`
- Agent 2 lane: `PANIC-*`, `RECONF-*`, `CI-*`, `KERN-*`, `EXAMPLE-01`, `DOCS-02`, `DOCS-04`

If overlap is discovered:
1. Append `RELEASE`
2. Append `BLOCKED` with exact conflicting file/module
3. Re-claim a ready task in your lane

---

## Task Registry (immutable)

Columns:
- `Task ID`: immutable identifier
- `Sprint`: planned sprint number (1-4)
- `Priority`: P0/P1/P2
- `Difficulty`: Low / Low-Medium / Medium / Medium-High / High
- `Impact`: Low / Medium / Medium-High / High / Very High
- `Parallel`: `Y`, `N`, or `Partial`
- `Depends On`: task IDs that must be done first

| Task ID | Initiative | Deliverable | Sprint | Priority | Difficulty | Impact | Parallel | Depends On |
|---|---|---|---:|---|---|---|---|---|
| PANIC-01 | Engine hardening | Inventory all panic/unwrap/expect in `tarsier-engine` non-test code and publish module-level remediation plan | 1 | P0 | Medium | Very High | Y | - |
| PANIC-02 | Engine hardening | Replace panic paths in analysis/lowering surfaces with typed `Result` errors and CLI diagnostics | 1 | P0 | Medium | High | Partial | PANIC-01 |
| PANIC-03 | Engine hardening | Replace panic paths in verification/proof paths with typed `Result` errors and stable error messages | 1 | P0 | Medium-High | Very High | Partial | PANIC-01 |
| PANIC-04 | Engine hardening | Remove remaining production panic/unwrap/expect usage in engine helpers and reporting paths | 2 | P0 | Medium | High | Partial | PANIC-02, PANIC-03 |
| PANIC-05 | Engine hardening | Add CI guardrails for panic/unwrap bans in non-test engine code with allowlist only for tests | 2 | P0 | Low-Medium | High | Y | PANIC-04 |
| INTEG-01 | Real-node conformance | Add reproducible CometBFT live test harness (containerized bootstrap + deterministic config) | 1 | P0 | Medium-High | High | Partial | - |
| INTEG-02 | Real-node conformance | Add reproducible etcd-raft live test harness (containerized bootstrap + deterministic config) | 1 | P0 | Medium-High | High | Partial | - |
| INTEG-03 | Real-node conformance | End-to-end conformance-active test against live CometBFT node(s) with trace assertions | 2 | P0 | Medium | Very High | Partial | INTEG-01 |
| INTEG-04 | Real-node conformance | End-to-end conformance-active test against live etcd-raft node(s) with trace assertions | 2 | P0 | Medium | Very High | Partial | INTEG-02 |
| INTEG-05 | Real-node conformance | CI integration job for live-adapter tests (PR smoke + nightly full) with failure triage output | 2 | P1 | Medium | High | Partial | INTEG-03, INTEG-04 |
| RECONF-01 | Reconfiguration closure | Audit DSL->IR->SMT epoch semantics and produce concrete gap report with reproducer cases | 1 | P0 | Medium | High | Y | - |
| RECONF-02 | Reconfiguration closure | Implement missing epoch transition constraints and parameter consistency checks identified by audit | 2 | P0 | Medium-High | High | Partial | RECONF-01 |
| RECONF-03 | Reconfiguration closure | Add multi-epoch regression corpus and solver-parity tests for reconfigure transitions | 2 | P0 | Medium | High | Partial | RECONF-02 |
| CODEGEN-01 | Codegen semantic validation | Build model-vs-generated trace oracle harness reusable by Rust and Go generated outputs | 1 | P1 | Medium | High | Y | - |
| CODEGEN-02 | Codegen semantic validation | Add semantic validation tests for generated Rust outputs against model traces | 2 | P1 | Medium | High | Partial | CODEGEN-01 |
| CODEGEN-03 | Codegen semantic validation | Add semantic validation tests for generated Go outputs against model traces | 2 | P1 | Medium | High | Partial | CODEGEN-01 |
| CODEGEN-04 | Codegen semantic validation | Add CI gate for codegen semantic parity suite with deterministic fixtures | 3 | P1 | Medium | Medium-High | Partial | CODEGEN-02, CODEGEN-03 |
| EXAMPLE-01 | Example coverage | Produce feature-coverage matrix for DAG/clocks/reconfig/bounded collections and identify missing safe/unsafe pairs | 1 | P1 | Low-Medium | Medium | Y | - |
| EXAMPLE-02 | Example coverage | Add missing `.trs` examples from coverage matrix and expected-verdict metadata | 2 | P1 | Medium | Medium-High | Partial | EXAMPLE-01 |
| EXAMPLE-03 | Example coverage | Add fast regression runner over example matrix in CI and local script | 2 | P1 | Medium | Medium | Partial | EXAMPLE-02 |
| DOCS-01 | Docs hardening | Multi-solver operations guide (Z3/cvc5/ByMC) including troubleshooting and env setup | 2 | P1 | Low-Medium | Medium | Y | - |
| DOCS-02 | Docs hardening | Proof-kernel extension guide (certificate schema, checker contracts, invariants) | 2 | P1 | Medium | Medium | Y | - |
| DOCS-03 | Docs hardening | Invariant inference debugging playbook (CTI triage, template tuning, solver diagnostics) | 2 | P1 | Low-Medium | Medium | Y | - |
| DOCS-04 | Docs hardening | Documentation link audit + CLI help cross-link updates | 3 | P2 | Low | Medium | Y | DOCS-01, DOCS-02, DOCS-03 |
| CI-01 | CI enforcement | Make mutation testing enforceable in PRs (targeted scope) and keep nightly full campaign | 3 | P1 | Medium-High | High | Partial | - |
| CI-02 | CI enforcement | Make ByMC parity enforceable in PRs (targeted corpus) and keep nightly full parity run | 3 | P1 | Medium-High | High | Partial | - |
| CI-03 | CI enforcement | Align branch-protection expectations and CI docs for required checks | 3 | P1 | Low-Medium | Medium | Y | CI-01, CI-02 |
| PLAY-01 | Playground deployability | Add Docker Compose deployment template for playground and required services | 3 | P2 | Medium | Medium-High | Y | - |
| PLAY-02 | Playground deployability | Add local/hosted deployment guide with environment contract and operational notes | 3 | P2 | Low-Medium | Medium | Y | PLAY-01 |
| PLAY-03 | Playground deployability | Add playground compose smoke-check script and CI/manual verification path | 4 | P2 | Medium | Medium | Partial | PLAY-01 |
| KERN-01 | Kernel formalization | Author formalization RFC for checker semantics, threat model, and theorem milestones | 3 | P2 | Medium-High | Medium | Y | - |
| KERN-02 | Kernel formalization | Export/checker semantics artifact suitable for Lean/Coq prototype ingestion | 4 | P2 | High | Medium | Partial | KERN-01 |
| KERN-03 | Kernel formalization | Lean prototype proving one minimal checker soundness theorem over exported semantics | 4 | P2 | High | Medium | Partial | KERN-02 |
| KERN-04 | Kernel formalization | Coq prototype parity for minimal theorem and proof-check script | 4 | P2 | High | Medium | Partial | KERN-02 |

---

## Suggested Parallel Workstreams

- Stream A (Agent 1, immediate): `INTEG-01`, `INTEG-02`, `CODEGEN-01`
- Stream B (Agent 2, immediate): `PANIC-01`, `RECONF-01`, `EXAMPLE-01`
- Stream C (after sprint-1 audits): `INTEG-03/04`, `PANIC-02/03`, `RECONF-02`
- Stream D (stabilization): `CI-01/02`, `CODEGEN-04`, `DOCS-*`, `PLAY-*`

Highest-priority dependency edges:
- `PANIC-01 -> PANIC-02/PANIC-03 -> PANIC-04 -> PANIC-05`
- `INTEG-01 -> INTEG-03`, `INTEG-02 -> INTEG-04`, then `INTEG-05`
- `RECONF-01 -> RECONF-02 -> RECONF-03`
- `CODEGEN-01 -> CODEGEN-02/CODEGEN-03 -> CODEGEN-04`

---

## Agent Claims (append-only)

(append new lines below)

`2026-03-10T00:00:00Z | system | INIT | CLAIM | Phase-3 board created`
`2026-03-10T18:53:25Z | AGENT_2 | PANIC-01 | CLAIM | taking task`
`2026-03-10T18:53:50Z | AGENT_1 | INTEG-01 | CLAIM | taking task`
`2026-03-10T19:18:51Z | AGENT_1 | INTEG-02 | CLAIM | taking task`
`2026-03-10T19:22:13Z | AGENT_1 | DOCS-03 | CLAIM | taking task`

---

## Progress Events (append-only)

(append new lines below)

`2026-03-10T00:00:00Z | system | INIT | CHANGE | Initial phase-3 task registry published`
`2026-03-10T18:53:25Z | AGENT_2 | PANIC-01 | START | implementation started`
`2026-03-10T18:53:50Z | AGENT_1 | INTEG-01 | START | implementation started`
`2026-03-10T19:02:42Z | AGENT_1 | INTEG-01 | PR_OPEN | branch=codex/agent1-integ-01-v1 pr=local summary=deterministic CometBFT docker-compose harness + bootstrap + config validator + docs`
`2026-03-10T19:02:42Z | AGENT_1 | INTEG-01 | DONE | commit=5573943 tests=python3 scripts/check-cometbft-live-config.py; bash -n scripts/cometbft-live-harness.sh; bash -n integration/cometbft-live/bootstrap/bootstrap.sh; docker compose -f integration/cometbft-live/docker-compose.yml config >/tmp/cometbft_live_compose.out; ./scripts/cometbft-live-harness.sh endpoint` 
`2026-03-10T19:03:21Z | AGENT_1 | INTEG-01 | CHANGE | pr_url=https://github.com/yaksetig/tarsier/pull/new/codex/agent1-integ-01-v1` 
`2026-03-10T19:18:51Z | AGENT_1 | INTEG-02 | START | implementation started`
`2026-03-10T19:21:08Z | AGENT_1 | INTEG-02 | PR_OPEN | branch=codex/agent1-integ-02-v1 pr=https://github.com/yaksetig/tarsier/pull/new/codex/agent1-integ-02-v1 summary=deterministic etcd-raft docker-compose harness + config validator + docs`
`2026-03-10T19:21:08Z | AGENT_1 | INTEG-02 | DONE | commit=f767aa2 tests=python3 scripts/check-etcd-raft-live-config.py; bash -n scripts/etcd-raft-live-harness.sh; docker compose -f integration/etcd-raft-live/docker-compose.yml config >/tmp/etcd_raft_live_compose.out; ./scripts/etcd-raft-live-harness.sh endpoint` 
`2026-03-10T19:22:13Z | AGENT_1 | DOCS-03 | START | implementation started`
`2026-03-10T19:26:59Z | AGENT_1 | DOCS-03 | PR_OPEN | branch=codex/agent1-docs-03-v1 pr=https://github.com/yaksetig/tarsier/pull/new/codex/agent1-docs-03-v1 summary=invariant inference debugging playbook + command cross-links`
`2026-03-10T19:26:59Z | AGENT_1 | DOCS-03 | DONE | commit=8aeaea5 tests=cargo run -q -p tarsier-cli -- infer-invariants examples/library/reliable_broadcast_safe.trs --depth 4 --timeout 30 --format json > /tmp/docs03_infer.json; python3 -c \"import json; d=json.load(open('/tmp/docs03_infer.json')); assert d['schema_version']==1 and 'result' in d and 'inductive' in d and 'init_only' in d\"; cargo run -q -p tarsier-cli -- prove examples/library/reliable_broadcast_safe.trs --k 4 --engine kinduction --auto-strengthen --format json > /tmp/docs03_prove_auto.json; python3 -c \"import json; d=json.load(open('/tmp/docs03_prove_auto.json')); assert d.get('auto_strengthen') is True and d.get('mode')=='prove' and 'result' in d and 'details' in d\"` 

---

## Dependency Notes (read-only)
- Reconfiguration may already be partially complete; `RECONF-01` explicitly validates and scopes only residual work.
- Example coverage may already exist for parts of DAG/clock/reconfigure/bounded features; `EXAMPLE-01` should prevent duplicate churn.
- CI gating tasks (`CI-01`, `CI-02`) must include runtime budget controls to avoid excessive PR cycle times.
- Keep backward compatibility for existing `.trs` protocols and existing JSON report schemas.
`2026-03-10T19:34:45Z | AGENT_1 | PLAY-01 | CLAIM | taking task`
`2026-03-10T19:34:45Z | AGENT_1 | PLAY-01 | START | implementation started`
`2026-03-10T19:37:26Z | AGENT_1 | PLAY-01 | PR_OPEN | branch=codex/agent1-play-docs-v1 pr=local summary=playground docker-compose template with optional proxy profile`
`2026-03-10T19:37:26Z | AGENT_1 | PLAY-01 | DONE | commit=ebe5d4b tests=cp playground/deploy/.env.example playground/deploy/.env; docker compose -f playground/deploy/docker-compose.yml config; docker compose -f playground/deploy/docker-compose.yml --profile proxy config`
`2026-03-10T19:37:26Z | AGENT_1 | PLAY-02 | CLAIM | taking task`
`2026-03-10T19:37:26Z | AGENT_1 | PLAY-02 | START | implementation started`
`2026-03-10T19:38:30Z | AGENT_1 | PLAY-02 | PR_OPEN | branch=codex/agent1-play-docs-v1 pr=local summary=local/hosted playground deployment guide with env contract and ops notes`
`2026-03-10T19:38:30Z | AGENT_1 | PLAY-02 | DONE | commit=217857f tests=python3 - <<'PY'\nfrom pathlib import Path\ntext = Path('docs/PLAYGROUND_DEPLOYMENT.md').read_text(encoding='utf-8')\nassert 'TARSIER_AUTH_TOKEN' in text and 'TARSIER_ALLOWED_ORIGINS' in text\nassert 'docker compose -f playground/deploy/docker-compose.yml up -d --build' in text\nprint('ok')\nPY; rg -n "PLAYGROUND_DEPLOYMENT|playground/deploy" playground/README.md docs/PLAYGROUND_DEPLOYMENT.md`
`2026-03-10T19:38:30Z | AGENT_1 | DOCS-01 | CLAIM | taking task`
`2026-03-10T19:38:30Z | AGENT_1 | DOCS-01 | START | implementation started`
`2026-03-10T19:40:03Z | AGENT_1 | DOCS-01 | PR_OPEN | branch=codex/agent1-play-docs-v1 pr=local summary=multi-solver operations guide for Z3/cvc5/ByMC with setup + troubleshooting`
`2026-03-10T19:40:03Z | AGENT_1 | DOCS-01 | DONE | commit=706d891 tests=python3 - <<'PY'\nfrom pathlib import Path\ntext = Path('docs/MULTI_SOLVER_OPERATIONS.md').read_text(encoding='utf-8')\nfor key in ['Z3', 'cvc5', 'ByMC', 'install_solvers.sh', 'benchmarks/bymc/run_bymc.sh']:\n    assert key in text\nprint('ok')\nPY; rg -n "MULTI_SOLVER_OPERATIONS" docs/ADVANCED_USAGE.md docs/GETTING_STARTED.md docs/MULTI_SOLVER_OPERATIONS.md`
`2026-03-10T19:40:53Z | AGENT_1 | DOCS-01 | CHANGE | pr_url=https://github.com/yaksetig/tarsier/pull/new/codex/agent1-play-docs-v1`
`2026-03-10T19:52:45Z | AGENT_1 | CODEGEN-01 | CLAIM | taking task`
`2026-03-10T19:52:45Z | AGENT_1 | CODEGEN-01 | START | implementation started`
`2026-03-10T19:53:32Z | AGENT_1 | CODEGEN-01 | PR_OPEN | branch=codex/agent1-codegen-01-v1 pr=local summary=add shared model-vs-generated trace oracle harness with reusable Rust/Go validation APIs and tests`
`2026-03-10T19:53:52Z | AGENT_1 | CODEGEN-01 | DONE | commit=5624846 tests=cargo test -p tarsier-codegen trace_oracle; cargo clippy -p tarsier-codegen --all-targets -- -D warnings`
`2026-03-10T19:55:17Z | AGENT_1 | PLAY-03 | CLAIM | taking task`
`2026-03-10T19:55:17Z | AGENT_1 | PLAY-03 | START | implementation started`
`2026-03-10T19:57:56Z | AGENT_1 | PLAY-03 | PR_OPEN | branch=codex/agent1-play-03-v1 pr=local summary=add playground compose smoke script, CI config check step, and manual verification docs`
`2026-03-10T19:58:30Z | AGENT_1 | PLAY-03 | DONE | commit=c2bfb44 tests=bash -n scripts/playground-compose-smoke.sh; ./scripts/playground-compose-smoke.sh endpoint; rc=0; ./scripts/playground-compose-smoke.sh config >/tmp/playground_compose_config.out 2>/tmp/playground_compose_config.err || rc=0; test "" -eq 2; rg -n "docker daemon is not running" /tmp/playground_compose_config.err; rg -n "playground-compose-smoke\.sh|Playground Compose Smoke" .github/workflows/ci.yml docs/PLAYGROUND_DEPLOYMENT.md playground/deploy/README.md playground/README.md`
`2026-03-10T19:58:39Z | AGENT_1 | PLAY-03 | CHANGE | corrected_tests=bash -n scripts/playground-compose-smoke.sh; ./scripts/playground-compose-smoke.sh endpoint; rc=0; ./scripts/playground-compose-smoke.sh config >/tmp/playground_compose_config.out 2>/tmp/playground_compose_config.err || rc=$?; test "$rc" -eq 2; rg -n "docker daemon is not running" /tmp/playground_compose_config.err; rg -n "playground-compose-smoke\.sh|Playground Compose Smoke" .github/workflows/ci.yml docs/PLAYGROUND_DEPLOYMENT.md playground/deploy/README.md playground/README.md`
`2026-03-10T20:00:42Z | AGENT_1 | CODEGEN-02 | CLAIM | taking task`
`2026-03-10T20:00:42Z | AGENT_1 | CODEGEN-02 | START | implementation started`
`2026-03-10T20:01:31Z | AGENT_1 | CODEGEN-02 | PR_OPEN | branch=codex/agent1-codegen-02-v1 pr=local summary=add Rust semantic validation suite using model-vs-generated trace oracle`
`2026-03-10T20:01:31Z | AGENT_1 | CODEGEN-02 | DONE | commit=pending tests=cargo test -p tarsier-codegen --test semantic_rust; cargo test -p tarsier-codegen trace_oracle; cargo clippy -p tarsier-codegen --test semantic_rust -- -D warnings`
`2026-03-10T20:01:46Z | AGENT_1 | CODEGEN-02 | CHANGE | done_commit=f8537c3`
`2026-03-10T20:02:21Z | AGENT_1 | CODEGEN-03 | CLAIM | taking task`
`2026-03-10T20:02:21Z | AGENT_1 | CODEGEN-03 | START | implementation started`
`2026-03-10T20:03:04Z | AGENT_1 | CODEGEN-03 | PR_OPEN | branch=codex/agent1-codegen-03-v1 pr=local summary=add Go semantic validation suite using model-vs-generated trace oracle`
`2026-03-10T20:03:04Z | AGENT_1 | CODEGEN-03 | DONE | commit=pending tests=cargo test -p tarsier-codegen --test semantic_go; cargo test -p tarsier-codegen trace_oracle; cargo clippy -p tarsier-codegen --test semantic_go -- -D warnings`
`2026-03-10T20:03:11Z | AGENT_1 | CODEGEN-03 | CHANGE | done_commit=15c3f6c`
`2026-03-10T20:04:40Z | AGENT_1 | CODEGEN-04 | CLAIM | taking task`
`2026-03-10T20:04:40Z | AGENT_1 | CODEGEN-04 | START | implementation started`
`2026-03-10T20:06:37Z | AGENT_1 | CODEGEN-04 | PR_OPEN | branch=codex/agent1-codegen-04-v1 pr=local summary=add CI codegen semantic parity gate and deterministic parity script`
`2026-03-10T20:06:37Z | AGENT_1 | CODEGEN-04 | DONE | commit=pending tests=./scripts/codegen-semantic-parity.sh`
`2026-03-10T20:06:47Z | AGENT_1 | CODEGEN-04 | CHANGE | done_commit=a14d552`
