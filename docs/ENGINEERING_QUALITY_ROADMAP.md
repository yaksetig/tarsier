# Engineering Quality Roadmap

This document turns the "how do we get this repo from strong to excellent?"
question into a concrete execution backlog.

The goal is to move the repository from "feature-rich and ambitious" to
"boringly reliable, easy to change, and explicit about trust and stability."

## Target State

We should consider this roadmap substantially complete when all of the
following are true:

- `main` stays green on `cargo fmt --all -- --check`, `cargo test --workspace --all-targets`, and core CI gates without cleanup follow-up PRs.
- Public Rust API rustdoc coverage is `>= 90%` and enforced in CI.
- Large responsibility-heavy modules have been decomposed so the biggest
  production files are no longer concentrated in a handful of command and
  orchestration entrypoints.
- Example-library and manifest drift are prevented mechanically rather than
  detected late.
- Solver and proof-checker trust assumptions are narrowed and enforced where
  possible, especially around sandboxing and replay independence.
- The supported public surface is intentionally curated and documented.

## Working Rules

These rules exist to stop cleanup work from turning into open-ended drift:

1. One task, one PR. Avoid "while I am here" refactors unless they are
   required for the acceptance criteria.
2. Every task must end with an artifact: code, docs, test, script, CI gate, or
   metric.
3. Do not mix semantic changes with mass formatting unless the formatter is the
   explicit purpose of the PR.
4. If a task changes examples, schemas, manifests, or generated artifacts, it
   must also add or update the mechanism that prevents future drift.
5. Close tasks only with evidence: command output, CI job, or file reference.

## Start Here

Do these first. They reduce the most risk per hour and make the later work
less error-prone.

- [x] `EQ-01` Split `analyze` into focused modules.
- [x] `EQ-02` Split `verify` into focused modules.
- [x] `EQ-03` Add a fast generated-artifact drift gate for examples/manifests/schemas.
- [x] `EQ-04` Raise public API rustdoc coverage gate from `60%` to `80%`.
- [x] `EQ-05` Add maintainability size guards for oversized production files.
- [x] `EQ-06` Publish a crate-by-crate supported API matrix.

## Milestone 1: Maintainability and Change Safety

### EQ-01

- Priority: `P0`
- Title: Split CLI analyze pipeline into focused modules
- Targets:
  - `crates/tarsier-cli/src/commands/analyze.rs`
- Deliverable:
  - Separate modules for profile selection, execution planning, layer report
    shaping, and UX rendering.
- Acceptance:
  - No resulting module over roughly `1000` LOC.
  - Existing analyze tests remain green.
  - New unit tests cover interpretation/report helpers without requiring a full
    end-to-end run.

### EQ-02

- Priority: `P0`
- Title: Split CLI verify command into bounded-check, portfolio, and reporting layers
- Targets:
  - `crates/tarsier-cli/src/commands/verify.rs`
- Deliverable:
  - Separate modules for bounded execution, portfolio merge policy, trace
    formatting, and output serialization.
- Acceptance:
  - Merge behavior and trace selection logic are testable without exercising the
    full CLI.
  - Existing verify tests remain green.

### EQ-03

- Priority: `P1`
- Title: Add a fast generated-artifact drift gate
- Targets:
  - `examples/library/cert_suite.json`
  - schema docs under `docs/`
  - drift-check scripts and CI
- Deliverable:
  - One CI step dedicated to drift detection for manifests, schemas, and
    generated artifacts.
- Acceptance:
  - Adding a new library `.trs` file without manifest coverage fails in a fast,
    narrow job.
  - Regenerating artifacts locally is documented and reproducible.

### EQ-04

- Priority: `P1`
- Title: Raise public API rustdoc coverage to 80%
- Targets:
  - `scripts/check_public_api_doc_coverage.py`
  - low-coverage public modules
- Deliverable:
  - Coverage threshold raised from `60%` to `80%`.
- Acceptance:
  - CI passes with the higher threshold.
  - Coverage output shows progress concentrated in previously weak crates.

### EQ-05

- Priority: `P1`
- Title: Add maintainability guards for oversized production files and functions
- Targets:
  - new script under `scripts/`
  - `.github/workflows/ci.yml`
- Deliverable:
  - CI script that flags oversize production files/functions, with a small
    allowlist if needed.
- Acceptance:
  - New PRs cannot introduce another multi-thousand-line production module
    without explicit review.

### EQ-06

- Priority: `P1`
- Title: Publish a supported public API matrix per crate
- Targets:
  - `docs/API_STABILITY.md`
- Deliverable:
  - A table naming stable, provisional, and internal surfaces for each crate.
- Acceptance:
  - A downstream user can tell which APIs are intended for reuse and which are
    implementation details.

### EQ-07

- Priority: `P1`
- Title: Split engine verification orchestration into planner and executor layers
- Targets:
  - `crates/tarsier-engine/src/pipeline/verification/orchestration.rs`
- Deliverable:
  - Separate modules for stage planning, solver dispatch, result normalization,
    and diagnostics.
- Acceptance:
  - Stage-level tests can run without driving the entire pipeline stack.

### EQ-08

- Priority: `P1`
- Title: Decompose playground server into routes, state, and request-validation modules
- Targets:
  - `playground/src/main.rs`
- Deliverable:
  - Smaller route/state files and a thin `main.rs`.
- Acceptance:
  - Request-validation and route tests can be run independently.

## Milestone 2: Documentation and Public Surface Quality

### EQ-09

- Priority: `P1`
- Title: Add public entrypoint docs for core library crates
- Targets:
  - `crates/tarsier-ir/src/lib.rs`
  - `crates/tarsier-smt/src/lib.rs`
  - `crates/tarsier-engine/src/lib.rs`
  - `crates/tarsier-conformance/src/lib.rs`
  - `crates/tarsier-dsl/src/lib.rs`
  - `crates/tarsier-prob/src/lib.rs`
- Deliverable:
  - Module-level rustdoc describing purpose, guarantees, trust assumptions, and
    intended callers.
- Acceptance:
  - Public API rustdoc coverage increases meaningfully in the worst files listed
    by the coverage script.

### EQ-10

- Priority: `P1`
- Title: Add rustdoc examples for the five main workflows
- Targets:
  - parser/lowering
  - bounded verify
  - unbounded prove
  - conformance replay/check
  - certificate replay
- Deliverable:
  - Runnable or `no_run` examples in public docs.
- Acceptance:
  - Examples compile under `cargo doc` and show realistic usage rather than toy
    signatures only.

### EQ-11

- Priority: `P1`
- Title: Add command-level soundness and trust summaries
- Targets:
  - `README.md`
  - `docs/TRUST_BOUNDARY.md`
  - command docs where needed
- Deliverable:
  - Short "what this command proves / what it still assumes" references for
    `analyze`, `verify`, `prove`, `conformance-*`, and certificate commands.
- Acceptance:
  - A user can compare command strength without reading the full semantics
    document.

### EQ-12

- Priority: `P2`
- Title: Reduce exposed Rust API surface by converting internal `pub` to `pub(crate)`
- Targets:
  - public items identified as implementation-only
- Deliverable:
  - Narrower supported surface and smaller documentation burden.
- Acceptance:
  - Public item count drops while public API coverage rises.
  - No breakage to intended downstream consumers.

## Milestone 3: Repo Process and Contributor Flow

### EQ-13

- Priority: `P1`
- Title: Add a single local gate command that mirrors branch protection
- Targets:
  - `justfile`
- Deliverable:
  - One command that runs the essential local quality gates in the correct
    order.
- Acceptance:
  - A contributor can run one command and get a high-confidence pre-push result.

### EQ-14

- Priority: `P2`
- Title: Audit ignored tests and classify them explicitly
- Targets:
  - all ignored tests across the workspace
- Deliverable:
  - A short inventory mapping each ignored test to one of: slow, flaky,
    environment-dependent, nightly-only, obsolete.
- Acceptance:
  - No ignored test remains unexplained.
  - Obsolete ignored tests are deleted or re-enabled.

### EQ-15

- Priority: `P2`
- Title: Enforce semantic-only vs formatter-only PR hygiene
- Targets:
  - contribution docs
  - optional CI helper script
- Deliverable:
  - Documented review rule and optional script that flags very broad
    formatting-only churn in semantic PRs.
- Acceptance:
  - Mixed cleanup PRs become the exception rather than the norm.

### EQ-16

- Priority: `P2`
- Title: Make example and manifest maintenance semi-generated
- Targets:
  - `examples/library/`
  - `examples/library/cert_suite.json`
- Deliverable:
  - Script or generator that reduces manual bookkeeping for library coverage and
    hashes.
- Acceptance:
  - Adding a new example requires updating structured metadata in one place
    rather than hand-editing the full manifest.

## Milestone 4: Hardening and Assurance

### EQ-17

- Priority: `P2`
- Title: Enforce real OS-level solver sandboxing where supported
- Targets:
  - `crates/tarsier-engine/src/sandbox.rs`
  - solver launch paths
- Deliverable:
  - Actual network/filesystem/process restrictions around solver subprocesses on
    supported platforms.
- Acceptance:
  - Trust-boundary docs can state enforced isolation instead of design intent
    only.

### EQ-18

- Priority: `P2`
- Title: Strengthen independent replay and differential validation paths
- Targets:
  - certificate replay path
  - differential checker gates
- Deliverable:
  - More checks that do not rely on the same implementation stack as the main
    encoder/orchestrator.
- Acceptance:
  - At least one critical proof path has stronger implementation diversity.

### EQ-19

- Priority: `P3`
- Title: Record and verify solver/proof-checker provenance in developer flows
- Targets:
  - release docs
  - local helper commands
- Deliverable:
  - Reproducible local checks for solver versions and hashes, not just CI
    pinning.
- Acceptance:
  - Developers can reproduce high-assurance verification environments locally.

### EQ-20

- Priority: `P3`
- Title: Ratchet long-term quality bars upward
- Targets:
  - CI thresholds for rustdoc coverage, mutation score, benchmark budgets, and
    maintainability guards
- Deliverable:
  - A schedule for raising quality floors rather than holding them flat.
- Acceptance:
  - Threshold changes move upward by default and require explicit justification
    to lower.

## Recommended Execution Order

If we want the highest leverage sequence, do the work in this order:

1. `EQ-01`
2. `EQ-02`
3. `EQ-03`
4. `EQ-04`
5. `EQ-05`
6. `EQ-06`
7. `EQ-07`
8. `EQ-08`
9. `EQ-09`
10. `EQ-10`
11. `EQ-11`
12. `EQ-13`
13. `EQ-14`
14. `EQ-15`
15. `EQ-16`
16. `EQ-12`
17. `EQ-17`
18. `EQ-18`
19. `EQ-19`
20. `EQ-20`

## Suggested First Sprint

If the goal is to stop circling and start shipping, the first sprint should be:

- [x] `EQ-01` Split `analyze`
- [x] `EQ-02` Split `verify`
- [x] `EQ-03` Add fast drift gate
- [x] `EQ-04` Raise rustdoc coverage gate to `80%`
- [x] `EQ-05` Add maintainability size guard

That sprint gives us structural improvement, prevents fresh drift, and raises
the minimum quality bar immediately.
