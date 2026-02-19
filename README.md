# Tarsier

Tarsier is a bounded model checker for BFT protocol models written in a threshold-automata DSL.
It targets fast safety/liveness bug-finding and parameterized reasoning over `n`, `t`, `f`-style systems.

## What It Supports

- Safety checks (agreement/invariant fragments).
- Bounded liveness checks.
- User-definable liveness targets (`property ...: liveness { ... }`) with `decided=true` fallback.
- Temporal liveness operators (`X`, `[]`, `<>`, `U`, `W`, `R`, `~>`) for bounded `liveness` and unbounded fair-liveness/proof flows.
- Distinct-sender threshold guards (`received distinct >= ...`).
- Automatic pacemaker view increments (optional).
- Multiple fault models (`byzantine`, `omission`, `crash`).
- Configurable Byzantine equivocation profile (`equivocation: full|none`).
- Partial synchrony with explicit GST (`timing: partial_synchrony; gst: ...`).
- Configurable network semantics (`network: classic|identity_selective|cohort_selective|process_selective`).
- Message value abstraction for unbounded fields (`values: sign`).
- First-class cryptographic objects (`certificate`, `threshold_signature`) with `form`/`has`/`lock`/`justify`.
- Committee tail-bound analysis (hypergeometric) with SMT bound injection.
- Sound communication-complexity reporting (role-aware protocol bounds and adversary-aware injection bounds).
- Quantitative finality estimates (success lower bounds, expected rounds, 90%/99% confidence rounds, and message upper-bound projections).
- Unbounded safety proof attempts (`prove` command) with `kinduction` and full IC3/PDR (`pdr`) engines.
- `prove` auto-dispatch: if a model declares only `property ...: liveness`, `prove` runs unbounded fair-liveness proof (weak/strong fairness) instead of safety proof.
- Round/view cutoff evidence generation via bound sweeps (`round-sweep`) for capped-round models.
- Sound round-erasure abstraction proofs for unbounded rounds (`prove-round` command, over-approximation).
- CTI reporting for failed k-induction (`RESULT: NOT PROVED` now includes a human-readable counterexample-to-induction witness when available).
- Bounded fair-liveness counterexample search (`fair-liveness --fairness weak|strong`).
- Unbounded fair-liveness proof attempts (`prove-fair --fairness weak|strong`) with fair-cycle IC3/PDR.
- Round-erasure fair-liveness proofs for unbounded rounds (`prove-fair-round`, over-approximation).
- Safety and fair-liveness proof certificate bundles (`certify-safety`, `certify-fair-liveness`, `check-certificate`).
- Optional raw solver proof-object extraction during certificate checks.
- Deterministic multi-layer analysis modes with machine-readable JSON (`analyze --mode ...`).
- End-to-end timeout budgets (including CEGAR/fair-liveness search loops), not just per-query solver time limits.
- Protocol library corpus under `examples/library/` plus benchmark harness.
- Local web playground with analysis, linting, scaffold assistant (`pbft`/`hotstuff`/`raft`), CTI view, and interactive trace replay.

## Quick Start

```bash
cargo run -p tarsier-cli -- verify examples/pbft_simple.trs --depth 10 --timeout 60
cargo run -p tarsier-cli -- round-sweep examples/pbft_faithful_liveness.trs --depth 8 --min-bound 1 --max-bound 12 --stable-window 3 --format json --out artifacts/pbft-round-sweep.json
cargo run -p tarsier-cli -- verify examples/pbft_simple.trs --depth 10 --timeout 60 --cegar-iters 1
cargo run -p tarsier-cli -- verify examples/pbft_simple.trs --depth 10 --timeout 60 --cegar-iters 3 --cegar-report-out artifacts/pbft-cegar.json
cargo run -p tarsier-cli -- verify examples/pbft_simple.trs --depth 10 --timeout 60 --portfolio
cargo run -p tarsier-cli -- liveness examples/pbft_simple.trs --depth 10 --timeout 60
cargo run -p tarsier-cli -- fair-liveness examples/pbft_simple.trs --depth 10 --fairness weak --timeout 60
cargo run -p tarsier-cli -- prove examples/pbft_simple.trs --k 12 --timeout 120
cargo run -p tarsier-cli -- prove examples/pbft_simple.trs --k 12 --engine pdr --timeout 120
cargo run -p tarsier-cli -- prove examples/trivial_live.trs --k 8 --fairness weak --timeout 120
cargo run -p tarsier-cli -- prove examples/pbft_simple.trs --k 12 --engine pdr --cegar-iters 2
cargo run -p tarsier-cli -- prove examples/pbft_simple.trs --k 12 --engine pdr --cegar-iters 2 --cegar-report-out artifacts/pbft-prove-cegar.json
cargo run -p tarsier-cli -- prove-round examples/pbft_faithful_liveness.trs --k 20 --engine pdr --round-vars view,round,epoch,height
cargo run -p tarsier-cli -- prove examples/pbft_simple.trs --k 12 --portfolio
cargo run -p tarsier-cli -- prove examples/pbft_simple.trs --k 12 --engine pdr --cert-out certs/pbft-pdr
cargo run -p tarsier-cli -- prove-fair examples/pbft_simple.trs --k 0 --fairness strong --timeout 120
cargo run -p tarsier-cli -- prove-fair examples/pbft_simple.trs --k 0 --fairness strong --cegar-iters 2
cargo run -p tarsier-cli -- prove-fair examples/pbft_simple.trs --k 0 --fairness strong --cegar-iters 2 --cegar-report-out artifacts/pbft-prove-fair-cegar.json
cargo run -p tarsier-cli -- prove-fair-round examples/pbft_faithful_liveness.trs --k 20 --fairness strong --round-vars view,round,epoch,height
cargo run -p tarsier-cli -- prove-fair examples/trivial_live.trs --k 8 --fairness weak --cert-out certs/live-weak
cargo run -p tarsier-cli -- certify-safety examples/pbft_simple.trs --k 12 --engine kinduction --out certs/pbft
cargo run -p tarsier-cli -- certify-safety examples/pbft_simple.trs --k 12 --engine pdr --out certs/pbft-pdr
cargo run -p tarsier-cli -- certify-fair-liveness examples/trivial_live.trs --k 8 --fairness weak --out certs/live-weak
cargo run -p tarsier-cli -- check-certificate certs/pbft --solvers z3,cvc5
cargo run -p tarsier-cli -- check-certificate certs/pbft --solvers z3,cvc5 --rederive
cargo run -p tarsier-cli -- check-certificate certs/pbft --solvers z3,cvc5 --emit-proofs certs/pbft/proofs --require-proofs
cargo run -p tarsier-cli -- check-certificate certs/pbft --solvers z3,cvc5 --trusted-check --min-solvers 2 --rederive --emit-proofs certs/pbft/proofs --proof-checker ./scripts/check-proof.sh
cargo run -p tarsier-cli -- analyze examples/pbft_simple.trs --mode standard --format json
cargo run -p tarsier-cli -- visualize examples/reliable_broadcast_buggy.trs --check verify --format markdown --out artifacts/rb-cex.md
cargo run -p tarsier-cli -- debug-cex examples/reliable_broadcast_buggy.trs --check verify --depth 8
cargo run -p tarsier-cli -- lint examples/pbft_simple.trs --soundness strict
cargo run -p tarsier-cli -- assist --kind hotstuff --out examples/hotstuff_skeleton.trs
cargo run -p tarsier-cli -- cert-suite --manifest examples/library/cert_suite.json --engine kinduction --k 8 --format text
cargo run -p tarsier-cli -- show-ta examples/pbft_simple.trs
cargo run -p tarsier-cli -- comm examples/pbft_simple.trs --depth 10
python3 benchmarks/run_library_bench.py --mode standard
cargo run -p tarsier-playground
```

Then open [http://127.0.0.1:7878](http://127.0.0.1:7878). You can override bind settings with `TARSIER_PLAYGROUND_HOST` and `TARSIER_PLAYGROUND_PORT`.

## DSL Highlights

- Parameter shorthand:

```trs
params n, t, f;
```

- Resilience shorthand:

```trs
resilience: n = 3*f + 1;
```

- Fault/timing/value configuration:

```trs
adversary {
    model: byzantine;           // byzantine | omission | crash
    bound: f;                   // fault/drop bound parameter
    equivocation: full;         // full | none (Byzantine only)
    auth: signed;               // none | signed
    network: process_selective; // classic | identity_selective | cohort_selective | process_selective
    delivery: per_recipient;    // legacy_counter | per_recipient | global
    faults: per_recipient;      // legacy_counter | per_recipient | global
    timing: partial_synchrony;  // asynchronous | partial_synchrony
    gst: gst;                   // required for partial_synchrony
    values: sign;               // exact | sign
}
```

Semantics:
- `omission`: environment may drop in-flight messages up to `bound` per step (drops forced to `0` after GST in partial synchrony).
- `crash`: processes can crash-stop (become permanently non-sending) with cumulative crash count bounded by `bound`.
- `byzantine` + `equivocation: full` (default): adversary may inject conflicting message variants.
- `byzantine` + `equivocation: none`: adversary is restricted to one injected variant per `(message type, recipient)` per step.
- `auth: signed`: sender-authenticated modeling that tracks per-sender one-send flags for sent message counters.
  With `auth: signed`, Byzantine injections are identity-capped per `(message family, recipient)` per step.
  Distinct-sender threshold guards (`received distinct >= ...`) should use `auth: signed` in strict mode.
- `network: identity_selective`: ties Byzantine variant sender budgets across recipients and enables selective per-recipient delivery on Byzantine channels.
- `network: cohort_selective`: adds internal per-role delivery cohorts (`#0/#1` channels) so same-role processes can observe different Byzantine deliveries (approximate, still cohort-based).
- `network: process_selective`: uses concrete bounded process identifiers (`pid`) for recipient-scoped channels (`Role#pid`) with uniqueness constraints (`<= 1` process per `(role,pid)` bucket), enabling true per-process selective delivery in finite instances.
  Defaults to `pid` but can be overridden with explicit identity declarations.
- `delivery`: controls recipient coupling for delivery/injection behavior in selective-network modes.
  `per_recipient` keeps selective behavior; `global` enforces recipient-coupled delivery; `legacy_counter` preserves old counter behavior.
- `faults`: controls how adversary/drop budgets are aggregated.
  `legacy_counter` keeps per-counter bounds; `per_recipient` aggregates per recipient channel; `global` aggregates across all recipients.

- Explicit role/process identities and key namespaces:

```trs
identity Replica: process(node_id) key replica_key;
identity Client: role key client_key;
```

- Per-message channel authentication and equivocation overrides:

```trs
channel Vote: authenticated; // authenticated | unauthenticated
equivocation Vote: none;     // full | none
```

These declarations are message-class overrides on top of the global adversary defaults.
For `network: process_selective`, each role must use a process-scoped identity variable
with a bounded nat/int domain (e.g., `var node_id: nat in 0..3;`), no explicit init, immutable.

- Bounded local integer variables:

```trs
var view: int in 0..5 = 0;
```

- Bounded integer/nat message fields:

```trs
message Vote(view: int in 0..5, round: nat in 0..10);
```

- Recipient-scoped send actions (or broadcast when omitted):

```trs
send Vote(view=view) to Replica;
send Vote(view=view); // broadcast to all roles
```

- Distinct sender thresholds:

```trs
when received distinct >= 2*t+1 Vote(view=view) => { ... }
```

- Cryptographic objects (QC / threshold signature):

```trs
certificate PrepareQC from Prepare threshold 2*t+1 signer Replica;
threshold_signature CommitSig from Commit threshold 2*t+1 signer Replica;
```

- Crypto object guards/actions:

```trs
when has PrepareQC(view=view) => { ... }
form PrepareQC(view=view);
lock PrepareQC(view=view);
justify PrepareQC(view=view);
```

- OR guards are supported and lowered to disjunctive rule sets:

```trs
when received >= 1 A || received >= 1 B => { ... }
```

- `decide v;` semantics:
  - maps to `decision = v` when `decision` exists,
  - maps to `decided = true` when `decided: bool` exists.

- Optional liveness property (used by `liveness`, `fair-liveness`, `prove-fair`):

```trs
property term: liveness {
    forall p: Replica. p.decided == true
}
```

If omitted, liveness falls back to locations with `decided == true`.

Temporal liveness operators are supported by bounded `liveness`, `fair-liveness`, and `prove-fair`:

```trs
property live: liveness {
    forall p: Replica. [] (p.safe == true)
}
property next_example: liveness {
    forall p: Replica. X (p.safe == true)
}
property progress: liveness {
    forall p: Replica. (p.locked == true) ~> <> (p.decided == true)
}
property until_example: liveness {
    forall p: Replica. (p.phase == precommit) U (p.phase == commit)
}
property weak_until_example: liveness {
    forall p: Replica. (p.locked == true) W (p.decided == true)
}
property release_example: liveness {
    forall p: Replica. (p.decided == true) R (p.safe == true)
}
```

## Development

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

CI now also runs safety and fair-liveness certificate generation/checking with pinned solver binaries:
- Z3 `4.12.5`
- cvc5 `1.1.2`
- Optional proof-object validation path (`tarsier-certcheck --proof-checker .github/scripts/check_proof_object.py`) on CI-supported solvers.
- Proof-mode merge gate: CI runs `analyze --mode proof` and then requires `tarsier-certcheck` to independently validate produced proof bundles (two solvers + proof-object checker) before downstream jobs continue.

## Analysis Modes

Use `analyze` for deterministic CI/governance pipelines:

```bash
# Fast bug scan
cargo run -p tarsier-cli -- analyze examples/pbft_simple.trs --mode quick

# Bounded safety/liveness/fair-liveness + comm report
cargo run -p tarsier-cli -- analyze examples/pbft_simple.trs --mode standard

# Standard + unbounded safety and fair-liveness proofs
cargo run -p tarsier-cli -- analyze examples/pbft_simple.trs --mode proof --fairness weak

# Proof + cross-solver checks, write JSON artifact
cargo run -p tarsier-cli -- analyze examples/pbft_simple.trs --mode audit --format json --report-out report.json

# Run solver-sensitive layers in portfolio mode (Z3 + cvc5)
cargo run -p tarsier-cli -- analyze examples/pbft_simple.trs --mode proof --portfolio --format json
```

`analyze` exits with code `0` on overall pass and `2` otherwise.

JSON reports now include per-layer profiling diagnostics under
`layers[*].details.abstractions`:
- `phase_profiles`: parse/lower/check/encode/solve timings (`elapsed_ms`) plus `rss_bytes`
  (Linux current RSS; other platforms may report `null`).
- `smt_profiles`: SMT encode/solve call counts and elapsed time, plus
  assertion dedup metrics (`assertion_candidates`, `assertion_unique`,
  `assertion_dedup_hits`, `assertion_dedup_rate`), incremental-depth reuse
  metrics (`incremental_depth_reuse_steps`, reuse-hit counters), and symmetry
  pruning metrics (`symmetry_candidates`, `symmetry_pruned`, `symmetry_prune_rate`),
  including stutter-signature collapse counts (`stutter_signature_normalizations`),
  with explicit enablement flags (`symmetry_enabled`, `incremental_enabled`).
- `lowerings[*]` now includes partial-order/fallback visibility:
  `independent_rule_pairs`, `por_enabled`, `fallback_applied`, `fallback_steps`,
  `fallback_exhausted`, `network_fallback_state`, plus transition-pruning stats
  (`por_stutter_rules_pruned`, `por_commutative_duplicate_rules_pruned`,
  `por_effective_rule_count`).
- POR now performs exact transition pruning in the SMT relation:
  pure stutter rules and commutative duplicate rules are disabled (`delta=0`)
  with no reachability loss for safety/liveness traces under the counter semantics.

Quick tuning guidance by mode:
- `quick`: low depth, fast bug-finding; use for every PR.
- `standard`: bounded safety/liveness checks for routine correctness gates.
- `proof`: add unbounded proof layers; increase `--k` only when needed.
- `audit`: cross-solver/portfolio governance runs; expect highest runtime.

Concrete scale guardrails:
- `quick`:
  - Start with `--depth 4..8`, `--timeout 60..120`.
  - Keep faithful fallback at `identity` or `classic` with budgets near:
    `--fallback-max-locations 6000 --fallback-max-shared-vars 30000 --fallback-max-message-counters 20000`.
- `standard`:
  - Start with `--depth 8..12`, `--timeout 120..240`.
  - Keep `--soundness strict`; only widen fallback budgets if diagnostics show frequent exhaustion.
- `proof`:
  - Start with `--k 12..20`, `--timeout 300+`, `--engine pdr` for harder models.
  - Use `--portfolio` for solver-sensitive runs.
- `audit`:
  - Use `--portfolio --format json --report-out ...` and archive full artifacts.
  - Expect highest runtime and memory.

CI perf regression gate (library smoke benchmark):

```bash
python3 benchmarks/run_library_bench.py --mode quick --depth 4 --timeout 90 \
  --samples 3 \
  --perf-budget benchmarks/budgets/ci-quick-smoke-budget.json \
  --out benchmarks/results/ci-library-smoke.json
```

Large-model benchmark profile (proof mode, faithful-heavy subset):

```bash
python3 benchmarks/run_library_bench.py --mode proof --k 16 --timeout 240 \
  --samples 3 \
  --protocols benchmarks/protocols-large.txt \
  --perf-budget benchmarks/budgets/proof-large-budget.json \
  --out benchmarks/results/proof-large.json
```

## Unbounded Rounds

For models with bounded `view/round` domains, use round abstraction proof:

```bash
cargo run -p tarsier-cli -- prove-round examples/pbft_faithful_liveness.trs \
  --k 20 \
  --engine pdr \
  --round-vars view,round,epoch,height

cargo run -p tarsier-cli -- prove-fair-round examples/pbft_faithful_liveness.trs \
  --k 20 \
  --fairness strong \
  --round-vars view,round,epoch,height
```

`prove-round` erases selected round fields/locals and proves safety on an
over-approximation:
- `SAFE` is sound for concrete unbounded-round behavior.
- `UNSAFE` can be spurious (re-check concrete model).

`prove-fair-round` applies the same abstraction for unbounded fair-liveness:
- `LIVE_PROVED` is sound for concrete unbounded-round behavior.
- `FAIR_CYCLE_FOUND` can be spurious (re-check concrete model).

## Counterexample Visualization

Generate timeline and message-sequence-chart artifacts directly from failing runs:

```bash
# Safety counterexample (bounded)
cargo run -p tarsier-cli -- visualize examples/reliable_broadcast_buggy.trs \
  --check verify \
  --depth 8 \
  --format markdown \
  --out artifacts/reliable-broadcast-cex.md

# Fair-liveness lasso counterexample
cargo run -p tarsier-cli -- visualize examples/fair_nonterminating.trs \
  --check fair-liveness \
  --depth 10 \
  --fairness strong \
  --format mermaid \
  --out artifacts/fair-lasso.mmd
```

Supported `--check` modes:
- `verify`
- `liveness`
- `fair-liveness`
- `prove`
- `prove-fair`

Supported `--format` modes:
- `timeline` (plain text)
- `mermaid` (sequence diagram)
- `markdown` (timeline + Mermaid block)
- `json` (machine-readable bundle with timeline + Mermaid)

## Current Boundary

Tarsier is a threshold-automata symbolic checker.
Unbounded safety is attempted with induction-based engines (`kinduction` and IC3/PDR `pdr`).
Unbounded fair-liveness is attempted with fair-cycle IC3/PDR (`prove-fair`) under selectable weak/strong fairness assumptions.
Both PDR engines use solver-backed assumption-literal UNSAT-core cube generalization (with domain-guided fallback), adaptive bad-cube/obligation budgets instead of fixed hard caps, and frame-level cube subsumption pruning.
Under `timing: partial_synchrony`, fair-liveness loops are required to be post-GST.
`fair-liveness` / `prove-fair` support temporal liveness properties by compiling the negated property into a Büchi monitor and proving absence of fair accepting cycles.

Formal semantics and soundness assumptions are documented in `docs/SEMANTICS.md`.
Explicit trust boundary (what is trusted vs independently verified) is documented in `docs/TRUST_BOUNDARY.md`.

For scalability-focused bug triage, `verify`, `prove`, and `prove-fair` support adaptive CEGAR (`--cegar-iters`) with optional JSON artifact output (`--cegar-report-out`).
Refinement starts from the global atom set (`equivocation:none`, `auth:signed`, `values:exact`, `network:identity_selective`, `network:process_selective`) and now also synthesizes message-scoped refinements from counterexample evidence (for example `equivocation(Vote)=none`, `channel(Vote)=authenticated`).
Stage selection is evidence-driven: trace/core-backed refinements are attempted first, then fallbacks, with explicit per-stage selection rationale in the report.
When evidence signals are present, Tarsier now computes a solver-backed UNSAT-core seed over evidence-coverage obligations and starts from a minimized refinement set instead of relying on a fixed ladder order.
When multi-atom refinements eliminate a witness, Tarsier greedily shrinks to a minimal elimination core and emits both effective predicates and a derived conjunction predicate (`cegar.core.min(...)`).
CEGAR reports now include explicit termination metadata (iteration budget/usage, timeout budget, elapsed time, stable termination reason) and deterministic stage ordering for CI diffability.
CEGAR reports include stage-by-stage outcomes, explicit model changes, eliminated traces, inferred trace-signal notes, discovered refinement predicates (stage-local and aggregate), explicit counterexample analysis (`concrete` / `potentially_spurious` / `inconclusive`), and a final classification (`safe`, `unsafe_unrefined`, `unsafe_confirmed`, `timeout`, `inconclusive`).
Scalability regression coverage includes a multi-case false-alarm reduction check (`scalability_refinement_materially_reduces_false_alarms_on_harder_models`) to ensure CEGAR materially lowers spurious UNSAFE alarms across harder approximation-sensitive models.
`prove` and `prove-fair` CEGAR report APIs (`prove_*_with_cegar_report`) now emit full stage-by-stage refinement traces (labels, refinements, model changes, eliminated traces, discovered predicates, stage outcome, stage/overall counterexample analysis, deterministic termination metadata) in addition to baseline/final outcomes and explicit refinement controls for CI/governance tooling.
For `prove` with k-induction, CEGAR now also performs CTI-driven predicate synthesis: it mines candidate location-unreachability predicates from the induction witness, proves candidates, and reruns the proof with those synthesized invariants.
For scale and resilience to solver-specific behavior, `verify` and `prove` now support `--portfolio` (parallel Z3 + cvc5 execution with conservative result merging).

## Protocol Certification Suite

Run regression checks over the protocol corpus:

```bash
./scripts/certify-corpus.sh

# equivalent raw command
cargo run -p tarsier-cli -- cert-suite --manifest examples/library/cert_suite.json --engine kinduction --k 8 --format text
```

`examples/library/cert_suite.json` (schema v2) includes:
- expected safety outcomes (`verify`, `prove`),
- expected liveness outcomes (`liveness`, `fair_liveness`, `prove_fair`) for selected models,
- protocol metadata (`family`, `class`) for reporting and filtering.
- optional variant metadata (`variant`, `variant_group`) for minimal/faithful pairing.
- canonical BFT and CFT families (including crash/omission variants such as Paxos, Raft, Viewstamped Replication, HBBFT ACS-like, and Zab kernels).
- per-entry rationale in `notes`; schema v2 rejects entries without expected outcomes or rationale text.
- expected-outcome tokens are validated per check type to catch manifest drift early.
- `class=known_bug` entries are enforced as regression sentinels (must include bug-revealing expected outcomes).
- variant groups marked as paired must include both `minimal` and `faithful` models.
- strict schema contract is documented in `docs/CERT_SUITE_SCHEMA.md` with machine-readable schema `docs/cert-suite-schema-v2.json`.
- each entry pins `model_sha256` (file fingerprint) for deterministic failure triage.
- `enforce_library_coverage=true` (in `examples/library/cert_suite.json`) requires that every
  `examples/library/*.trs` protocol has a manifest expectation entry.
- this makes new protocol additions fail certification until expectations/tests are added.

Per-protocol outputs now include:
- entry `verdict` and `duration_ms`,
- explicit execution `assumptions` (solver/engine/soundness/fairness/network/depth/k/timeout/cegar),
- `artifact_links` for per-check outputs and entry summaries.
- failure `triage` labels: `model_change`, `engine_regression`, or `expected_update`.

Use `--format json --out artifacts/cert-suite.json --artifacts-dir artifacts/cert-suite` for CI artifacts.
After intentional model edits, refresh manifest fingerprints with:
`python3 scripts/update-cert-suite-hashes.py --manifest examples/library/cert_suite.json`.
`./scripts/certify-corpus.sh` now runs a hash-consistency check by default before certification.
CI includes `corpus-certification-gate`, which runs `./scripts/certify-corpus.sh` on pinned solver environments and gates downstream certificate/benchmark jobs.
Release process is additionally gated by the `Release Certification` workflow (tag `v*`), which runs corpus certification on pinned environment versions:
- OS: `ubuntu-22.04`
- Rust: `1.92.0`
- Z3: `4.12.5`
- cvc5: `1.1.2`
See `docs/RELEASE_PROCESS.md`.

## Designer UX

- Semantic linting:

```bash
cargo run -p tarsier-cli -- lint examples/pbft_simple.trs --soundness strict
```

- Interactive counterexample replay:

```bash
cargo run -p tarsier-cli -- debug-cex examples/reliable_broadcast_buggy.trs --check verify --depth 8
```

- Guided protocol scaffolds:

```bash
cargo run -p tarsier-cli -- assist --kind pbft --out examples/pbft_new.trs
cargo run -p tarsier-cli -- assist --kind hotstuff --out examples/hotstuff_new.trs
cargo run -p tarsier-cli -- assist --kind raft --out examples/raft_new.trs
```

## Proof Certificates

Generate a certificate bundle:

```bash
cargo run -p tarsier-cli -- certify-safety examples/pbft_simple.trs --k 12 --engine kinduction --out certs/pbft
cargo run -p tarsier-cli -- certify-safety examples/pbft_simple.trs --k 12 --engine pdr --out certs/pbft-pdr
cargo run -p tarsier-cli -- certify-fair-liveness examples/trivial_live.trs --k 8 --fairness weak --out certs/live-weak
```

This writes:

- `certificate.json` (metadata, proof engine, obligations, assumptions, SHA256 integrity fields)
- one `.smt2` file per obligation, each with an expected result

Schema contract:

- versioned certificate metadata schema with `schema_version` (current: `2`)
- strict checker compatibility (`schema_version` must match exactly)
- deterministic canonical certificate emission (stable ordering/canonicalized SMT obligations)
- obligation-profile completeness checks by certificate kind/engine (missing or extra obligations are rejected)
- schema docs: `docs/CERTIFICATE_SCHEMA.md`
- machine-readable schema: `docs/certificate-schema-v2.json`

Check with external solvers:

```bash
cargo run -p tarsier-cli -- check-certificate certs/pbft --solvers z3,cvc5
# minimal standalone checker (no parser/lowering/engine dependencies)
cargo run -p tarsier-certcheck -- certs/pbft --solvers z3,cvc5
# require multi-solver replay and emit machine-readable per-solver outcomes
cargo run -p tarsier-certcheck -- certs/pbft --solvers z3,cvc5 --require-two-solvers --json-report certcheck-report.json
# optional proof-object replay/validation path
chmod +x .github/scripts/check_proof_object.py
cargo run -p tarsier-certcheck -- certs/pbft --solvers z3,cvc5 --require-two-solvers --emit-proofs certs/pbft/proofs --require-proofs --proof-checker .github/scripts/check_proof_object.py
```

`check-certificate` first runs a trusted integrity kernel (schema/version checks, safe obligation paths, per-obligation hash checks, bundle hash check, and SMT script sanity checks) before invoking external solvers.
`tarsier-certcheck` applies the same integrity checks, rejects malformed solver outputs (missing/ambiguous SAT tokens), and records per-solver replay outcomes in JSON.
See `docs/TRUST_BOUNDARY.md` for exact claim boundaries of replay, re-derivation, and optional proof-object validation.
Use `--trusted-check --min-solvers N --rederive --proof-checker <path>` to require independent N-of-M solver confirmations per obligation, strict-soundness certificates, UNSAT-only obligations, fresh obligation re-derivation, and externally checked UNSAT proofs.
Use `--allow-unchecked-proofs` only if you intentionally accept weaker trust (solver UNSAT + proof-shape checks without an external checker).
Use `--proof-checker <path>` to run an external proof checker per UNSAT obligation (`--solver`, `--smt2`, `--proof` arguments are passed automatically).

Re-derive obligations from source and compare hashes before solver runs:

```bash
cargo run -p tarsier-cli -- check-certificate certs/pbft --solvers z3,cvc5 --rederive
```

To additionally persist raw solver proofs and enforce non-empty UNSAT proofs:

```bash
cargo run -p tarsier-cli -- check-certificate certs/pbft \
  --solvers z3,cvc5 \
  --emit-proofs certs/pbft/proofs \
  --require-proofs
```

You can also emit a certificate directly from `prove`:

```bash
cargo run -p tarsier-cli -- prove examples/pbft_simple.trs --k 12 --engine pdr --cert-out certs/pbft-pdr
```

And from `prove-fair`:

```bash
cargo run -p tarsier-cli -- prove-fair examples/trivial_live.trs --k 8 --fairness strong --cert-out certs/live-strong
```

Current certificate scope is:
- k-induction obligations (`base_case`, `inductive_step`)
- PDR invariant obligations (`init_implies_inv`, `inv_and_transition_implies_inv_prime`, `inv_implies_safe`)
- fair-liveness PDR obligations (`init_implies_inv`, `inv_and_transition_implies_inv_prime`, `inv_implies_no_fair_bad`)

## Protocol Library And Benchmarks

- Library models live in `examples/library/` (25 protocols including PBFT, HotStuff, Jolteon/Fast-HotStuff, Tendermint, Streamlet, Casper-FFG-like, SBFT, Zyzzyva, Algorand-vote, GRANDPA-like, Paxos/Multi-Paxos, Raft, QBFT, DiemBFT-like, HBBFT-ACS-like, Tusk-like, reliable-broadcast, and temporal/liveness sanity kernels).
- Canonical regression manifest: `examples/library/cert_suite.json` (schema v2 with safety and liveness expectations).
- Run a deterministic corpus benchmark and emit JSON:

```bash
python3 benchmarks/run_library_bench.py --mode standard --depth 8 --timeout 120
```

## Soundness Profiles

- `strict` (default): rejects underspecified models (missing safety property for `verify`, missing adversary bound when faults are modeled, unbounded integer locals). Distinct sender guards are modeled with automatic sender-uniqueness tracking. Under Byzantine `equivocation: full`, strict mode requires monotone threshold guards (`>=` or `>`). Linting in strict mode requires at least identity-coupled Byzantine networking (`network: identity_selective`, `cohort_selective`, or `process_selective`).
- `permissive`: keeps prototype-friendly fallbacks.

Use:

```bash
cargo run -p tarsier-cli -- verify examples/pbft_simple.trs --soundness strict
cargo run -p tarsier-cli -- verify examples/pbft_simple.trs --soundness permissive
```
