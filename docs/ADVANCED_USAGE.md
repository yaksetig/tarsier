# Advanced Usage

This document covers CI integration, governance pipelines, proof certificates, CEGAR refinement, benchmarks, and other advanced Tarsier features. For getting started, see the [README](../README.md) or [Getting Started guide](GETTING_STARTED.md).

## Analysis Modes

Use `analyze` for deterministic CI/governance pipelines:

```bash
# Fast bug scan
tarsier analyze examples/pbft_simple.trs --mode quick

# Bounded safety/liveness/fair-liveness + comm report
tarsier analyze examples/pbft_simple.trs --mode standard

# Standard + unbounded safety and fair-liveness proofs
tarsier analyze examples/pbft_simple.trs --mode proof --fairness weak

# Proof + cross-solver checks, write JSON artifact
tarsier analyze examples/pbft_simple.trs --mode audit --format json --report-out report.json

# Portfolio mode (Z3 + cvc5)
tarsier analyze examples/pbft_simple.trs --mode proof --portfolio --format json
```

`analyze` exits with code `0` on overall pass and `2` otherwise.

### Legacy Command Mapping

| Legacy command | Equivalent `analyze` invocation |
|---|---|
| `verify file.trs --depth 10` | `analyze file.trs --goal bughunt` |
| `prove file.trs --k 12 --engine pdr` | `analyze file.trs --goal safety` |
| `prove-fair file.trs --k 8 --fairness weak` | `analyze file.trs --goal safety+liveness` |
| `analyze file.trs --mode audit` | `analyze file.trs --goal release` |

Legacy commands remain available with `--profile pro`. See [MIGRATION.md](MIGRATION.md) for the full V2 migration guide.

### Focused Expert Commands

Use these when you need targeted diagnostics beyond the default `analyze` flow:

| Command | Purpose |
|---|---|
| `tarsier infer-invariants <file> --solver z3 --depth 12` | Mine and rank candidate strengthening predicates |
| `tarsier prove <file> --auto-strengthen` | Run prove with invariant-inference pre-pass |
| `tarsier refinement-check concrete.trs --abstract-file abstract.trs --depth 12` | Directional refinement/simulation diagnostics |
| `tarsier equivalence-check a.trs --other b.trs --depth 12` | Bidirectional bounded equivalence diagnostics |
| `tarsier conformance-replay <file> --check verify --export-trace replay.json` | Concretize/replay traces for conformance workflows |

### Scale Guardrails by Mode

- **quick**: `--depth 4..8`, `--timeout 60..120`. Keep faithful fallback at `identity` or `classic` with budgets near `--fallback-max-locations 6000 --fallback-max-shared-vars 30000 --fallback-max-message-counters 20000`.
- **standard**: `--depth 8..12`, `--timeout 120..240`. Keep `--soundness strict`; widen fallback budgets only if diagnostics show frequent exhaustion.
- **proof**: `--k 12..20`, `--timeout 300+`, `--engine pdr` for harder models. Use `--portfolio` for solver-sensitive runs.
- **audit**: Use `--portfolio --format json --report-out ...` and archive full artifacts. Expect highest runtime and memory.

## CI Integration

```bash
# Fast CI gate (quick mode, depth 4, 60s timeout)
tarsier analyze my_protocol.trs --profile ci-fast --format json

# CI proof gate (proof mode, depth 10, k 12, 300s timeout)
tarsier analyze my_protocol.trs --profile ci-proof --format json

# Release gating (audit mode, depth 12, k 14, 600s timeout, portfolio enabled)
tarsier analyze my_protocol.trs --profile release-gate --format json --report-out release/
```

### CI Perf Regression Gate

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
  --perf-budget benchmarks/budgets/large-smoke-budget.json \
  --out benchmarks/results/proof-large.json
```

## Governance Pipeline

### One-Command Governance

```bash
tarsier governance-pipeline examples/library/reliable_broadcast_safe.trs \
  --cert-manifest examples/library/cert_suite.json \
  --conformance-manifest examples/conformance/conformance_suite.json \
  --benchmark-report artifacts/benchmark-report.json \
  --format json \
  --out artifacts/governance-pipeline-report.json
```

Emits a machine-readable gate report (`proof`, `cert`, `corpus`, `perf`) with per-gate status/details and top-level `overall` pass/fail. Schema: `docs/governance-pipeline-report-schema-v1.json`.

### Governance Feature Build

Governance-only commands compile only when built with `--features governance`:

```bash
CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo build -p tarsier-cli --features governance
```

Commands: `cert-suite`, `certify-safety`, `certify-fair-liveness`, `check-certificate`, `generate-trust-report`, `governance-pipeline`, `verify-governance-bundle`.

### Signed Governance Bundle

When running release/governance analysis with `--report-out`, Tarsier writes `governance-bundle.json` including analysis report metadata, certificate artifact references/hashes, and detached Ed25519 signature metadata.

```bash
tarsier verify-governance-bundle artifacts/governance-bundle.json --format json
```

Bundle schema: `docs/governance-bundle-schema-v1.json`.

## Proof Certificates

Generate a certificate bundle (governance build required):

```bash
tarsier certify-safety examples/pbft_simple.trs --k 12 --engine kinduction --out certs/pbft
tarsier certify-safety examples/pbft_simple.trs --k 12 --engine pdr --out certs/pbft-pdr
tarsier certify-fair-liveness examples/trivial_live.trs --k 8 --fairness weak --out certs/live-weak
```

This writes `certificate.json` (metadata, proof engine, obligations, assumptions, SHA256 integrity) and one `.smt2` file per obligation.

### Checking Certificates

```bash
# Basic check
tarsier check-certificate certs/pbft --solvers z3,cvc5

# Standalone checker (no parser/lowering/engine dependencies)
tarsier-certcheck certs/pbft --solvers z3,cvc5

# Multi-solver replay with machine-readable report
tarsier-certcheck certs/pbft --solvers z3,cvc5 --require-two-solvers --json-report certcheck-report.json

# Re-derive obligations from source
tarsier check-certificate certs/pbft --solvers z3,cvc5 --rederive

# Emit raw solver proofs
tarsier check-certificate certs/pbft --solvers z3,cvc5 --emit-proofs certs/pbft/proofs --require-proofs

# High-assurance profile (requires cvc5 + Carcara)
TARSIER_REQUIRE_CARCARA=1 tarsier-certcheck certs/pbft --profile high-assurance \
  --solvers z3,cvc5 --emit-proofs certs/pbft/proofs \
  --proof-checker .github/scripts/check_proof_object.py

# Full trusted check
tarsier check-certificate certs/pbft --solvers z3,cvc5 \
  --trusted-check --min-solvers 2 --rederive \
  --emit-proofs certs/pbft/proofs --proof-checker ./scripts/check-proof.sh
```

### Emitting Certificates from Proof Commands

```bash
tarsier prove examples/pbft_simple.trs --k 12 --engine pdr --cert-out certs/pbft-pdr
tarsier prove-fair examples/trivial_live.trs --k 8 --fairness strong --cert-out certs/live-strong
```

Current certificate scope: k-induction obligations (`base_case`, `inductive_step`), PDR invariant obligations (`init_implies_inv`, `inv_and_transition_implies_inv_prime`, `inv_implies_safe`), fair-liveness PDR obligations (`init_implies_inv`, `inv_and_transition_implies_inv_prime`, `inv_implies_no_fair_bad`).

Schema: `docs/CERTIFICATE_SCHEMA.md` / `docs/certificate-schema-v2.json`.

## Unbounded Rounds

For models with bounded `view/round` domains, use round abstraction proofs:

```bash
tarsier prove-round examples/pbft_faithful_liveness.trs \
  --k 20 --engine pdr --round-vars view,round,epoch,height

tarsier prove-fair-round examples/pbft_faithful_liveness.trs \
  --k 20 --fairness strong --round-vars view,round,epoch,height
```

- `prove-round`: `SAFE` is sound for concrete unbounded-round behavior. `UNSAFE` can be spurious.
- `prove-fair-round`: `LIVE_PROVED` is sound. `FAIR_CYCLE_FOUND` can be spurious.

## Counterexample Visualization

```bash
# Safety counterexample
tarsier visualize examples/reliable_broadcast_buggy.trs \
  --check verify --depth 8 --format markdown --out artifacts/rb-cex.md

# Fair-liveness lasso counterexample
tarsier visualize examples/library/reliable_broadcast_live_buggy.trs \
  --check fair-liveness --depth 10 --fairness strong --format mermaid --out artifacts/fair-lasso.mmd
```

Supported `--check` modes: `verify`, `liveness`, `fair-liveness`, `prove`, `prove-fair`.
Supported `--format` modes: `timeline`, `mermaid`, `markdown`, `json`.

## CEGAR Refinement

`verify`, `prove`, and `prove-fair` support adaptive CEGAR (`--cegar-iters`) with optional JSON artifact output (`--cegar-report-out`).

```bash
tarsier verify examples/pbft_simple.trs --depth 10 --cegar-iters 3 --cegar-report-out artifacts/pbft-cegar.json
tarsier prove examples/pbft_simple.trs --k 12 --engine pdr --cegar-iters 2 --cegar-report-out artifacts/pbft-prove-cegar.json
```

Key CEGAR features:
- Evidence-driven stage selection with solver-backed UNSAT-core seeding
- Multi-atom refinement with greedy minimal elimination cores
- CTI-driven predicate synthesis for k-induction proofs
- Full stage-by-stage refinement traces in JSON reports
- Deterministic termination metadata and stable fingerprints for CI diffability

## Protocol Certification Suite

```bash
./scripts/certify-corpus.sh

# Or directly:
tarsier cert-suite --manifest examples/library/cert_suite.json --engine kinduction --k 8 --format text
```

The manifest (`examples/library/cert_suite.json`, schema v2) includes expected safety/liveness outcomes, protocol metadata, variant pairing, and model fingerprints. See `docs/CERT_SUITE_SCHEMA.md` for the schema contract.

After model edits, refresh fingerprints: `python3 scripts/update-cert-suite-hashes.py --manifest examples/library/cert_suite.json`.

## Soundness Profiles

- **strict** (default): rejects underspecified models, requires monotone threshold guards under Byzantine equivocation, requires explicit identity/key/auth/equivocation declarations for faithful networking.
- **permissive**: prototype-friendly fallbacks.

```bash
tarsier verify examples/pbft_simple.trs --soundness strict
tarsier verify examples/pbft_simple.trs --soundness permissive
```

## DSL Reference

### Adversary Configuration

```trs
adversary {
    model: byzantine;           // byzantine | omission | crash
    bound: f;
    equivocation: full;         // full | none
    auth: signed;               // none | signed
    network: process_selective; // classic | identity_selective | cohort_selective | process_selective
    delivery: per_recipient;    // legacy_counter | per_recipient | global
    faults: per_recipient;      // legacy_counter | per_recipient | global
    timing: partial_synchrony;  // asynchronous | partial_synchrony
    gst: gst;
    values: sign;               // exact | sign
}
```

### Network Semantics

- `omission`: drops up to `bound` per step (forced to `0` after GST in partial synchrony).
- `crash`: crash-stop with cumulative count bounded by `bound`.
- `byzantine` + `equivocation: full`: conflicting message variants allowed.
- `byzantine` + `equivocation: none`: one variant per `(message type, recipient)` per step.
- `auth: signed`: sender-authenticated with per-sender one-send flags.
- `network: identity_selective`: ties Byzantine budgets across recipients with selective per-recipient delivery.
- `network: cohort_selective`: internal per-role delivery cohorts.
- `network: process_selective`: concrete bounded process identifiers with per-process selective delivery.

### Identities and Channels

```trs
identity Replica: process(node_id) key replica_key;
identity Client: role key client_key;
channel Vote: authenticated;
equivocation Vote: none;
```

### Cryptographic Objects

```trs
certificate PrepareQC from Prepare threshold 2*t+1 signer Replica;
threshold_signature CommitSig from Commit threshold 2*t+1 signer Replica;

when has PrepareQC(view=view) => { ... }
form PrepareQC(view=view);
lock PrepareQC(view=view);
justify PrepareQC(view=view);
```

### Liveness Properties

```trs
property term: liveness {
    forall p: Replica. p.decided == true
}

property progress: liveness {
    forall p: Replica. (p.locked == true) ~> <> (p.decided == true)
}

property eventually_some: liveness {
    exists p: Replica. p.decided == true
}
```

Temporal operators: `X` (next), `[]` (always), `<>` (eventually), `U` (until), `W` (weak until), `R` (release), `~>` (leads-to).

## JSON Report Diagnostics

JSON reports include per-layer profiling under `layers[*].details.abstractions`:
- `phase_profiles`: parse/lower/check/encode/solve timings and RSS
- `smt_profiles`: SMT call counts, assertion dedup, incremental reuse, symmetry pruning, POR metrics
- `por_dynamic_ample`: deterministic effectiveness summary for CI gating
- `lowerings[*]`: POR visibility including independent rule pairs, fallback state, and transition pruning stats

## DAG Protocol Verification

DAG-based consensus protocols (DAG-Rider, Bullshark, Narwhal) use `dag_round` declarations to model round dependency graphs. Verification uses the same commands as standard protocols:

```bash
# Bounded safety check
tarsier analyze my_dag_protocol.trs --mode standard

# Unbounded safety proof
tarsier analyze my_dag_protocol.trs --mode proof

# Refinement: compare DAG protocol against abstract spec
tarsier refinement-check concrete_dag.trs --abstract-file abstract.trs --depth 12

# Equivalence: compare two DAG protocol variants
tarsier equivalence-check dag_v1.trs --other dag_v2.trs --depth 12
```

The DAG structure is validated at lowering time (cycle detection, self-loop rejection, connectivity checks). For the full guide including DAG patterns, validation rules, and migration instructions, see [DAG_WORKFLOWS.md](DAG_WORKFLOWS.md).

## CI Solver Pinning

CI runs with pinned solver binaries:
- Z3 `4.12.5`
- cvc5 `1.1.2`
- Optional Alethe proof checking via Carcara for cvc5 proofs

Release certification uses: OS `ubuntu-22.04`, Rust `1.92.0`, Z3 `4.12.5`, cvc5 `1.1.2`. See [RELEASE_PROCESS.md](RELEASE_PROCESS.md).
