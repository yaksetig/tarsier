# Kernel Formalization RFC (KERN-01)

Status: Draft (Phase 3, KERN-01)  
Owners: Proof-kernel maintainers  
Last updated: 2026-03-10

## 1. Goal

Define a concrete formalization program for the standalone checker kernel
(`tarsier-proof-kernel`) so we can prove, in a theorem prover, that accepted
certificate bundles satisfy the kernel's published structural integrity contract.

This RFC is the planning artifact for:
- `KERN-02` (export/checker semantics artifact),
- `KERN-03` (Lean prototype theorem),
- `KERN-04` (Coq prototype parity).

## 2. Scope and Non-Scope

### In scope

- Formal semantics for:
  - certificate metadata/profile validation,
  - obligation set completeness checks,
  - path-safety checks,
  - per-file hash consistency checks,
  - deterministic bundle-hash recomputation checks,
  - SMT script structural sanity constraints.
- Theorems of the shape: "if kernel accepts, then integrity predicates hold."

### Out of scope

- Proving solver correctness (`sat`/`unsat` semantics).
- Proving SMT formula correctness with respect to protocol theorems.
- Proving parser/lowering/encoder correctness for `.trs` -> SMT obligations.
- Proving OS/filesystem primitives are correct.

These remain explicit trust assumptions in `docs/TRUST_BOUNDARY.md`.

## 3. Reference Semantics Baseline

The formal model in this RFC is anchored to:

- checker behavior contract: `docs/KERNEL_SPEC.md`
- trust assumptions/boundaries: `docs/TRUST_BOUNDARY.md`
- soundness artifact and subset tests: `docs/CHECKER_SOUNDNESS_ARGUMENT.md`
- implementation under proof: `crates/tarsier-proof-kernel/src/lib.rs`

The formal model must track the versioned certificate schema (`v2`) and fail-closed
behavior (`is_ok() == true` iff no issues are emitted).

## 4. Threat Model for Formalization Work

The formalization targets high-value integrity failures that would let malformed
or tampered bundles pass checker validation.

Threat classes addressed by theorem work:

1. Schema/profile bypass:
   accepted bundle uses illegal `(kind, proof_engine, fairness)` combination.
2. Obligation profile incompleteness:
   missing required obligations or unexpected obligation names are accepted.
3. Path traversal/escape:
   accepted obligation/proof paths resolve outside bundle root.
4. Hash tampering:
   obligation/proof/bundle hashes do not match actual bytes.
5. SMT structural bypass:
   malformed scripts (missing assert/check-sat/exit or disallowed commands) are accepted.

Residual threats (not addressed by these theorems):

- compromised solver/proof-checker binaries,
- incorrect semantics encoding in obligations,
- model fidelity mismatch between `.trs` and deployment.

## 5. Semantic Model Requirements

The exported semantics artifact (`KERN-02`) must include:

- typed certificate metadata model:
  - kind, proof_engine, fairness, induction_k, obligations, hashes.
- obligation profile relation:
  - required obligation names by `(kind, proof_engine)`.
- filesystem/path predicate model:
  - relative-path requirement, no traversal components, no bundle escape.
- hash function abstraction:
  - deterministic byte-to-digest function symbol (no cryptographic proof required).
- SMT command-shape model:
  - command multiset and ordering constraints used by kernel checks.
- report semantics:
  - issue set and `is_ok` predicate.

## 6. Theorem Roadmap and Milestones

## M1 (KERN-02): Exportable Checker Semantics Artifact

Deliverable:
- machine-readable semantics artifact that both Lean/Coq adapters can ingest.
- initial artifact path: `artifacts/kernel-semantics/kernel_semantics_v1.json`
- initial schema path: `docs/kernel-semantics-schema-v1.json`
- initial exporter entrypoint:
  `cargo run -p tarsier-proof-kernel --bin kernel-semantics-export -- --out artifacts/kernel-semantics/kernel_semantics_v1.json`

Acceptance criteria:
- artifact covers all current kernel error-code classes;
- generation is deterministic;
- CI check validates artifact schema and round-trip parse.

## M2 (KERN-03): Lean Prototype Soundness Theorem

Minimum theorem target:
- `kernel_accepts(bundle) -> integrity_predicates_hold(bundle)`

`integrity_predicates_hold` must include:
- profile admissibility,
- obligation completeness,
- path safety,
- hash-match predicates,
- SMT structural sanity predicates.

Acceptance criteria:
- theorem checked in CI by Lean;
- at least one negative counterexample construction tested (reject path).

## M3 (KERN-04): Coq Prototype Parity Theorem

Minimum theorem target:
- Coq statement equivalent to Lean theorem over same exported semantics artifact.

Acceptance criteria:
- Coq proof script checks in CI;
- proof scope and assumptions documented side-by-side with Lean statement.

## M4 (Post KERN-04): Parity Drift Gate

Deliverable:
- CI contract requiring semantic export compatibility + Lean/Coq theorem parity summary.

Acceptance criteria:
- drift in exported semantics or theorem statement shape causes CI failure unless approved.

## 7. Artifact and CI Plan

Expected artifact layout after `KERN-02+`:

- `artifacts/kernel-semantics/kernel_semantics_v1.json` (or equivalent)
- `artifacts/kernel-semantics/lean/` (generated ingestion layer/proof target stubs)
- `artifacts/kernel-semantics/coq/` (generated ingestion layer/proof target stubs)

CI expectations:

1. schema validation for exported semantics artifact,
2. deterministic regeneration check,
3. Lean theorem check job,
4. Coq theorem check job.

## 8. Risks and Mitigations

1. Spec/implementation divergence:
   mitigate with explicit traceability from each formal predicate to kernel error code.
2. Proof maintenance overhead:
   mitigate with narrow theorem scope (structural soundness only) and versioned semantics.
3. Toolchain instability in theorem provers:
   mitigate by pinning Lean/Coq versions in CI and maintaining minimal proof dependencies.

## 9. Exit Criteria for "Formalization v1"

Formalization v1 is complete when:

1. `KERN-02`, `KERN-03`, and `KERN-04` are DONE,
2. Lean and Coq both check the minimal kernel-soundness theorem over a shared exported semantics artifact,
3. trust-boundary docs explicitly reference these proofs and still enumerate residual assumptions.
