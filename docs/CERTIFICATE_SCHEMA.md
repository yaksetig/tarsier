# Certificate Schema (v2)

This document defines the on-disk schema for Tarsier proof certificate bundles.

## Scope

A certificate bundle directory contains:

- `certificate.json` (metadata)
- one SMT query file per obligation (for example `base_case.smt2`)

The trusted integrity checker in `tarsier-proof-kernel` validates both metadata and SMT files before any solver replay.
`tarsier-certcheck` is the standalone replay binary that uses this kernel and external solvers only.
For explicit trusted/verified boundaries, see `docs/TRUST_BOUNDARY.md`.

## Versioning Policy

- Current schema version: **2**
- Metadata field: `schema_version`
- Checker compatibility: **exact match only** (`schema_version == 2`)

Why exact match:
- Avoids silently accepting future layouts/semantics that this checker was not written to validate.
- Keeps the trust boundary explicit.

If schema changes:
1. Bump `schema_version`.
2. Update `tarsier-proof-kernel` validation logic.
3. Update this document and the JSON schema file.
4. Add migration/release notes.

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| v1 | 2025-01 | Initial schema: `certificate.json` with obligations, SHA256 hashes, and bundle hash. No `fairness`, no `committee_bounds`, no proof-profile obligation completeness. |
| v2 | 2025-03 | Added `fairness` field (required for `fair_liveness_proof`). Added `committee_bounds` array. Introduced proof-profile obligation completeness checks by `(kind, proof_engine)`. Added `deny_unknown_fields` enforcement. Domain-tagged bundle hash (`tarsier-certificate-v2\n` prefix). |
| v2.1 | 2026-02 | Added optional `proof_file` and `proof_sha256` fields to obligations for binding solver proof objects to certificates. Bundle hash now covers proof metadata. |

## Cross-References

| Artifact | Path | Relationship |
|----------|------|-------------|
| Machine-readable JSON schema | `docs/certificate-schema-v2.json` | Formal schema for `certificate.json` validation |
| Proof kernel implementation | `crates/tarsier-proof-kernel/src/lib.rs` | Rust implementation of integrity checks, hash computation, and obligation profiles |
| Trust boundary documentation | `docs/TRUST_BOUNDARY.md` | Documents what is verified vs trusted, residual assumptions, and governance profiles |
| Proof kernel specification | `docs/KERNEL_SPEC.md` | Formal specification of kernel semantics, trusted base, and obligation-to-check mapping |
| Checker soundness artifact | `docs/CHECKER_SOUNDNESS_ARGUMENT.md` | Soundness argument, machine-checked subset proof links, and explicit non-goals |
| Standalone checker binary | `crates/tarsier-certcheck/` | Minimal binary for independent certificate replay (depends only on `tarsier-proof-kernel`) |

## Stability Contract

For schema version 2:

- `certificate.json` uses strict decoding (`deny_unknown_fields`), so unknown fields are rejected.
- Obligation file paths must be safe relative paths inside the bundle.
- Each obligation must include a SHA256 hash.
- Bundle integrity includes a deterministic `bundle_sha256` over metadata + obligation hashes. The hash is computed with the domain tag `tarsier-certificate-v2\n` prepended to prevent cross-protocol hash collisions.
- Certificate emission canonicalizes obligation ordering, committee-bound ordering, and SMT declaration/assertion ordering for deterministic output.
- The trusted checker enforces proof-profile obligation completeness by `(kind, proof_engine)` (no missing or extra obligations).
- All proof obligations must use `expected = "unsat"` to support independent replay.

## `certificate.json` Fields (v2)

Top-level object:

- `schema_version: integer` (must be `2`)
- `kind: string` (`"safety_proof"` or `"fair_liveness_proof"`)
- `protocol_file: string`
- `proof_engine: string` (`"kinduction"` or `"pdr"`)
- `induction_k: integer|null`
- `solver_used: string` (`"z3"` or `"cvc5"`)
- `soundness: string` (`"strict"` or `"permissive"`)
- `fairness: string|null` (`"weak"` or `"strong"`; only for fair-liveness)
- `committee_bounds: array<[string, integer]>`
- `bundle_sha256: string` (hex)
- `obligations: array<object>`

Each obligation object:

- `name: string`
- `expected: string` (must be `"unsat"`)
- `file: string` (relative `.smt2` filename)
- `sha256: string` (hex)
- `proof_file: string|null` (optional; relative `.proof` filename for bound proof object)
- `proof_sha256: string|null` (optional; hex SHA-256 of the proof object file)

## Required Obligation Profiles

For independent replay, obligation names are fixed by certificate type:

- `kind = "safety_proof", proof_engine = "kinduction"`:
  - `base_case`
  - `inductive_step`
- `kind = "safety_proof", proof_engine = "pdr"`:
  - `init_implies_inv`
  - `inv_and_transition_implies_inv_prime`
  - `inv_implies_safe`
- `kind = "fair_liveness_proof", proof_engine = "pdr"`:
  - `init_implies_inv`
  - `inv_and_transition_implies_inv_prime`
  - `inv_implies_no_fair_bad`

Additional profile checks:

- `induction_k` is required for all proof certificates (for fair-liveness this is the converged frame).
- `fairness` must be absent for safety certificates.
- `fairness` must be `"weak"` or `"strong"` for fair-liveness certificates.

Standalone replay contract (`tarsier-certcheck`):
- Replays **both** safety and fair-liveness obligation bundles with external solvers.
- Fails closed if required obligations for a profile are missing (`missing_required_obligation`) or extra (`unexpected_obligation_name`).
- Remains engine-independent: `tarsier-certcheck` depends only on `tarsier-proof-kernel` plus external solver invocation.

## Minimal Example

```json
{
  "schema_version": 2,
  "kind": "safety_proof",
  "protocol_file": "examples/pbft_simple.trs",
  "proof_engine": "pdr",
  "induction_k": 7,
  "solver_used": "z3",
  "soundness": "strict",
  "fairness": null,
  "committee_bounds": [["f", 1]],
  "bundle_sha256": "9f...ab",
  "obligations": [
    {
      "name": "init_implies_inv",
      "expected": "unsat",
      "file": "init_implies_inv.smt2",
      "sha256": "3a...10"
    },
    {
      "name": "inv_and_transition_implies_inv_prime",
      "expected": "unsat",
      "file": "inv_and_transition_implies_inv_prime.smt2",
      "sha256": "0b...9a"
    },
    {
      "name": "inv_implies_safe",
      "expected": "unsat",
      "file": "inv_implies_safe.smt2",
      "sha256": "d1...ef"
    }
  ]
}
```

## Machine-Readable Schema

See `docs/certificate-schema-v2.json`.
