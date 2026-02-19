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

## Stability Contract

For schema version 2:

- `certificate.json` uses strict decoding (`deny_unknown_fields`), so unknown fields are rejected.
- Obligation file paths must be safe relative paths inside the bundle.
- Each obligation must include a SHA256 hash.
- Bundle integrity includes a deterministic `bundle_sha256` over metadata + obligation hashes.
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
