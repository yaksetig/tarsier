# Checker Soundness Argument Artifact

This document is the soundness artifact for the standalone checker path (`tarsier-proof-kernel` + `tarsier-certcheck`).
It complements `docs/KERNEL_SPEC.md` by pinning the argument structure, explicit assumptions, explicit non-goals,
and machine-checked subset proof obligations.

## Soundness Claim

Given a bundle directory `B`, if `check_bundle_integrity(B)` returns `is_ok() == true`, then all kernel checks in
`docs/KERNEL_SPEC.md` Sections 4.1-4.6 hold for that bundle:

- schema/profile checks;
- obligation structure and completeness checks;
- path safety and hash integrity checks;
- SMT script sanity checks;
- bundle-hash integrity check.

This is a *structural soundness* claim for certificate integrity/replay preconditions. It is not a semantic proof that
an SMT obligation encodes the intended protocol theorem.

## Machine-Checked Subset Proof

The repository includes executable subset proofs that are checked in CI:

1. `soundness_subset_profile_validator_matches_reference_spec`
   - File: `crates/tarsier-proof-kernel/src/lib.rs`
   - Method: exhaustive finite-domain equivalence check against a reference specification.
   - Coverage: all combinations over `{kind, proof_engine, fairness, induction_k}` used by profile/fairness metadata checks.

2. `soundness_subset_bundle_hash_matches_spec_vectors`
   - File: `crates/tarsier-proof-kernel/src/lib.rs`
   - Method: fixed test vectors for canonical domain-tagged bundle hashing.
   - Coverage: safety and fair-liveness metadata forms, including optional proof metadata fields.

These tests provide a machine-checked subset proof for key kernel obligations (profile admissibility + hash canonicalization).

## Assumptions (Explicit + Test-Linked)

| Assumption | Scope | Test / Gate Link |
|---|---|---|
| `sha2` computes correct SHA-256 digests | Hash-integrity checks | `bundle_hash_covers_proof_metadata`, `soundness_subset_bundle_hash_matches_spec_vectors`, CI `build-test` |
| JSON decoding enforces strict schema (`deny_unknown_fields`) | Metadata parsing | `load_metadata_rejects_unknown_top_level_fields`, CI `build-test` |
| Path canonicalization reflects actual FS boundaries | Symlink/path escape defense | `integrity_report_flags_unsafe_obligation_path`, CI `build-test` |
| External solver verdicts are correct | Replay soundness (outside kernel) | `certcheck_passes_valid_bundle_with_mock_solver`, `certcheck_fails_on_tampered_obligation`, CI `Certcheck Standalone Replay Gate` |

## Explicit Non-Goals (Boundary + Test-Linked)

| Non-goal | Why out of scope | Boundary Test / Gate |
|---|---|---|
| Proving SMT formula semantic adequacy vs intended theorem | Kernel checks structure and integrity, not theorem semantics | `integrity_report_flags_disallowed_commands_and_bad_command_counts` (structure-only SMT checks), `docs/TRUST_BOUNDARY.md` |
| Independent source-to-obligation translation validation | Requires parser/lowering/encoder, beyond tiny kernel | `check-certificate --rederive` path (outside kernel), CI `certificate-check` / `certificate-check-fair-liveness` jobs |
| Fully formally verified external solver/proof checker stack | Depends on external tools | CI `certificate-proof-object-validation`, optional `--proof-checker` path; trust boundary remains explicit |

## CI Enforcement

The following CI steps enforce this artifact path:

- `Enforce Checker Soundness Artifact` (`python3 .github/scripts/check_checker_soundness_artifact.py`)
- `Checker Soundness Subset Gate` (`cargo test -p tarsier-proof-kernel soundness_subset_ -- --nocapture`)
- `Certcheck Standalone Replay Gate` (`cargo test -p tarsier-certcheck --test integration -- --nocapture`)

## Related Docs

- `docs/KERNEL_SPEC.md`
- `docs/CERTIFICATE_SCHEMA.md`
- `docs/TRUST_BOUNDARY.md`
