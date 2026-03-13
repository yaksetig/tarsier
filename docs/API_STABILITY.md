# API Stability and Compatibility Policy

This document defines which Tarsier surfaces are intended for downstream reuse
and which are implementation details even if they are currently `pub`.

## Versioning Baseline

- Workspace crates are still `0.x`.
- Before `1.0.0`, SemVer minor releases may include breaking Rust API changes.
- Even pre-`1.0`, supported surfaces listed here should avoid avoidable
  breakage and should receive migration notes when practical.

## Cross-Cutting Contract Tiers

### Tier 1: Versioned External Contracts

These are treated as stable, explicitly versioned contracts:

- JSON schema artifacts under `docs/*schema*.json`
- Certificate metadata and bundle integrity schema
  (`CERTIFICATE_SCHEMA_VERSION`)
- Conformance manifest/report schemas
- Quantitative report schema versions

Guarantee:

- Breaking changes require an explicit schema version bump.
- Release notes and migration notes must explain the change.
- Old and new schema versions must not be silently conflated.

### Tier 2: Process and Wire Contracts

These are user-facing contracts exposed through executables or protocols rather
than through a Rust library API:

- The `tarsier` CLI command set and documented top-level workflows
- The `tarsier-certcheck` CLI contract
- The LSP wire protocol served by `tarsier-lsp`
- The documented playground HTTP behavior when it is used as a local tool

Guarantee:

- Breaking behavioral changes should come with release-note migration guidance.
- Renames or removals should use a deprecation period when practical.

### Tier 3: Rust Crate Support Matrix

The matrix below classifies each workspace crate into three buckets:

- Supported: intended for downstream reuse. These are the best candidates for
  external dependencies today.
- Provisional: public and sometimes useful, but still expected to evolve while
  the repo is pre-`1.0`.
- Internal: not a supported API, even if currently `pub`. Prefer a supported
  Rust API or the documented CLI/LSP/schema contract instead.

The matrix is intentionally selective. If a public item is not clearly named in
the Supported column, assume it is at most provisional.

## Crate-by-Crate Matrix

| Crate | Supported surfaces | Provisional surfaces | Internal / avoid depending on |
| --- | --- | --- | --- |
| `tarsier-dsl` | Top-level parsing entrypoints: `parse`, `parse_with_diagnostics`, `resolve_imports`; AST and parse-diagnostic types under `ast` and `errors` | Raw `parser` module items beyond the re-exported entrypoints; exact grammar and span-shape behavior | Parser implementation details and grammar internals; prefer the top-level parse API |
| `tarsier-ir` | Core data models that cross crate boundaries: `threshold_automaton`, `counter_system`, `runtime_trace`, `properties` | `lowering`, `abstraction`, `composition`, `equivalence`, `product`, `refinement` | `proptest_generators` and any test-only/helper surface |
| `tarsier-smt` | No supported external Rust surface today; prefer `tarsier-engine` unless you are extending solver internals | `solver`, `sorts`, `terms`, backend-selection abstractions | `bmc`, `encoder`, `encoding_helpers`, `equivalence_encoder`, `refinement_encoder` |
| `tarsier-prob` | `CommitteeSpec`, `CommitteeAnalysis`, `HypergeometricParams`, `analyze_committee` | Module-level helpers in `committee` and `hypergeometric` | Numerical implementation details not intentionally exposed as reusable API |
| `tarsier-proof-kernel` | Certificate validation entrypoints and schema-facing types/constants, including `check_bundle_integrity`, certificate metadata/report types, and certificate schema constants | Governance/profile export structs and auxiliary helpers used by CLI/CI tooling | Hashing, path-normalization, and replay internals beyond the documented validation entrypoints |
| `tarsier-engine` | High-level embedding surfaces in `pipeline`, `result`, and `visualization` | `compositional`, `counterexample`, `export_ta` | `sandbox` and lower-level pipeline internals that are public only for workspace integration |
| `tarsier-codegen` | `CodegenTarget`, `CodegenError`, `ProvenanceInfo`, `generate`, `generate_with_provenance` | Backend modules `go_gen`, `rust_gen`, `trace_hooks`, `trace_oracle`, `common` | Backend formatting/layout internals beyond the top-level generate API |
| `tarsier-conformance` | `checker`, `manifest`, and `replay` entrypoints and the report/obligation types they expose | `active`, `adapters`, `obligations` | `network_shim` and transport-specific internals |
| `tarsier-cli` | The `tarsier` executable contract: command names, documented flags, and documented machine-readable outputs | None | All Rust modules in this package; do not depend on this crate as a library |
| `tarsier-certcheck` | The `tarsier-certcheck` executable contract and its documented JSON report shape | None | All Rust modules in this package; use `tarsier-proof-kernel` if you need an embeddable checker API |
| `tarsier-lsp` | The LSP wire contract exposed by the server process | `TarsierLspBackend::new` for embedding in custom hosts | Remaining Rust modules, workspace state layout, and helper functions |
| `tarsier-playground` | No supported Rust API; this package is `publish = false` and is treated as a local/demo service | Current HTTP routes and JSON response shapes | Server internals, templates, and module layout |

## Change and Deprecation Rules

When changing a Tier 1 contract or a Supported surface from the matrix:

1. Document the change in `docs/CHANGELOG.md`.
2. Add migration guidance in `docs/MIGRATION.md` when applicable.
3. Keep CI contract checks in sync (`.github/scripts/check_release_doc_sync.py`
   and related checks).
4. Update this document in the same change if a surface moves between
   Supported, Provisional, and Internal.

Changes to Provisional or Internal surfaces do not require a deprecation
period, but they should still be called out in release notes when they affect
likely downstream users.

## Scope Notes

- This policy covers source-level, process-level, and schema-level
  compatibility.
- It does not guarantee solver-level determinism across solver upgrades.
- It does not freeze internal module layout for pre-`1.0` crates.
- Future `pub(crate)` cleanup may move items from Provisional/Internal into a
  smaller, clearer supported surface.
