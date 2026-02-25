# API Stability and SemVer Policy

This document defines compatibility guarantees for Tarsier public surfaces.

## Versioning Baseline

- Crates are currently `0.x`.
- Per SemVer, breaking changes may occur in minor releases before `1.0.0`.
- We still treat key user-facing contracts as stable unless explicitly versioned or deprecated.

## Stability Tiers

### Tier 1: Versioned External Contracts (Strongest Guarantee)

These are treated as stable, schema-versioned contracts:

- JSON schema artifacts under `docs/*schema*.json`
- Certificate metadata and bundle integrity schema (`CERTIFICATE_SCHEMA_VERSION`)
- Conformance manifest/report schemas
- Quantitative report schema versions

Guarantee:
- Breaking changes must be accompanied by explicit schema version bumps and migration notes.
- Old and new schema versions must not be silently conflated.

### Tier 2: CLI User Contract (Strong Guarantee)

These are intended to remain stable across patch/minor releases:

- Canonical command flow: `assist -> analyze -> visualize`
- Core command names and top-level semantics (`analyze`, `prove`, `prove-fair`, `lint`, `visualize`)
- Governance command set when built with `--features governance`

Guarantee:
- Breaking flag/behavior changes require deprecation period or clear release-note migration guidance.

### Tier 3: Rust Crate APIs (Best-Effort Pre-1.0)

Public Rust APIs in workspace crates are currently best-effort and may evolve in minor releases while the project is pre-1.0.

Guarantee:
- Patch releases should avoid avoidable breakage.
- Minor releases may refactor/rename `pub` APIs when needed for correctness/performance.

## Deprecation Process

When changing Tier 1 or Tier 2 surfaces:

1. Document the change in `docs/CHANGELOG.md`.
2. Add migration guidance in `docs/MIGRATION.md` when applicable.
3. Keep CI contract checks in sync (`.github/scripts/check_release_doc_sync.py` and related checks).

## Scope Notes

- This policy covers source-level and schema-level compatibility.
- It does not guarantee solver-level determinism across solver upgrades.
- It does not freeze internal module layout for crates that are not yet `1.0.0`.
