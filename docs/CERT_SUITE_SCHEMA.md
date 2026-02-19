# Certification Suite Manifest Schema (v2)

This document defines the schema contract for `cert-suite` manifests.

## Scope

A certification manifest (for example `examples/library/cert_suite.json`) declares:

- protocol entries (`file`)
- expected outcomes per check (`verify`, `liveness`, `fair_liveness`, `prove`, `prove_fair`)
- metadata for reporting/triage (`family`, `class`)
- optional variant pairing metadata (`variant`, `variant_group`)
- rationale (`notes`)
- protocol fingerprint (`model_sha256`)
- optional corpus coverage gate (`enforce_library_coverage`, `library_dir`)

`tarsier-cli cert-suite` validates this manifest before running any checks.

## Versioning Policy

- Current schema version: **2**
- Field: `schema_version`
- Compatibility policy: **exact match only** (`schema_version == 2`)

Why exact match:

- avoids silently accepting future shapes/semantics;
- keeps CI and regression expectations deterministic.

If the schema changes:

1. bump `schema_version`;
2. update `tarsier-cli` manifest validation;
3. update this document and the JSON schema file;
4. add migration notes.

## Validation Contract (v2)

- Strict decoding (`deny_unknown_fields`): unknown keys are rejected.
- `entries` must be non-empty.
- Optional top-level coverage gate:
  - `enforce_library_coverage=true` enforces that all `.trs` files in `library_dir` have expectation entries, and manifest entries do not reference missing files in that directory.
  - `library_dir` defaults to manifest directory (`.`).
- `file` must be a non-empty `.trs` path.
- `file` must be unique within the manifest.
- `family` is required and non-empty.
- `class` is required and must be one of:
  - `expected_safe`
  - `known_bug`
- If `variant` is set, `variant_group` must be set, and vice versa.
- `variant` (when present) must be `minimal` or `faithful`.
- For each `variant_group`, both `minimal` and `faithful` entries must exist.
- Manifest must include at least one `class=known_bug` entry (regression sentinel coverage).
- Every `class=known_bug` entry must include at least one bug-sentinel expected outcome:
  - `unsafe`
  - `not_live`
  - `fair_cycle_found`
- `notes` is required and non-empty (rationale per protocol).
- `model_sha256` is required and must be a 64-char hex SHA-256 digest of the `.trs` file content.
  - helper: `python3 scripts/update-cert-suite-hashes.py --manifest examples/library/cert_suite.json`
- Each entry must define at least one expected outcome field:
  - `verify`
  - `liveness`
  - `fair_liveness`
  - `prove`
  - `prove_fair`
- Expected outcomes are check-typed:
  - `verify`: `safe | probabilistically_safe | unsafe | unknown`
  - `liveness`: `live | not_live | unknown`
  - `fair_liveness`: `no_fair_cycle_up_to | fair_cycle_found | unknown`
  - `prove`: `safe | probabilistically_safe | unsafe | not_proved | unknown`
  - `prove_fair`: `live_proved | fair_cycle_found | not_proved | unknown`

## Failure Triage Contract

For failing entries/checks, `cert-suite` emits `triage` with one of:

- `model_change`: protocol file hash differs from `model_sha256`.
- `engine_regression`: model hash matches baseline but result changed or execution errored.
- `expected_update`: mismatch is polarity-consistent with benchmark class and likely indicates stale expected tokens.

## Machine-Readable Schema

See `docs/cert-suite-schema-v2.json`.
