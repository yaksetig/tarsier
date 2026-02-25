# Quantitative Output Schema (v2)

This document defines the JSON contract for quantitative outputs emitted by:

- `tarsier-cli comm ... --format json`
- `tarsier-cli comm ... --format json --out <artifact.json>` (CI/governance artifact path)

## Versioning Policy

- Current schema version: **2**
- Field: `schema_version`
- Compatibility policy: **exact match only** (`schema_version == 2`)

Why exact match:

- prevents silent acceptance of changed metric semantics;
- keeps CI/governance ingestion deterministic.

If the quantitative output shape changes:

1. bump `schema_version`;
2. update `CommComplexityReport` and serialization tests;
3. update this document and the JSON schema file;
4. add migration notes for downstream consumers.

## Contract Summary (v2)

The top-level quantitative report includes:

- model provenance (`model_metadata`)
- assumptions (`model_assumptions`, `assumption_notes`)
- bound classifications (`bound_annotations`) including explicit evidence class:
  - `theorem_backed` for structural/provable upper/lower/exact bounds
  - `heuristic_estimate` for approximation-driven estimates
- communication bounds (`per_*` fields)
- probabilistic/finality metrics (`finality_*`, `expected_rounds_*`, confidence rounds)
- sensitivity samples (`sensitivity`)
- sensitivity-derived probabilistic confidence intervals (`probabilistic_confidence_intervals`)
- explicit rejection behavior for unsupported extrapolations (affected metrics are `null` and reason is emitted in `assumption_notes` with `level = "error"`).

`model_metadata` includes explicit reproducibility anchors:

- `source_hash` (SHA-256 of model source text)
- `analysis_options` (command + depth)
- `analysis_environment` (target os/arch/family + build profile)
- `reproducibility_fingerprint` (SHA-256 over source hash + options + environment + engine version)

The machine-readable schema is strict (`additionalProperties: false`) and version-pinned.

## Machine-Readable Schema

See `docs/quantitative-schema-v2.json`.

## CI Baseline Gate

Known analytic formula baselines are enforced in CI/release via:

- `scripts/check-quantitative-baselines.sh`
- `scripts/check-quantitative-cli-pipeline.sh` (CLI reproducibility gate)
