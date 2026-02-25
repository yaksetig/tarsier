# Conformance Manifest Schema (v1)

This document defines the schema contract for conformance test suite manifests.

## Scope

A conformance manifest declares a set of protocol-trace pairs with expected outcomes for deterministic conformance testing. Each entry maps a `.trs` protocol model to a trace JSON file, chooses an adapter family (`runtime`, `cometbft`, `etcd-raft`), and specifies checker strictness (`permissive`/`strict`) plus expected pass/fail outcome.

The conformance runner (`tarsier conformance-suite`) validates the manifest before executing any checks.

## Versioning Policy

- Current schema version: **1**
- Field: `schema_version`
- Compatibility policy: **exact match only** (`schema_version == 1`)

Why exact match:

- avoids silently accepting future shapes/semantics;
- keeps CI and regression expectations deterministic.

If the schema changes:

1. bump `schema_version`;
2. update `tarsier-conformance` manifest validation;
3. update this document and the JSON schema file;
4. add migration notes.

## Validation Contract (v1)

- Strict decoding (`deny_unknown_fields`): unknown keys are rejected at both top-level and entry-level.
- `suite_name` must be non-empty.
- `entries` must be non-empty.
- Each entry `name` must be non-empty and unique within the manifest.
- `protocol_file` must be non-empty and end with `.trs`.
- `trace_file` must be non-empty and end with `.json`.
- `trace_adapter` must be one of `runtime | cometbft | etcd-raft` (default: `runtime`).
- `checker_mode` must be one of `permissive | strict` (default: `permissive`).
- `expected_verdict` must be `"pass"` or `"fail"`.
- `model_sha256` (optional) must be a 64-hex SHA-256 hash.
- `mismatch_hint` (optional) must be one of `model_change | engine_regression | impl_divergence`.
- When file-path validation is enabled, both `protocol_file` and `trace_file` must resolve to existing files relative to the manifest base directory.

## `conformance_suite.json` Fields (v1)

Top-level object:

- `schema_version: integer` (must be `1`)
- `suite_name: string` (non-empty)
- `description: string|null` (optional)
- `entries: array<object>` (non-empty)

Each entry object:

- `name: string` (non-empty, unique)
- `protocol_file: string` (non-empty, must end with `.trs`)
- `trace_file: string` (non-empty, must end with `.json`)
- `trace_adapter: string` (`"runtime" | "cometbft" | "etcd-raft"`, default `"runtime"`)
- `checker_mode: string` (`"permissive" | "strict"`, default `"permissive"`)
- `expected_verdict: string` (`"pass"` or `"fail"`)
- `model_sha256: string|null` (optional, 64-hex SHA-256 of protocol file)
- `mismatch_hint: string|null` (optional, classification hint when verdict mismatches)
- `tags: array<string>` (optional, for filtering/classification)
- `notes: string|null` (optional, rationale)

## Failure Triage Contract

For failing entries, the conformance runner emits `triage` with one of:

- `model_change`: protocol source changed relative to `model_sha256`, or model decode/lower errors.
- `engine_regression`: runner/checker/adapter pipeline regression (or explicit `mismatch_hint` override).
- `impl_divergence`: adapted implementation trace diverges from modeled behavior.

These triage categories are contract-enforced; unknown triage labels are rejected before report emission.

## Cross-References

| Artifact | Path | Relationship |
|----------|------|-------------|
| Machine-readable JSON schema | `docs/conformance-manifest-schema-v1.json` | Formal schema for conformance manifest validation |
| Conformance checker library | `crates/tarsier-conformance/src/checker.rs` | Runtime trace validation against threshold automaton models |
| Manifest module | `crates/tarsier-conformance/src/manifest.rs` | Rust types, validation, and serde for conformance manifests |
| CLI conformance-suite command | `crates/tarsier-cli/src/main.rs` | Runner that executes a manifest deterministically |
| Reference manifest | `examples/conformance/conformance_suite.json` | Reference conformance suite for CI |
| Runner script | `scripts/run-conformance-suite.sh` | Shell wrapper for CI/release gates |

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| v1 | 2026-02 | Initial schema: `suite_name`, `description`, `entries` with `name`, `protocol_file`, `trace_file`, `expected_verdict`, `tags`, `notes`. Strict decoding with `deny_unknown_fields`. |
| v1 (expanded fields) | 2026-02 | Added optional `trace_adapter`, `checker_mode`, `model_sha256`, and `mismatch_hint` with validation; triage taxonomy aligned to `model_change`/`engine_regression`/`impl_divergence`. |

## Minimal Example

```json
{
  "schema_version": 1,
  "suite_name": "reference-conformance",
  "description": "Reference conformance traces for CI gate",
  "entries": [
    {
      "name": "valid_vote_trace",
      "protocol_file": "crates/tarsier-conformance/tests/fixtures/simple_vote.trs",
      "trace_file": "crates/tarsier-conformance/tests/fixtures/valid_trace.json",
      "trace_adapter": "runtime",
      "checker_mode": "strict",
      "expected_verdict": "pass",
      "model_sha256": "79fca27bcaf42a5a1f1965d31830631d4af307f2fd402b6c88e66ec3ef4f37b3",
      "tags": ["voting", "safety"],
      "notes": "Basic valid voting trace"
    },
    {
      "name": "guard_violation",
      "protocol_file": "crates/tarsier-conformance/tests/fixtures/simple_vote.trs",
      "trace_file": "crates/tarsier-conformance/tests/fixtures/guard_not_satisfied.json",
      "trace_adapter": "runtime",
      "checker_mode": "strict",
      "expected_verdict": "fail",
      "mismatch_hint": "impl_divergence",
      "tags": ["voting", "negative"],
      "notes": "Trace with insufficient votes should fail guard check"
    }
  ]
}
```

## Machine-Readable Schema

See `docs/conformance-manifest-schema-v1.json`.
