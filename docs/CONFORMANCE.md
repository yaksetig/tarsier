# Conformance Assurance Bridge

This document describes how Tarsier connects verified model properties to runtime implementation behavior through conformance checking.

## Overview

Tarsier verifies protocol models (`.trs` files) using bounded model checking and k-induction. The **conformance bridge** extends the trust boundary from the model to the implementation by:

1. Defining a runtime trace schema matching model transition semantics
2. Validating implementation traces against the model's allowed transitions
3. Mapping verified safety properties to machine-readable runtime obligations
4. Replaying model counterexample traces into process-level format

## Runtime Trace Schema

Process-level traces capture what a real implementation does. Each process emits events:

| Event Type | Description |
|-----------|-------------|
| `Init` | Process starts in a named location |
| `Transition` | Process moves from one location to another |
| `Send` | Process sends a message |
| `Receive` | Process receives a message from another process |
| `Decide` | Process makes a decision |
| `VarUpdate` | Process updates a local variable |

The JSON schema is defined in `docs/schemas/runtime-trace-schema-v1.json`.

### Example Trace

```json
{
  "schema_version": 1,
  "protocol_name": "ReliableBroadcast",
  "params": [["n", 4], ["t", 1], ["f", 1]],
  "processes": [
    {
      "process_id": 0,
      "role": "Process",
      "events": [
        { "sequence": 0, "kind": { "type": "Init", "location": "Process_Init" } },
        { "sequence": 1, "kind": { "type": "Send", "message_type": "Echo", "fields": [] } },
        { "sequence": 2, "kind": { "type": "Receive", "message_type": "Echo", "from_process": 1, "fields": [] } },
        { "sequence": 3, "kind": { "type": "Receive", "message_type": "Echo", "from_process": 2, "fields": [] } },
        { "sequence": 4, "kind": { "type": "Transition", "from_location": "Process_Init", "to_location": "Process_Accepted", "rule_id": null } },
        { "sequence": 5, "kind": { "type": "Decide", "value": "accept" } }
      ]
    }
  ]
}
```

## Recording Traces from Implementation

Generated Rust skeleton code includes a `TraceRecorder` trait:

```rust
pub trait TraceRecorder {
    fn record_init(&mut self, process_id: u64, location: &str);
    fn record_transition(&mut self, process_id: u64, from: &str, to: &str);
    fn record_send(&mut self, process_id: u64, msg_type: &str, fields: &[(&str, &str)]);
    fn record_receive(&mut self, process_id: u64, msg_type: &str, from: u64, fields: &[(&str, &str)]);
    fn record_decide(&mut self, process_id: u64, value: &str);
    fn record_var_update(&mut self, process_id: u64, var: &str, value: &str);
}
```

A `NoopRecorder` implementation is provided for production use (zero overhead). Implement `TraceRecorder` to capture traces for conformance checking.

## Running the Conformance Checker

The `tarsier-conformance` crate provides `ConformanceChecker`:

```rust
use tarsier_conformance::checker::ConformanceChecker;

let checker = ConformanceChecker::new(&automaton, &param_bindings);
let result = checker.check(&runtime_trace);

if !result.passed {
    for violation in &result.violations {
        eprintln!("Violation at process {} event {}: {:?} - {}",
            violation.process_id,
            violation.event_sequence,
            violation.kind,
            violation.message);
    }
}
```

### Adapter-Aware CLI Path

`tarsier conformance-check` supports trace adaptation and strictness directly:

```bash
tarsier conformance-check examples/library/pbft_simple_safe.trs \
  --trace examples/conformance/adapters/cometbft_simple_vote_pass.json \
  --adapter cometbft \
  --checker-mode strict
```

Supported adapters:

- `runtime`: native Tarsier runtime-trace JSON schema (`docs/schemas/runtime-trace-schema-v1.json`)
- `cometbft`: CometBFT/Tendermint-style node event traces
- `etcd-raft`: etcd/raft-style peer step traces

`--checker-mode permissive` allows partial mappings for exploratory bring-up.
`--checker-mode strict` rejects unknown message mappings and invalid decide context.

### Violation Types

| Kind | Meaning |
|------|---------|
| `InvalidInitialLocation` | Process starts in a non-initial location |
| `NoMatchingRule` | No model rule exists for the observed transition |
| `GuardNotSatisfied` | A rule exists but its guard condition is not met |
| `InvalidTransitionTarget` | A claimed rule ID does not match the transition endpoints |
| `UnknownLocation` | Referenced location name not found in the model |
| `UnknownMessageType` | Referenced message type not found in the model |

### Guard Evaluation

Guards are evaluated using pure arithmetic (no SMT solver needed):

- **Threshold guards**: Sum of per-message counters compared against a linear combination of parameters
- **Distinct guards**: Count of unique senders (tracked via sender ID sets)
- **Trivial guards**: Always satisfied (empty guard conjunction)

## Adapter Authoring Guide

Adapters are implemented in `crates/tarsier-conformance/src/adapters.rs` through a stable trait:

```rust
pub trait TraceAdapter {
    fn kind(&self) -> AdapterKind;
    fn adapt_json(&self, raw: &str) -> Result<RuntimeTrace, AdapterError>;
}
```

Authoring rules:

1. Parse source-family trace JSON with `deny_unknown_fields`.
2. Validate `schema_version == 1`.
3. Convert to `RuntimeTrace` with deterministic ordering and stable counter mapping.
4. Return typed `AdapterError` variants (`Decode`, `SchemaVersion`, `Invalid`) for deterministic failure behavior.
5. Add both pass/fail replay fixtures and corruption/tamper tests.

The conformance suite manifest field `trace_adapter` selects the adapter per entry.

## Trace Schema Contract

Conformance manifests (`docs/conformance-manifest-schema-v1.json`) define:

- `trace_adapter`: `runtime | cometbft | etcd-raft`
- `checker_mode`: `permissive | strict`
- `model_sha256` (optional): source hash pin for model drift detection
- `mismatch_hint` (optional): triage hint (`model_change | engine_regression | impl_divergence`)

Strict mode contract:

- unknown message/counter mappings are violations;
- decide events must occur in locations with `decided=true`.

## CometBFT Live Harness

`INTEG-01` adds a reproducible single-node CometBFT harness for live integration
bring-up. It runs a real `cometbft` process in Docker with fixed genesis/key
artifacts.

Harness assets:

- `integration/cometbft-live/docker-compose.yml`
- `integration/cometbft-live/bootstrap/bootstrap.sh`
- `integration/cometbft-live/bootstrap/config/*.json`

From repo root:

```bash
scripts/cometbft-live-harness.sh start
scripts/cometbft-live-harness.sh status
scripts/cometbft-live-harness.sh endpoint
scripts/cometbft-live-harness.sh stop
```

For a clean deterministic restart:

```bash
scripts/cometbft-live-harness.sh reset
scripts/cometbft-live-harness.sh start
```

Static deterministic config checks:

```bash
python3 scripts/check-cometbft-live-config.py
```

## CometBFT Active Conformance E2E (INTEG-03)

`INTEG-03` adds an end-to-end active conformance smoke path that exercises:

1. live CometBFT harness health (`scripts/cometbft-live-harness.sh start`);
2. `tarsier conformance-active` schedule replay to a live endpoint contract;
3. deterministic trace assertions over emitted `start/tick/fault/stop` events.

Fixture-only contract check (no Docker required):

```bash
./scripts/cometbft-conformance-active-smoke.sh assert-fixture
```

Full end-to-end smoke (requires Docker + local toolchain):

```bash
./scripts/cometbft-conformance-active-smoke.sh smoke
```

The smoke script verifies:

- adapter is `cometbft`;
- schema version and seed are stable;
- live CometBFT RPC contract (`/status`) is valid and non-regressing;
- expected fault/tick counts are deterministic;
- live contract metadata is `tarsier.active.v1`;
- endpoint receives the exact deterministic `start -> tick/fault* -> stop` sequence.

## etcd-raft Live Harness

`INTEG-02` adds a reproducible single-node etcd harness for live etcd-raft
integration bring-up. It runs a real etcd process in Docker with fixed cluster
token, node identity, and timing parameters.

Harness assets:

- `integration/etcd-raft-live/docker-compose.yml`

From repo root:

```bash
scripts/etcd-raft-live-harness.sh start
scripts/etcd-raft-live-harness.sh status
scripts/etcd-raft-live-harness.sh endpoint
scripts/etcd-raft-live-harness.sh stop
```

For a clean deterministic restart:

```bash
scripts/etcd-raft-live-harness.sh reset
scripts/etcd-raft-live-harness.sh start
```

Static deterministic config checks:

```bash
python3 scripts/check-etcd-raft-live-config.py
```

## etcd-raft Active Conformance E2E (INTEG-04)

`INTEG-04` adds an end-to-end active conformance smoke path that exercises:

1. live etcd harness health (`scripts/etcd-raft-live-harness.sh start`);
2. `tarsier conformance-active` schedule replay to a live endpoint contract;
3. deterministic trace assertions over emitted `start/tick/fault/stop` events.

Fixture-only contract check (no Docker required):

```bash
./scripts/etcd-raft-conformance-active-smoke.sh assert-fixture
```

Full end-to-end smoke (requires Docker + local toolchain):

```bash
./scripts/etcd-raft-conformance-active-smoke.sh smoke
```

The smoke script verifies:

- adapter is `etcd-raft`;
- schema version and seed are stable;
- live etcd HTTP contract (`/version` and `/health`) is valid;
- expected fault/tick counts are deterministic;
- live contract metadata is `tarsier.active.v1`;
- endpoint receives the exact deterministic `start -> tick/fault* -> stop` sequence.

## CI Integration for Live Adapter Tests (INTEG-05)

Workflow: `.github/workflows/live-adapter-conformance.yml`

- **PR smoke job**:
  - deterministic harness config checks;
  - fixture contract checks for CometBFT and etcd-raft;
  - adapter schedule generation smoke (`conformance-active`) for both adapters;
  - uploads smoke artifacts for debugging.

- **Nightly full job** (and manual `workflow_dispatch`):
  - runs full `smoke` for CometBFT and etcd-raft active conformance scripts;
  - on failure captures triage artifacts (`docker ps`, compose `ps/logs`, reports, event logs);
  - uploads triage bundle as workflow artifact.

## Triage Playbook

Conformance mismatches/errors are classified as:

- `model_change`: model hash drift or model parse/lower breakage.
- `engine_regression`: checker/runner regression (or explicit `mismatch_hint` override).
- `impl_divergence`: adapted implementation trace behavior diverges from expected model behavior.

Recommended response:

1. `model_change`: review model diff and update hash/expectations intentionally.
2. `engine_regression`: bisect tool changes and block release until fixed.
3. `impl_divergence`: inspect trace + counterexample to locate implementation bug or adapter bug.

## Obligation Map

The obligation map translates verified safety properties into machine-readable runtime monitoring specifications.

```rust
use tarsier_conformance::obligations::generate_obligation_map;

let map = generate_obligation_map(&automaton, "MyProtocol", &properties);
let json = serde_json::to_string_pretty(&map)?;
```

The JSON schema is defined in `docs/schemas/obligation-map-schema-v1.json`.

### Monitor Types

| Monitor | Source Property | Runtime Check |
|---------|----------------|---------------|
| `AgreementMonitor` | Agreement | No two processes in conflicting decision locations simultaneously |
| `InvariantMonitor` | Invariant | Bad location sets never all occupied simultaneously |
| `TerminationMonitor` | Termination | All processes eventually reach goal locations |

## Counterexample Replay

Counter-level traces from BMC can be concretized into process-level traces:

```rust
use tarsier_conformance::replay::concretize_trace;

let runtime_trace = concretize_trace(&counter_trace, &automaton)?;
```

This creates concrete processes from the initial kappa values and replays each counter-level step by moving the appropriate number of processes between locations. The resulting trace can be fed back into the checker for round-trip validation.

## Dependency Boundary

`tarsier-conformance` depends only on:
- `tarsier-ir` (with `serialize` feature)
- `tarsier-dsl`
- `serde`, `serde_json`, `thiserror`

It does **not** depend on `tarsier-smt`, `tarsier-engine`, `tarsier-prob`, or `z3`. This ensures the conformance layer has a minimal trust boundary and can be used independently of the verification infrastructure.
