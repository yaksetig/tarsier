# tarsier-conformance

Runtime conformance checking against protocol specifications.

## Overview

`tarsier-conformance` verifies that a concrete protocol implementation conforms
to its verified `.trs` specification by replaying execution traces against the
threshold automaton model. It checks that every observed state transition
corresponds to a valid rule in the automaton, that guards are satisfied, and
that no process enters an illegal state. This closes the gap between the
formally verified model and a real-world implementation.

## Key Types / API

- `checker::CheckResult` -- Outcome of a conformance check: `passed` flag and
  a list of `Violation` instances.
- `checker::Violation` -- A single conformance violation: process ID, event
  sequence number, `ViolationKind`, and a human-readable message.
- `checker::ViolationKind` -- Enum of violation types: `InvalidInitialLocation`,
  `NoMatchingRule`, `GuardNotSatisfied`, `InvalidTransitionTarget`,
  `UnknownLocation`, `UnknownMessageType`, `InvalidDecideContext`.
- `checker::ConformanceMode` -- Strictness level: `Permissive` or `Strict`.
- `replay::concretize_trace(counter_trace, automaton)` -- Convert a
  counter-level counterexample trace into a process-level `RuntimeTrace`.
- `manifest::ConformanceManifest` -- Test suite manifest describing
  protocol-trace pairs and expected outcomes.
- `obligations::ObligationMap` -- Machine-readable mapping from verified
  properties to runtime monitoring obligations.
- `obligations::generate_obligation_map(automaton, name, properties)` --
  Generate runtime monitoring obligations from verified safety properties.
- `adapters` module -- Trace format adapters for different systems (native
  runtime traces, CometBFT, etcd-raft).

## Usage

```bash
# Check a single trace against a model
tarsier conformance-check protocol.trs --trace execution.json

# Run a full conformance test suite from a manifest
tarsier conformance-suite manifest.json

# Generate runtime monitoring obligations
tarsier conformance-obligations protocol.trs --out obligations.json
```

## Architecture

The checker replays each process event in the trace against the threshold
automaton's transition relation. For each event, it verifies that the source
location matches the process's current state, that threshold guards evaluate
to true given the current counter values, and that the destination location
matches the rule's target. Adapter modules normalize traces from different
runtime systems into the common `RuntimeTrace` format before checking.

## Links

- [Workspace overview](../../README.md)
- [Conformance documentation](../../docs/CONFORMANCE.md)
- [Conformance manifest schema](../../docs/CONFORMANCE_MANIFEST_SCHEMA.md)
