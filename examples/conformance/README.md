# Conformance Checking: End-to-End Demo

This directory demonstrates Tarsier's conformance checking workflow using the
Reliable Broadcast protocol as a realistic example.

Conformance checking bridges the gap between a **verified protocol model** and
a **real implementation**: it validates that runtime execution traces from your
system follow every transition rule in the formally verified model.

## Prerequisites

```bash
# Build tarsier
cargo build -p tarsier-cli
```

## Step 1: Verify the protocol model

First, verify that the Reliable Broadcast protocol is safe:

```bash
tarsier verify examples/library/reliable_broadcast_safe.trs
```

This proves the agreement property: if any correct process delivers a value,
all correct processes deliver the same value.

## Step 2: Generate a runtime trace

Use the included simulator to produce a trace from a simulated execution:

```bash
# All-honest execution (n=4 processes, t=1 fault tolerance)
python3 examples/conformance/simulator.py --n 4 --t 1 --out /tmp/rb_trace.json

# With 1 Byzantine process
python3 examples/conformance/simulator.py --n 4 --t 1 --byzantine 1 --out /tmp/rb_byz_trace.json
```

The simulator emits JSON traces in Tarsier's runtime trace format, with events
like `Init`, `Receive`, `Transition`, `Send`, and `Decide` for each process.

## Step 3: Check conformance

Validate the trace against the verified model:

```bash
tarsier conformance-check examples/library/reliable_broadcast_safe.trs --trace /tmp/rb_trace.json
```

Expected output: `PASSED`

## Step 4: Detect violations

The `traces/rb_violation_n4_t1.json` file contains a manually crafted trace
where a process illegally skips from `waiting` directly to `done`:

```bash
tarsier conformance-check examples/library/reliable_broadcast_safe.trs \
  --trace examples/conformance/traces/rb_violation_n4_t1.json
```

Expected output:
```
FAILED: 1 violation(s)
  process 0, event 1: NoMatchingRule — no rule from 'Process_waiting[...]' to 'Process_done[...]'
```

## Step 5: Run the full conformance suite

Run all conformance traces (including the SimpleVote fixtures and these
Reliable Broadcast traces) in one command:

```bash
tarsier conformance-suite --manifest examples/conformance/conformance_suite.json
```

## Step 6: Run adapter-family conformance suite

Run the adapter-backed suite (CometBFT + etcd-raft trace families):

```bash
tarsier conformance-suite --manifest examples/conformance/conformance_suite_adapters.json
```

You can also run a single adapter trace directly:

```bash
tarsier conformance-check crates/tarsier-conformance/tests/fixtures/simple_vote.trs \
  --trace examples/conformance/adapters/cometbft_simple_vote_pass.json \
  --adapter cometbft \
  --checker-mode strict
```

## What conformance checking guarantees

When a trace passes conformance checking, you know:

1. **Every transition follows a verified rule** — the process was in the correct
   source location and moved to a valid destination.
2. **Guards were satisfiable** — the message counts at the time of each
   transition met the threshold guards in the model.
3. **No impossible transitions** — the implementation didn't skip phases or
   take transitions that don't exist in the model.

This does **not** replace testing or formal verification of the implementation
itself. It is a lightweight runtime check that your implementation's observable
behavior matches the verified model's transition structure.

## Files in this directory

| File | Description |
|------|-------------|
| `simulator.py` | Python simulator for Reliable Broadcast |
| `traces/rb_safe_n4_t1.json` | Valid trace (n=4, t=1, all honest) |
| `traces/rb_byzantine_n4_t1.json` | Valid trace with 1 Byzantine process |
| `traces/rb_violation_n4_t1.json` | Invalid trace (skips phases) |
| `conformance_suite.json` | Suite manifest for batch checking |
| `conformance_suite_adapters.json` | Adapter replay suite (CometBFT + etcd-raft) |
| `adapters/*.json` | Adapter input fixtures (pass/fail + corruption cases) |
