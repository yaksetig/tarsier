# DAG Workflow Guide

This guide covers modeling and verifying DAG-based consensus protocols in Tarsier. For the syntax reference, see [LANGUAGE_REFERENCE.md, Section 19](LANGUAGE_REFERENCE.md#19-dag-rounds). For general verification workflows, see [ADVANCED_USAGE.md](ADVANCED_USAGE.md).

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [DAG Patterns](#dag-patterns)
4. [Validation Rules](#validation-rules)
5. [Verification Workflows](#verification-workflows)
6. [Troubleshooting](#troubleshooting)
7. [Migration Guide](#migration-guide)

---

## Overview

Many modern consensus protocols (DAG-Rider, Bullshark, Narwhal, Mysticeti) structure their communication rounds as a directed acyclic graph (DAG) rather than a simple linear sequence. In a DAG-based protocol, each round can depend on multiple prior rounds, and independent rounds can execute concurrently.

### When to use DAG rounds

| Scenario | Model |
|---|---|
| Rounds execute strictly one after another | Linear phases (standard `phase` blocks) |
| Rounds have branching or merging dependencies | `dag_round` declarations |
| Multiple independent proposal streams merge at a decision point | `dag_round` with multi-root pattern |
| Protocol combines DAG structure with threshold voting | `dag_round` + standard messages and guards |

DAG round declarations are metadata that capture the structural dependency graph of the protocol. They are validated at lowering time and made available to the verification engine alongside the threshold automaton.

---

## Quick Start

Here is a minimal DAG protocol with three rounds forming a chain:

```trs
protocol SimpleDAG {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }

    dag_round r0;
    dag_round r1 extends r0;
    dag_round r2 extends r1;

    message Vote;

    role Node {
        var decided: bool = false;
        init propose;

        phase propose {
            when received >= n - t Vote => {
                goto phase done;
            }
        }
        phase done {}
    }

    property inv: invariant {
        forall p: Node. p.decided == false
    }
}
```

Key elements:

- `dag_round r0;` declares a root round (no parents).
- `dag_round r1 extends r0;` declares `r1` with a dependency on `r0`.
- The `extends` keyword lists one or more parent rounds that must complete before this round proceeds.
- The rest of the protocol (roles, messages, guards, properties) uses standard Tarsier syntax.

Verify with:

```bash
tarsier analyze my_dag_protocol.trs --mode standard
```

---

## DAG Patterns

### Linear chain

Sequential rounds where each depends on its predecessor. This is equivalent to traditional round-based execution but expressed as a DAG.

```trs
dag_round r0;
dag_round r1 extends r0;
dag_round r2 extends r1;
dag_round r3 extends r2;
dag_round r4 extends r3;
```

Structure: `r0 -> r1 -> r2 -> r3 -> r4`

Use this when your protocol has a strict round ordering but you want to express it within the DAG framework for consistency with other DAG-based models.

Full example: [`examples/experimental/dag_deep_chain_safe.trs`](../examples/experimental/dag_deep_chain_safe.trs)

### Diamond pattern

Two rounds branch from a common ancestor and later merge at a join point. This models protocols where independent sub-tasks (e.g., propose and certify) run in parallel after an initial round, then synchronize.

```trs
dag_round r0;
dag_round r1 extends r0;
dag_round r2 extends r0;
dag_round r3 extends r1, r2;
```

Structure:
```
    r0
   /  \
  r1   r2
   \  /
    r3
```

`r1` and `r2` both depend on `r0` and can proceed independently. `r3` waits for both `r1` and `r2` to complete.

Full example: [`examples/experimental/dag_diamond_safe.trs`](../examples/experimental/dag_diamond_safe.trs)

### Multi-root

Multiple independent root rounds that merge downstream. This models protocols with independent proposal streams (e.g., separate leaders or shards) that converge at a decision point.

```trs
dag_round r0;
dag_round r1;
dag_round r2 extends r0, r1;
```

Structure:
```
  r0   r1
   \  /
    r2
```

Both `r0` and `r1` are roots (no `extends` clause). `r2` depends on both, merging the two independent streams.

Full example: [`examples/experimental/dag_multi_root_safe.trs`](../examples/experimental/dag_multi_root_safe.trs)

### Deep chain

Long sequential dependency chains for protocols with many rounds (e.g., pipelined consensus with deep commit pipelines).

```trs
dag_round r0;
dag_round r1 extends r0;
dag_round r2 extends r1;
dag_round r3 extends r2;
dag_round r4 extends r3;
```

This is structurally a linear chain but tests that the validator handles arbitrarily deep parent chains correctly. There is no practical depth limit imposed by Tarsier.

Full example: [`examples/experimental/dag_deep_chain_safe.trs`](../examples/experimental/dag_deep_chain_safe.trs)

---

## Validation Rules

Tarsier validates the DAG structure during lowering and rejects malformed graphs with actionable error messages. All validation runs automatically when you parse and verify a `.trs` file.

### 1. Cycle detection

The DAG must be acyclic. Tarsier runs a depth-first search and reports the cycle path if one is found.

**Invalid input:**
```trs
dag_round r0 extends r1;
dag_round r1 extends r0;
```

**Error:**
```
dag_round dependency cycle: r0 -> r1 -> r0
```

The error shows the full path of the cycle so you can identify where to break it.

### 2. Self-loop rejection

A round cannot list itself as a parent.

**Invalid input:**
```trs
dag_round r0 extends r0;
```

**Error:**
```
dag_round 'r0' lists itself as a parent (self-loop)
```

Full example: [`examples/experimental/dag_self_loop_invalid.trs`](../examples/experimental/dag_self_loop_invalid.trs)

### 3. Duplicate parent detection

A round cannot list the same parent more than once.

**Invalid input:**
```trs
dag_round r0;
dag_round r1 extends r0, r0;
```

**Error:**
```
dag_round 'r1' lists parent 'r0' more than once
```

### 4. Unknown parent detection

Every parent referenced in `extends` must be a declared `dag_round`. The error message includes the list of declared rounds to help you spot typos.

**Invalid input:**
```trs
dag_round r0;
dag_round r1 extends r0, r2;
```

**Error:**
```
dag_round 'r1' references unknown parent 'r2'; declared rounds: [r0, r1]
```

### 5. Root requirement

At least one round must have no parents (be a root). A DAG where every round has at least one parent is rejected.

**Invalid input:**
```trs
dag_round r0 extends r1;
dag_round r1 extends r0;
```

**Error:**
```
dag_round graph has no root rounds (every round has parents); at least one root round with no parents is required
```

Note: In practice, this case is also caught by cycle detection, but the root check provides a more direct diagnostic.

### 6. Connectivity requirement

Every non-root round must be reachable from at least one root via the parent-child edges. Disconnected subgraphs are rejected.

**Error:**
```
dag_round(s) [r3, r4] are not reachable from any root round [r0]
```

### Validation order

Checks run in this order: duplicate names, self-loops, unknown parents, duplicate parents, cycles, root existence, connectivity. The first failing check produces the error; subsequent checks are skipped.

---

## Verification Workflows

DAG protocols use the same verification commands as standard protocols. The DAG structure is validated during lowering, then the threshold automaton is checked with the usual engines.

### BMC safety checking

Bounded model checking for safety property violations:

```bash
# Quick bug scan
tarsier analyze my_dag_protocol.trs --mode quick

# Standard bounded safety check
tarsier analyze my_dag_protocol.trs --mode standard

# Direct BMC with explicit depth
tarsier verify my_dag_protocol.trs --depth 10
```

### K-induction unbounded proofs

Prove safety properties hold for all reachable states:

```bash
# Automated proof (runs both k-induction and PDR)
tarsier analyze my_dag_protocol.trs --mode proof

# Explicit k-induction
tarsier prove my_dag_protocol.trs --k 12 --engine kinduction

# PDR engine
tarsier prove my_dag_protocol.trs --k 12 --engine pdr
```

For protocols that need invariant strengthening:

```bash
tarsier infer-invariants my_dag_protocol.trs --solver z3 --depth 12
tarsier prove my_dag_protocol.trs --k 12 --engine kinduction --auto-strengthen
```

### Refinement checking with DAG protocols

Compare a DAG-based protocol against a simpler abstract model or check equivalence between DAG variants:

```bash
# Check that a concrete DAG protocol refines an abstract specification
tarsier refinement-check concrete_dag.trs --abstract-file abstract.trs --depth 12

# Check behavioral equivalence between two DAG protocol variants
tarsier equivalence-check dag_v1.trs --other dag_v2.trs --depth 12
```

### CI integration

```bash
# Fast CI gate for DAG protocols
tarsier analyze my_dag_protocol.trs --profile ci-fast --format json

# Full proof gate
tarsier analyze my_dag_protocol.trs --profile ci-proof --format json

# Release gating with certificates
tarsier analyze my_dag_protocol.trs --profile release-gate --format json --report-out release/
```

---

## Troubleshooting

### "dag_round dependency cycle" error

**Symptom:** Lowering fails with a cycle path like `r0 -> r1 -> r0`.

**Fix:** Examine the reported path and remove or redirect one of the `extends` references to break the cycle. DAG protocols must have a topological ordering.

### "references unknown parent" error

**Symptom:** Lowering fails with `dag_round 'r2' references unknown parent 'r1'; declared rounds: [r0, r2]`.

**Fix:** Check for typos in the parent name. The error message lists all declared rounds. Either fix the typo or add the missing `dag_round` declaration.

### "lists itself as a parent" error

**Symptom:** `dag_round 'r0' lists itself as a parent (self-loop)`.

**Fix:** Remove the self-reference from the `extends` clause. If the round has no other parents, omit `extends` entirely to make it a root.

### "lists parent more than once" error

**Symptom:** `dag_round 'r1' lists parent 'r0' more than once`.

**Fix:** Remove the duplicate entry from the `extends` list.

### "no root rounds" error

**Symptom:** `dag_round graph has no root rounds (every round has parents)`.

**Fix:** At least one `dag_round` must have no `extends` clause. Identify the entry point(s) of your protocol and remove their parent references.

### "not reachable from any root round" error

**Symptom:** `dag_round(s) [r3] are not reachable from any root round [r0]`.

**Fix:** The listed rounds form a disconnected subgraph. Either add `extends` edges connecting them to the main graph or declare them as additional roots if they represent independent entry points.

---

## Migration Guide

### Converting linear round-based protocols to DAG form

If your existing protocol uses sequential phases and you want to express it as a DAG (for instance, as a stepping stone toward modeling a full DAG-based protocol), add `dag_round` declarations that mirror the phase ordering.

**Before (linear phases only):**
```trs
protocol MyProtocol {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }

    role Node {
        var decided: bool = false;
        init round1;

        phase round1 {
            when received >= n - t Vote => {
                goto phase round2;
            }
        }
        phase round2 {
            when received >= n - t Commit => {
                goto phase decided;
            }
        }
        phase decided {}
    }

    // ...
}
```

**After (with DAG round metadata):**
```trs
protocol MyProtocol {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }

    dag_round r1;
    dag_round r2 extends r1;
    dag_round r3 extends r2;

    role Node {
        var decided: bool = false;
        init round1;

        phase round1 {
            when received >= n - t Vote => {
                goto phase round2;
            }
        }
        phase round2 {
            when received >= n - t Commit => {
                goto phase decided;
            }
        }
        phase decided {}
    }

    // ...
}
```

### Introducing parallelism

Once you have the linear DAG, identify rounds that can run concurrently and restructure:

```trs
// Before: r1 -> r2 -> r3 -> r4
dag_round r1;
dag_round r2 extends r1;
dag_round r3 extends r2;
dag_round r4 extends r3;

// After: r2 and r3 run in parallel after r1, then merge at r4
dag_round r1;
dag_round r2 extends r1;
dag_round r3 extends r1;
dag_round r4 extends r2, r3;
```

### Adding multiple entry points

If your protocol has independent initialization streams (e.g., separate leader election and data availability):

```trs
dag_round leader_election;
dag_round data_availability;
dag_round propose extends leader_election, data_availability;
dag_round commit extends propose;
```

Both `leader_election` and `data_availability` are roots that proceed independently before merging at `propose`.
