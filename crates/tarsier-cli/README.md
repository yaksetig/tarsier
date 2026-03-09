# tarsier-cli

Formal verification tool for distributed consensus protocols.

## Overview

`tarsier-cli` is the main command-line interface for the Tarsier verification
framework. It provides subcommands for every stage of the workflow: quick bug
hunting, unbounded safety and liveness proofs, code generation, conformance
checking, visualization, and proof certification. The recommended entry point
for new users is `tarsier analyze`, which automatically selects and runs the
appropriate verification strategy.

## Subcommands

### Primary

| Command                    | Description                                            |
|----------------------------|--------------------------------------------------------|
| `analyze`                  | Goal-directed analysis: `--goal bughunt\|safety\|safety+liveness\|release` |
| `assist`                   | Generate a starter `.trs` template for a protocol kind |
| `watch`                    | Watch a `.trs` file for changes and re-verify on save  |

### Bounded Verification

| Command                    | Description                                            |
|----------------------------|--------------------------------------------------------|
| `verify`                   | Bounded model checking (BMC) at a given depth          |
| `liveness`                 | Bounded liveness checking at a given depth             |
| `fair-liveness`            | Bounded liveness checking under fairness constraints   |

### Unbounded Verification

| Command                    | Description                                            |
|----------------------------|--------------------------------------------------------|
| `prove`                    | Unbounded safety proof via k-induction or PDR          |
| `prove-fair`               | Unbounded liveness proof under weak/strong fairness    |
| `prove-round`              | Safety proof via round-erasure over-approximation      |
| `prove-fair-round`         | Fair liveness proof via round-erasure over-approximation |
| `round-sweep`              | Sweep round/view bounds and report verdict convergence |

### Invariants

| Command                    | Description                                            |
|----------------------------|--------------------------------------------------------|
| `infer-invariants`         | Automatically infer inductive invariants from the model |

### Relational Verification

| Command                    | Description                                            |
|----------------------------|--------------------------------------------------------|
| `refinement-check`         | Check that one protocol refines another                |
| `equivalence-check`        | Check behavioral equivalence between two protocols     |
| `compose-check`            | Check safety of a composed multi-protocol system       |

### Counterexample Tools

| Command                    | Description                                            |
|----------------------------|--------------------------------------------------------|
| `visualize`                | Render automaton as Mermaid diagram or timeline         |
| `debug-cex`                | Interactively inspect a counterexample trace           |
| `explore`                  | Explore the reachable state space interactively        |

### Conformance Checking

| Command                    | Description                                            |
|----------------------------|--------------------------------------------------------|
| `conformance-check`        | Check a runtime trace against a protocol model         |
| `conformance-replay`       | Replay a counter-level trace as process-level events   |
| `conformance-obligations`  | Generate runtime monitoring obligations                |
| `conformance-suite`        | Run a conformance test suite from a manifest           |
| `conformance-active`       | Run active conformance testing against a live endpoint |

### Code Generation & Export

| Command                    | Description                                            |
|----------------------------|--------------------------------------------------------|
| `codegen`                  | Generate Rust or Go implementation from a `.trs` model |
| `export-dot`               | Export automaton as a Graphviz DOT graph                |
| `export-ta`                | Export threshold automaton in ByMC `.ta` format         |
| `proof-export`             | Export a completed proof in a portable format           |

### Certification

| Command                    | Description                                            |
|----------------------------|--------------------------------------------------------|
| `certify-safety`           | Produce a safety proof certificate bundle              |
| `certify-fair-liveness`    | Produce a fair-liveness proof certificate bundle       |
| `check-certificate`        | Verify a previously generated proof certificate        |
| `cert-suite`               | Run a suite of certification checks (requires `governance` feature) |

### Governance

| Command                    | Description                                            |
|----------------------------|--------------------------------------------------------|
| `generate-trust-report`    | Generate a trust report for a verified protocol (requires `governance` feature) |
| `governance-pipeline`      | Run the full governance certification pipeline (requires `governance` feature) |
| `verify-governance-bundle` | Verify a signed governance bundle (requires `governance` feature) |

### Static Analysis

| Command                    | Description                                            |
|----------------------------|--------------------------------------------------------|
| `lint`                     | Static analysis and lint checks on a `.trs` file       |
| `comm`                     | Analyze communication patterns in the protocol         |
| `committee`                | Analyze committee selection and probabilistic bounds    |

### Developer Utilities

| Command                    | Description                                            |
|----------------------------|--------------------------------------------------------|
| `parse`                    | Parse a `.trs` file and print the AST                  |
| `show-ta`                  | Display the lowered threshold automaton                |
| `completions`              | Generate shell completion scripts                      |

## Usage

```bash
# Quick bug hunt (recommended starting point)
tarsier analyze protocol.trs --goal bughunt

# Full safety + liveness analysis
tarsier analyze protocol.trs --goal safety+liveness

# Bounded verification at depth 15
tarsier verify protocol.trs --depth 15

# Unbounded safety proof via PDR
tarsier prove protocol.trs --engine pdr --k 12

# Generate Rust implementation
tarsier codegen protocol.trs --target rust --out protocol_generated.rs

# Produce a proof certificate
tarsier certify-safety protocol.trs --out certs/protocol
```

## Features

| Feature      | Description                                             |
|--------------|---------------------------------------------------------|
| `governance` | Enables the `governance-pipeline` subcommand and trust report generation. Adds `ring` dependency for cryptographic signing. |

## Architecture

The CLI is built with `clap` (derive API) and delegates all verification logic
to `tarsier-engine`. Output formatting uses `miette` for rich error diagnostics.
The optional TUI mode (via `ratatui` + `crossterm`) provides interactive
progress display during long-running proofs. Shell completions are generated
with `clap_complete`.

## Links

- [Workspace overview](../../README.md)
- [Getting started](../../docs/GETTING_STARTED.md)
- [Tutorial](../../docs/TUTORIAL.md)
- [Language reference](../../docs/LANGUAGE_REFERENCE.md)
