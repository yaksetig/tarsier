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

| Command                    | Description                                            |
|----------------------------|--------------------------------------------------------|
| `analyze`                  | Goal-directed analysis: `--goal bughunt\|safety\|safety+liveness\|release` |
| `verify`                   | Bounded model checking (BMC) at a given depth          |
| `prove`                    | Unbounded safety proof via k-induction or PDR          |
| `prove-fair`               | Unbounded liveness proof under weak/strong fairness    |
| `prove-round`              | Safety proof via round-erasure over-approximation      |
| `round-sweep`              | Sweep round/view bounds and report verdict convergence |
| `lint`                     | Static analysis and lint checks on a `.trs` file       |
| `assist`                   | Generate a starter `.trs` template for a protocol kind |
| `codegen`                  | Generate Rust or Go implementation from a `.trs` model |
| `visualize`                | Render automaton as Mermaid diagram or timeline         |
| `export-ta`                | Export threshold automaton in ByMC `.ta` format         |
| `conformance-check`        | Check a runtime trace against a protocol model         |
| `conformance-suite`        | Run a conformance test suite from a manifest           |
| `conformance-obligations`  | Generate runtime monitoring obligations                |
| `conformance-replay`       | Replay a counter-level trace as process-level events   |
| `certify-safety`           | Produce a safety proof certificate bundle              |
| `certify-fair-liveness`    | Produce a fair-liveness proof certificate bundle       |
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
