# Tarsier

[![CI](https://github.com/yaksetig/tarsier/actions/workflows/ci.yml/badge.svg)](https://github.com/yaksetig/tarsier/actions/workflows/ci.yml)
[![docs](https://img.shields.io/badge/docs-rustdoc-blue)](https://yaksetig.github.io/tarsier/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Tarsier is a formal verification tool for BFT consensus protocols. Write your protocol in a simple `.trs` DSL, and Tarsier checks safety and liveness — even under Byzantine faults.

Under the hood it models protocols as **threshold automata** and uses **SMT-based bounded model checking** plus **k-induction/IC3** for unbounded proofs.

## Installation

```bash
# Shell installer (Linux/macOS)
curl -fsSL https://raw.githubusercontent.com/yaksetig/tarsier/main/install.sh | sh

# Homebrew (macOS)
brew tap yaksetig/tarsier && brew install tarsier

# Or build from source
git clone https://github.com/yaksetig/tarsier.git && cd tarsier
CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo build --release
```

Pre-built binaries are available on [GitHub Releases](https://github.com/yaksetig/tarsier/releases).

## Quick Start — Three Commands

```bash
# 1. Scaffold a protocol from a template
tarsier assist --kind hotstuff --out my_protocol.trs

# 2. Verify safety
tarsier analyze my_protocol.trs --goal safety

# 3. Visualize counterexamples if bugs are found
tarsier visualize my_protocol.trs --check verify --format markdown --out cex.md
```

That's it. `analyze` is the primary entry point — it picks sane defaults so you don't need to think about solver flags, depth, or engine selection.

### Goals and Profiles

**Goals** select what to check: `bughunt`, `safety`, `safety+liveness`, `release`.
**Profiles** select expertise level: `beginner` (default), `pro`, `governance`, `ci-fast`, `ci-proof`, `release-gate`.

```bash
# CI fast gate
tarsier analyze my_protocol.trs --profile ci-fast --format json

# Advanced usage with explicit knobs
tarsier analyze my_protocol.trs --profile pro --depth 20 --k 16 --timeout 600
```

## DSL at a Glance

```trs
params n, t, f;
resilience: n = 3*f + 1;

adversary {
    model: byzantine;
    bound: f;
    equivocation: full;
}

var view: int in 0..5 = 0;
message Vote(view: int in 0..5);

when received distinct >= 2*t+1 Vote(view=view) => {
    decide true;
}

property agreement: safety {
    forall p1: Replica, p2: Replica.
        (p1.decided == true && p2.decided == true) => p1.decision == p2.decision
}
```

See the [Language Reference](docs/LANGUAGE_REFERENCE.md) for the complete DSL syntax.

## What It Can Check

- **Safety** — agreement, invariants, bounded and unbounded (k-induction, IC3/PDR)
- **Liveness** — bounded and unbounded fair-liveness (weak/strong fairness)
- **Temporal properties** — `[]`, `<>`, `X`, `U`, `W`, `R`, `~>` operators
- **Multiple fault models** — Byzantine, omission, crash
- **Cryptographic objects** — certificates, threshold signatures (`form`/`has`/`lock`/`justify`)
- **Partial synchrony** — explicit GST modeling
- **Proof certificates** — cross-solver validated, governance-grade bundles
- **CEGAR refinement** — adaptive counterexample-guided abstraction
- **Protocol library** — 25+ models (PBFT, HotStuff, Tendermint, Raft, Paxos, and more)

## Developer UX

```bash
tarsier lint my_protocol.trs --soundness strict    # Semantic linting
tarsier debug-cex buggy.trs --check verify          # Interactive counterexample replay
tarsier explore buggy.trs                            # TUI trace explorer
tarsier export-dot my_protocol.trs --svg --out a.svg # Graphviz automaton export
tarsier assist --kind pbft --out new.trs             # Scaffold from template
```

There's also a [VS Code extension](docs/TUTORIAL.md#13-vs-code-extension) with syntax highlighting, LSP diagnostics, and snippets, and a local [web playground](#web-playground).

## Web Playground

```bash
cargo run -p tarsier-playground
# Open http://127.0.0.1:7878
```

## Documentation

| Document | Description |
|----------|-------------|
| **[Getting Started](docs/GETTING_STARTED.md)** | **End-to-end walkthrough: install, write, verify, debug** |
| [Tutorial](docs/TUTORIAL.md) | Detailed feature-by-feature guide |
| [Example Catalog](docs/EXAMPLE_CATALOG.md) | Annotated guide to all 48 example protocols |
| [Language Reference](docs/LANGUAGE_REFERENCE.md) | Complete DSL syntax and semantics |
| [Advanced Usage](docs/ADVANCED_USAGE.md) | CI integration, governance, certificates, CEGAR, benchmarks |
| [Parameterized Verification](docs/PARAMETERIZED_VERIFICATION.md) | When results generalize beyond fixed parameters |
| [Semantics](docs/SEMANTICS.md) | Formal semantics and soundness assumptions |
| [Trust Boundary](docs/TRUST_BOUNDARY.md) | What is trusted vs. independently verified |
| [Architecture](docs/ARCHITECTURE.md) | 12-crate pipeline map and trust boundary overview |
| [Migration Guide](docs/MIGRATION.md) | Legacy command mapping to V2 `analyze` workflow |
| [API Stability](docs/API_STABILITY.md) | SemVer guarantees and compatibility policy |
| [Certificate Schema](docs/CERTIFICATE_SCHEMA.md) | Proof certificate bundle format |

## Development

```bash
just ci           # Full CI suite
just test         # Unit/integration tests
just clippy       # Lints
just proptest     # Property-based randomized pipeline tests
```

## Current Boundary

Tarsier is a threshold-automata symbolic checker. Unbounded safety uses k-induction and IC3/PDR. Unbounded fair-liveness uses fair-cycle IC3/PDR. Cryptographic claims are symbolic, not computational — see [Semantics](docs/SEMANTICS.md) and [Trust Boundary](docs/TRUST_BOUNDARY.md).

## License

[MIT](LICENSE)
