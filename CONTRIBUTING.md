# Contributing to Tarsier

Thank you for your interest in contributing to Tarsier! This document provides guidelines for contributing to the project.

## Getting Started

### Prerequisites

- **Rust** 1.92.0 or later (install via [rustup](https://rustup.rs/))
- **cmake**: required to build the Z3 solver backend
  - macOS: `brew install cmake`
  - Ubuntu/Debian: `sudo apt install cmake`

### Building

```bash
git clone https://github.com/tarsier-verify/tarsier.git
cd tarsier
CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo build
```

### Running Tests

```bash
# Full test suite
CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo test --all-targets

# Single crate
CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo test -p tarsier-engine

# Python benchmark tests
python3 -m pytest benchmarks/ -v
```

### Formatting and Linting

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

## Project Structure

Tarsier is organized as a Cargo workspace:

| Crate | Purpose |
|-------|---------|
| `tarsier-dsl` | PEG parser for `.trs` protocol specifications |
| `tarsier-ir` | Intermediate representation and lowering to threshold automata |
| `tarsier-smt` | SMT encoding and solver backends (Z3, cvc5) |
| `tarsier-engine` | Verification pipeline: BMC, k-induction, PDR, CEGAR |
| `tarsier-prob` | Hypergeometric probability analysis for committees |
| `tarsier-proof-kernel` | Minimal proof certificate validator |
| `tarsier-certcheck` | Multi-solver certificate replay checker |
| `tarsier-codegen` | Code generation from verified specifications |
| `tarsier-conformance` | Runtime trace conformance checking |
| `tarsier-cli` | Command-line interface |
| `tarsier-lsp` | Language Server Protocol implementation |

## Adding a New Protocol Model

1. Create a `.trs` file in `examples/library/`.
2. Follow the naming convention: `protocol_name.trs` (safe variant), `protocol_name_buggy.trs` (buggy variant), `protocol_name_faithful.trs` (faithful network mode variant).
3. Add an entry to `examples/library/cert_suite.json` with:
   - at least one expected outcome (`verify`/`liveness`/`fair_liveness`/`prove`/`prove_fair`);
   - `family`, `class`, non-empty `notes`, and `model_sha256`.
4. Refresh/verify manifest hashes:
   `python3 scripts/update-cert-suite-hashes.py --manifest examples/library/cert_suite.json`
5. Verify the full corpus gate passes:
   `./scripts/certify-corpus.sh`
6. Run manifest-focused regression tests:
   `cargo test -p tarsier-engine --test integration_tests manifest_ -- --nocapture`

### Required Review Checklist (Corpus Changes)

For PRs touching `examples/library/` or `examples/library/cert_suite.json`, include:

1. New/changed model file(s) listed.
2. Matching manifest entry updates (expected outcomes + rationale + hash).
3. Known-bug sentinel impact noted (`class=known_bug` entries preserved or intentionally updated).
4. Variant-pair impact noted (`minimal`/`faithful` groups stay complete where relevant).
5. Output of `./scripts/certify-corpus.sh` and `manifest_` tests attached in PR description.

## Submitting Changes

1. Fork the repository and create a feature branch.
2. Make your changes, ensuring all tests pass.
3. Run `cargo fmt` and `cargo clippy --all-targets -- -D warnings`.
4. Submit a pull request with a clear description of the changes.

## Reporting Issues

Please file issues at [GitHub Issues](https://github.com/tarsier-verify/tarsier/issues) with:
- A minimal `.trs` file reproducing the problem (if applicable).
- The command you ran and the full output.
- Your Rust version (`rustc --version`) and OS.

## Code of Conduct

Be respectful and constructive. We follow the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct).
