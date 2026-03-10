# Contributing to Tarsier

Tarsier is a threshold automata verification framework for Byzantine fault-tolerant protocols.

## Prerequisites

- **Rust 1.92+** via [rustup](https://rustup.rs) (see `rust-toolchain.toml`)
- **cmake** and **build-essential** for Z3 static compilation
- **Python 3** for CI contract scripts

Set this before building:

```sh
export CMAKE_POLICY_VERSION_MINIMUM=3.5
```

## Building

```sh
cargo build --workspace
```

## Testing

```sh
cargo test --workspace

# Single crate
cargo test -p tarsier-engine

# Documentation consistency + link audit
python3 .github/scripts/check_doc_consistency.py

# Full local CI gate (requires just)
just ci
```

## Running

```sh
cargo run -- <command>
# e.g. cargo run -- prove examples/library/ben_or_safe.trs
```

## Code Style

- Run `cargo fmt` before committing.
- Run `cargo clippy --all-targets -- -D warnings` (must pass with zero warnings).
- Follow existing patterns in the crate you are modifying.
- Prefer `Result` propagation over panics in library code.
- Add tests for new functionality.

## PR Process

1. Create a feature branch from `main`.
2. Keep PRs focused on a single change.
3. Run `cargo fmt` and `cargo clippy --all-targets -- -D warnings`.
4. Run `cargo test --workspace` and ensure all checks pass.
5. Write a clear PR description covering what changed and why.
6. If your change affects verification semantics, add or update tests and reference `docs/SEMANTICS.md`.

## Adding Protocol Models

1. Create a `.trs` file in `examples/library/`.
2. Add an entry to `examples/library/cert_suite.json`.
3. Refresh hashes: `python3 scripts/update-cert-suite-hashes.py --manifest examples/library/cert_suite.json`

## Reporting Issues

File issues with a minimal `.trs` reproducer, the command and output, and your Rust/OS version.

## Code of Conduct

We follow the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct).
