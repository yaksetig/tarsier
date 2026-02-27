# Contributing to Tarsier

Tarsier is a threshold automata verification framework for Byzantine fault-tolerant protocols.

## Development Setup

### Option A: Devcontainer (recommended)

Open the repo in VS Code with the [Dev Containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) extension, or launch a GitHub Codespace. The container installs all dependencies (cmake, build-essential, Z3) and runs `cargo check --workspace` on creation.

### Option B: Manual setup

- **Rust** stable (MSRV 1.92.0) via [rustup](https://rustup.rs)
- **cmake** and **build-essential** -- Z3 is compiled from source by the `z3` crate's `static-link-z3` feature
- **Python 3** -- used by CI contract scripts and cross-tool benchmarks

Set this environment variable before building (required for cmake compatibility):

```sh
export CMAKE_POLICY_VERSION_MINIMUM=3.5
```

Then build:

```sh
cargo build --workspace
```

## Project Architecture

| Crate | Role |
|---|---|
| `tarsier-dsl` | PEG parser (pest) for `.trs` threshold automata specs |
| `tarsier-ir` | Intermediate representation and lowering |
| `tarsier-smt` | SMT encoding (Z3 via `static-link-z3`) |
| `tarsier-prob` | Probabilistic verification (hypergeometric committee bounds) |
| `tarsier-proof-kernel` | Minimal trusted kernel for certificate checking |
| `tarsier-certcheck` | Standalone certificate replay checker (no Z3 dependency) |
| `tarsier-engine` | Verification orchestration: BMC, PDR, CEGAR, POR |
| `tarsier-codegen` | Code generation from verified specs |
| `tarsier-conformance` | Runtime trace conformance checking |
| `tarsier-cli` | User-facing CLI (`tarsier prove`, `tarsier verify`) |
| `tarsier-lsp` | Language server for editor support |

Data flows **DSL** -> **IR** -> **SMT** -> solver -> result. The engine crate orchestrates this pipeline and implements bounded model checking, IC3/PDR, CEGAR refinement, and partial order reduction.

## Running Tests

```sh
# Full test suite
cargo test --workspace

# Single crate
cargo test -p tarsier-engine

# Benchmarks
cargo bench -p tarsier-engine

# Lint (must pass with zero warnings)
cargo clippy --all-targets -- -D warnings
```

## CI Checks

Every PR runs the following (see `.github/workflows/ci.yml`):

- **Build + test** -- `cargo test --all-targets`
- **Clippy** -- `-D warnings`, no warnings allowed
- **Contract checks** -- workspace metadata, documentation consistency, certification gates
- **Property testing** -- proptest with deterministic seeds (minimum 24 cases)
- **Liveness proof gate** -- fair cycle detection tests
- **CEGAR / POR / crypto regression gates** -- verification correctness tests
- **Benchmark smoke tests** -- parser, lowering, encoder benchmarks with `--quick`
- **Cross-tool parity** -- verdict agreement with external model checkers

Nightly/weekly schedules run extended property tests, fuzzing (`cargo-fuzz`), and mutation testing.

### Deterministic drift checks

Run these locally before opening a PR:

```sh
python3 .github/scripts/check_workspace_package_metadata.py
python3 scripts/update-cert-suite-hashes.py --manifest examples/library/cert_suite.json --check
./scripts/check-clean-worktree.sh
```

## Code Style

- Run `cargo fmt` before committing.
- `cargo clippy --all-targets -- -D warnings` must pass.
- Follow existing patterns in the crate you are modifying.
- Prefer `Result` propagation over panics in library/production code.
- Add tests for new functionality. Integration tests go in `tests/` directories; unit tests go in `#[cfg(test)]` modules.

## Submitting Changes

1. Fork the repository and create a feature branch from `main`.
2. Keep PRs focused on a single change.
3. Write a clear PR description covering **what** changed and **why**.
4. Run `cargo fmt` and `cargo clippy --all-targets -- -D warnings`.
5. Ensure all CI checks pass before requesting review.
6. If your change affects verification semantics, add or update tests in `tarsier-engine` and reference the relevant property in `docs/SEMANTICS.md`.

## Adding a New Protocol Model

1. Create a `.trs` file in `examples/library/`.
2. Follow the naming convention: `protocol_name.trs` (safe), `protocol_name_buggy.trs` (buggy), `protocol_name_faithful.trs` (faithful network mode).
3. Add an entry to `examples/library/cert_suite.json` with expected outcomes, `family`, `class`, `notes`, and `model_sha256`.
4. Refresh hashes: `python3 scripts/update-cert-suite-hashes.py --manifest examples/library/cert_suite.json`
5. Run `./scripts/certify-corpus.sh` and the manifest regression tests.

## Reporting Issues

File issues at [GitHub Issues](https://github.com/yaksetig/tarsier/issues) with:
- A minimal `.trs` file reproducing the problem (if applicable).
- The command you ran and the full output.
- Your Rust version (`rustc --version`) and OS.

## Code of Conduct

We follow the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct).
