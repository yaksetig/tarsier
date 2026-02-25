# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Criterion microbenchmarks for parser, lowering, and SMT encoder subsystems.
- Cross-platform CI: macOS test runner for build, clippy, and tests.
- Benchmark smoke step in CI to validate benchmarks compile and execute.
- Parse-time validation for adversary block keys (typos now caught at parse time, not lowering).
- Error on unsupported declarations inside `module {}` blocks (previously silently dropped).
- Example `.trs` files for enum types, cohort-selective, and process-selective network modes.
- `CONTRIBUTING.md` with build, test, and contribution guidelines.
- Import file resolution: `import Name from "path.trs";` now loads and merges declarations from referenced files.
- Crate-level rustdoc (`//!`) for all 9 library crates.

### Fixed

- `compose-check` now properly lowers module interface assumptions to IR parameter constraints (previously hardcoded `0 >= 0`).
- LSP server no longer panics on poisoned RwLock; all lock operations use graceful fallback instead of `.unwrap()`.

### Changed

- Portfolio solver now uses channel-based first-result-wins racing instead of sequential join.
- Replaced placeholder `your-org/tarsier` URLs with `yaksetig/tarsier` across all docs, scripts, and manifests.
- Added `description`, `rust-version`, `repository`, and `publish = false` metadata to all Cargo.toml files.
- Moved workflow artifacts (`FINAL_COMPLETION_*.json`, `AGENT_EXECUTION_TICKETS.yaml`) from `docs/` to `.github/workflow-data/` to keep user-facing docs clean.

## [0.1.0] - 2026-02-22

### Added

- Tarsier DSL (`.trs`) with PEG parser: protocols, roles, phases, threshold guards, adversary models, properties.
- Threshold automaton lowering with location expansion, rule generation, shared-variable allocation.
- Four network abstraction modes: classic, identity-selective, cohort-selective, process-selective.
- First-class cryptographic objects: certificates, threshold signatures with non-forgeability constraints.
- SMT encoding to QF_LIA with Z3 and cvc5 backends.
- Bounded model checking (BMC) for safety bug-finding.
- $k$-induction for unbounded safety proofs.
- Property-directed reachability (PDR/IC3) for automatic invariant discovery.
- CEGAR with predicate refinement.
- Portfolio multi-solver mode (Z3 + cvc5 in parallel).
- Static and dynamic partial-order reduction.
- Symmetry reduction for PDR cubes.
- Bounded and fair liveness checking (weak/strong fairness).
- Proof certificate generation and validation with minimal proof kernel (4 dependencies).
- Multi-solver certificate replay via `tarsier-certcheck`.
- Hypergeometric committee analysis for probabilistic safety (`tarsier-prob`).
- Code generation for Rust and Go (`tarsier-codegen`).
- Runtime conformance checking (`tarsier-conformance`).
- Language Server Protocol implementation (`tarsier-lsp`).
- Interactive counterexample explorer (TUI).
- ByMC `.ta` and SPIN Promela export.
- Protocol library: 44+ models across 14 families (PBFT, HotStuff, Tendermint, Paxos, Algorand, and more).
- Playground security hardening: request limits, rate limiting, auth, CORS, timeout enforcement.
- Release artifact signing with Cosign (keyless OIDC).
- SPDX SBOM generation for all release artifacts.
- SLSA build provenance attestations via GitHub Artifact Attestations.
- Dependency vulnerability scanning via `cargo-deny`.
- `SECURITY.md` vulnerability disclosure policy.
