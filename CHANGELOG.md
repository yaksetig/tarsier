# Changelog

All notable changes to Tarsier will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

#### Core Verification Engine (`tarsier-engine`, `tarsier-smt`)
- Bounded model checking (BMC) with configurable depth for safety properties
- IC3-style unbounded fair PDR engine for liveness checking
- CEGAR loop with automatic refinement (equivocation, authentication, value constraints)
- Partial order reduction with ample-set computation for state-space reduction
- Verification orchestration with timeout management and memory budgets
- Counter abstraction for parameterized threshold automata
- Adversary injection model with per-shared-variable fault bounds
- Multi-solver backend support (Z3, CVC5, SMT-LIB printer)
- Compositional assume-guarantee contract validation for modular protocols
- Counterexample trace extraction with Mermaid, timeline, and markdown rendering
- Runtime sandbox with fail-closed semantics and ByMC `.ta` format export

#### DSL and Parser (`tarsier-dsl`)
- PEG grammar (pest) for `.trs` protocol specification files
- Roles with phases, transition rules, guards, and actions
- Threshold guards with `received >= t+1 MSG` syntax and distinct counting
- Enum types for protocol phases and message values
- Committee selection blocks with population, byzantine, size, and epsilon fields
- Cryptographic objects: certificates, threshold signatures, conflict policies
- Adversary, identity, and channel declarations (equivocation, authentication policies)
- Module and import system with assume-guarantee interfaces
- Property declarations: agreement, validity, safety, invariant, liveness
- Temporal operators: always, eventually, next, until, weak-until, release, leads-to
- Quantified formulas with `forall` and `exists` over roles

#### Intermediate Representation (`tarsier-ir`)
- Threshold automaton IR with locations, transitions, guard atoms, and counter system lowering
- Protocol composition with DAG-based assume-guarantee contract validation
- Runtime trace representation and property-test generators

#### Probabilistic Verification (`tarsier-prob`)
- Hypergeometric tail-bound computation with exact BigInt/BigRational arithmetic
- Committee selection analysis with inverse survival function
- Union bound aggregation for multiple committees
- `ProbabilisticallySafe` result variant with concrete bound parameters

#### Proof Certificates (`tarsier-proof-kernel`, `tarsier-certcheck`)
- Minimal trusted proof kernel (4 dependencies) for certificate validation
- Certificate bundle format v2 with SHA-256 content hashes
- Standalone `tarsier-certcheck` binary for independent certificate verification
- Governance profiles: standard, reinforced, high-assurance
- Ed25519-signed governance bundles with trust report generation
- Multi-solver certificate replay support
- External Alethe proof checking via Carcara integration

#### Conformance Checking (`tarsier-conformance`)
- Runtime trace replay against verified protocol models
- Adapter framework for CometBFT and etcd-raft trace formats
- Obligation map extraction and conformance manifest schema

#### Code Generation (`tarsier-codegen`)
- Rust and Go implementation skeleton generation from `.trs` models
- Runtime trace hooks for conformance checking instrumentation

#### Language Server (`tarsier-lsp`)
- Completion for keywords, parameters, roles, phases, messages, and properties
- Real-time diagnostics from parser errors and verification warnings
- Hover documentation for keywords, declarations, and threshold expressions
- Go-to-definition and find-references for all named symbols
- Rename refactoring across protocol declarations
- Document formatting with configurable indent style
- Inlay hints for threshold guard semantics
- Folding ranges for protocol blocks
- Code actions with quick-fix suggestions and semantic token highlighting
- Document and workspace symbol providers

#### CLI (`tarsier-cli`)
- `prove` command with BMC, PDR, and CEGAR engine selection
- `verify` command for multi-property verification with JSON/text output
- `analyze` command for protocol structure analysis and quantitative reports
- `lint` command with fix suggestions and span-level diagnostics
- `visualize` command for counterexample trace rendering (Mermaid, timeline, markdown)
- `conformance` command for runtime trace checking against specifications
- `codegen` command for Rust/Go skeleton generation
- `compose` command for module composition validation
- `governance` command for certification, trust reports, and governance bundles
- TUI progress display with configurable network semantics and soundness levels

#### VS Code Extension (`editors/vscode`)
- TextMate grammar for `.trs` syntax highlighting
- Language configuration (brackets, comments, auto-closing pairs)
- Snippet library for common protocol patterns
- LSP client integration with `tarsier-lsp` server

#### Playground
- Web-based protocol editor with in-browser verification
- Visual editor for threshold automata construction
- Code generation preview panel

#### CI/CD (`.github/workflows`)
- Multi-platform CI with Z3 static linking (Linux, macOS)
- Fuzz testing pipeline for parser, encoder, lowering, and proof kernel
- Nightly property-based test suite
- Mutation testing workflow
- Benchmark regression detection with budget enforcement
- Release binary builds for Linux and macOS (x86_64, aarch64)
- Release certification workflow with governance profile gates
- Cross-tool verdict parity checks (ByMC, Spin)
- Coverage threshold enforcement
- Doc consistency and schema validation gates

#### Infrastructure
- Dockerfile, devcontainer, and shell installer for reproducible builds
- Homebrew formula (`Formula/tarsier.rb`)
- `cargo-deny` configuration for license and advisory auditing
- JSON schemas for certificates, benchmarks, traces, conformance manifests, and governance bundles
- 49 example `.trs` models covering Paxos, PBFT, HotStuff, Tendermint, Raft, and more
- Conformance example suite with simulator and adapter traces
- `CONTRIBUTING.md`, `SECURITY.md`, and release process documentation
