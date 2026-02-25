# tarsier-certcheck

Multi-solver certificate replay checker.

## Overview

`tarsier-certcheck` is a standalone binary that validates Tarsier proof
certificates by replaying SMT obligations against one or more external solvers.
It is intentionally independent of the verification engine -- its only Tarsier
dependency is `tarsier-proof-kernel` -- so that certificate validity can be
confirmed without trusting the engine that produced the proof. This binary is
distributed as a pre-built artifact (`publish = false`) rather than as a
crates.io library.

## Key Features

- **Multi-solver replay**: Replays each obligation against Z3, CVC5, or both,
  verifying that all solvers agree on the expected result.
- **Integrity validation**: Uses `tarsier-proof-kernel` to check schema version,
  obligation completeness, SHA-256 hashes, and SMT script well-formedness before
  replay.
- **Governance profiles**: Supports `--profile standard`, `--profile reinforced`,
  and `--profile high-assurance` with escalating requirements (multi-solver,
  proof objects, external proof checker).
- **Proof object extraction**: With `--emit-proofs`, captures solver proof
  objects and optionally validates them with an external checker via
  `--proof-checker`.
- **JSON reporting**: Produces machine-readable reports via `--json-report`.

## Usage

```bash
# Basic single-solver replay
tarsier-certcheck certs/my_protocol/ --solvers z3

# Multi-solver replay with both Z3 and CVC5
tarsier-certcheck certs/my_protocol/ --solvers z3,cvc5 --require-two-solvers

# High-assurance replay with proof extraction and external checking
tarsier-certcheck certs/my_protocol/ \
  --profile high-assurance \
  --solvers z3,cvc5 \
  --emit-proofs proofs/ \
  --proof-checker /usr/local/bin/carcara \
  --json-report report.json

# Stop at first failure
tarsier-certcheck certs/my_protocol/ --fail-fast
```

## CLI Options

| Flag                    | Description                                          |
|-------------------------|------------------------------------------------------|
| `--solvers`             | Comma-separated solver commands (default: `z3,cvc5`) |
| `--require-two-solvers` | Require at least two distinct solvers for replay      |
| `--profile`             | Governance profile: `standard`, `reinforced`, `high-assurance` |
| `--emit-proofs DIR`     | Write solver proof objects to the given directory     |
| `--require-proofs`      | Require non-empty proof objects for UNSAT obligations |
| `--proof-checker PATH`  | External proof checker binary                        |
| `--json-report PATH`    | Write a JSON report to the given path                |
| `--fail-fast`           | Stop replay at the first failed obligation           |

## Architecture

The checker is deliberately thin: it delegates all structural validation to
`tarsier-proof-kernel`, then shells out to external solver binaries (z3, cvc5)
for replay. It does not link against Z3 or any SMT library. Solver output is
parsed to extract the sat/unsat/unknown verdict, and optionally proof objects
are captured and validated by an external proof-checker binary.

## Links

- [Workspace overview](../../README.md)
- [Certificate schema](../../docs/CERTIFICATE_SCHEMA.md)
- [Trust boundary](../../docs/TRUST_BOUNDARY.md)
- [Checker soundness argument](../../docs/CHECKER_SOUNDNESS_ARGUMENT.md)
