#!/usr/bin/env bash
set -euo pipefail

echo "[codegen-parity] Running model-vs-generated trace oracle suite"
cargo test -p tarsier-codegen --test trace_oracle
cargo test -p tarsier-codegen --test semantic_rust
cargo test -p tarsier-codegen --test semantic_go

echo "[codegen-parity] Running clippy on semantic suites"
cargo clippy -p tarsier-codegen --test semantic_rust -- -D warnings
cargo clippy -p tarsier-codegen --test semantic_go -- -D warnings

echo "[codegen-parity] OK"
