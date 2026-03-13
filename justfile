set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

# Common build environment needed by z3/cmake integration.
build_env := "CMAKE_POLICY_VERSION_MINIMUM=3.5"

# Show available tasks.
default:
    @just --list

# Run formatting checks.
fmt-check:
    cargo fmt --check

# Format the repository.
fmt:
    cargo fmt --all

# Run clippy with warnings denied.
clippy:
    {{build_env}} cargo clippy --all-targets -- -D warnings

# Run fast compile checks.
check:
    {{build_env}} cargo check --all-targets

# Run all tests.
test:
    {{build_env}} cargo test --all-targets

# Run the deterministic property-pipeline proptest target.
proptest:
    {{build_env}} PROPTEST_CASES=48 PROPTEST_RNG_ALGORITHM=cc PROPTEST_RNG_SEED=246813579 cargo test -p tarsier-engine --test property_pipeline_proptest -- --nocapture

# Run completion evidence validation scripts.
validate:
    python3 scripts/validate_final_completion.py
    python3 scripts/validate_final_completion.py --strict-evidence

# Check rustdoc coverage for externally public Rust APIs.
doc-coverage:
    python3 scripts/check_public_api_doc_coverage.py --min-pct 80

# Guard against oversized production Rust files and functions.
maintainability-guard:
    python3 scripts/check_maintainability_limits.py --base HEAD

# Run the fast generated-artifact drift gate.
artifact-drift:
    python3 scripts/check_generated_artifact_drift.py

# Refresh cert-suite model hashes after protocol edits.
refresh-cert-suite-hashes:
    python3 scripts/update-cert-suite-hashes.py --manifest examples/library/cert_suite.json

# Local "CI-like" gate for common contributor checks.
ci: artifact-drift doc-coverage maintainability-guard fmt-check clippy test

# Summarize multi-agent execution board status.
board-status:
    python3 scripts/board_status.py

# Emit board status as JSON for automation.
board-status-json:
    python3 scripts/board_status.py --json

# Show tasks that are done but still need independent review.
board-review-queue:
    python3 scripts/board_status.py --review-queue

# Show backlog of completed work with review state.
board-done-backlog:
    python3 scripts/board_status.py --done-backlog
