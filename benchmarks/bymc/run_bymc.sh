#!/bin/bash
# Wrapper script for running ByMC verification.
#
# Detection order:
#   1. verifypa-schema on PATH -> run locally
#   2. tarsier-bymc:latest Docker image -> docker run
#   3. Neither -> exit 127
#
# Usage: benchmarks/bymc/run_bymc.sh <model_file> --spec <spec> [--timeout <secs>]
set -euo pipefail

# Parse arguments — pass through to ByMC, adding default options
ARGS=()
MODEL_FILE=""
for arg in "$@"; do
    if [[ -z "$MODEL_FILE" && -f "$arg" ]]; then
        MODEL_FILE="$arg"
    fi
    ARGS+=("$arg")
done

# Add fastest safety checking mode if not already specified
if [[ ! " ${ARGS[*]} " =~ " -O " ]]; then
    ARGS+=("-O" "schema.tech=cav15")
fi

# Strategy 1: verifypa-schema on PATH
if command -v verifypa-schema &>/dev/null; then
    exec verifypa-schema "${ARGS[@]}"
fi

# Strategy 2: Docker image
if docker image inspect tarsier-bymc:latest &>/dev/null 2>&1; then
    # Mount the repo root so model file paths resolve inside the container
    REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
    exec docker run --rm \
        -v "$REPO_ROOT:/work" \
        -w /work \
        tarsier-bymc:latest "${ARGS[@]}"
fi

# Strategy 3: Neither available
echo "ERROR: ByMC not found. Install verifypa-schema or build the Docker image:" >&2
echo "  bash benchmarks/bymc/build-docker.sh" >&2
exit 127
