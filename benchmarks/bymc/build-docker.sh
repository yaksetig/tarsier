#!/bin/bash
# Build the ByMC Docker image for cross-tool benchmarking.
#
# Usage: bash benchmarks/bymc/build-docker.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "Building tarsier-bymc:latest Docker image..."
docker build -t tarsier-bymc:latest "$SCRIPT_DIR"
echo "Done. Image: tarsier-bymc:latest"
