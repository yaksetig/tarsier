#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HARNESS_DIR="$ROOT_DIR/integration/cometbft-live"
COMPOSE_FILE="$HARNESS_DIR/docker-compose.yml"
RPC_URL="${COMETBFT_RPC_URL:-http://127.0.0.1:26657}"
WAIT_SECS="${WAIT_SECS:-60}"

usage() {
  cat <<USAGE
Usage: $(basename "$0") <command>

Commands:
  start     Start CometBFT harness container and wait for RPC health.
  stop      Stop harness container.
  reset     Stop harness and delete persistent data volume.
  status    Print container status.
  logs      Tail harness logs.
  wait      Wait until RPC health endpoint is ready.
  endpoint  Print RPC endpoint URL.
USAGE
}

require_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "docker is required but not installed" >&2
    exit 2
  fi
  if ! docker info >/dev/null 2>&1; then
    echo "docker daemon is not running; start Docker and retry" >&2
    exit 2
  fi
}

compose() {
  docker compose -f "$COMPOSE_FILE" "$@"
}

wait_for_health() {
  local deadline=$((SECONDS + WAIT_SECS))
  while ((SECONDS < deadline)); do
    if curl -fsS "$RPC_URL/health" >/dev/null 2>&1; then
      echo "CometBFT RPC is healthy at $RPC_URL"
      return 0
    fi
    sleep 1
  done
  echo "timed out waiting for CometBFT RPC health at $RPC_URL" >&2
  return 1
}

cmd="${1:-}"
case "$cmd" in
  start)
    require_docker
    compose up -d --remove-orphans
    wait_for_health
    ;;
  stop)
    require_docker
    compose down
    ;;
  reset)
    require_docker
    compose down --volumes --remove-orphans
    ;;
  status)
    require_docker
    compose ps
    ;;
  logs)
    require_docker
    compose logs --tail "${TAIL_LINES:-200}" -f
    ;;
  wait)
    wait_for_health
    ;;
  endpoint)
    echo "$RPC_URL"
    ;;
  *)
    usage
    exit 2
    ;;
esac
