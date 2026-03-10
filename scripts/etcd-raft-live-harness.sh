#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HARNESS_DIR="$ROOT_DIR/integration/etcd-raft-live"
COMPOSE_FILE="$HARNESS_DIR/docker-compose.yml"
CLIENT_URL="${ETCD_CLIENT_URL:-http://127.0.0.1:2379}"
WAIT_SECS="${WAIT_SECS:-60}"

usage() {
  cat <<USAGE
Usage: $(basename "$0") <command>

Commands:
  start     Start etcd raft harness container and wait for endpoint health.
  stop      Stop harness container.
  reset     Stop harness and delete persistent data volume.
  status    Print container status.
  logs      Tail harness logs.
  wait      Wait until endpoint health is ready.
  smoke-raft  Verify real raft-backed write/read via etcdctl inside the live node.
  endpoint  Print client endpoint URL.
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
    if curl -fsS "$CLIENT_URL/health" >/dev/null 2>&1; then
      echo "etcd endpoint is healthy at $CLIENT_URL"
      return 0
    fi
    sleep 1
  done
  echo "timed out waiting for etcd endpoint health at $CLIENT_URL" >&2
  return 1
}

assert_raft_write_read() {
  local key="tarsier/smoke/${SMOKE_KEY_SUFFIX:-$(date +%s)}"
  local value="ok-${SMOKE_VALUE_SUFFIX:-$(date +%s)}"

  compose exec -T etcd-node0 sh -lc \
    "ETCDCTL_API=3 etcdctl --endpoints=http://127.0.0.1:2379 put '$key' '$value' >/dev/null"

  local got
  got="$(
    compose exec -T etcd-node0 sh -lc \
      "ETCDCTL_API=3 etcdctl --endpoints=http://127.0.0.1:2379 get '$key' --print-value-only"
  )"
  got="${got//$'\r'/}"
  got="${got%$'\n'}"

  if [[ "$got" != "$value" ]]; then
    echo "raft write/read mismatch for key '$key': expected '$value', got '$got'" >&2
    return 1
  fi

  local status
  status="$(
    compose exec -T etcd-node0 sh -lc \
      'ETCDCTL_API=3 etcdctl --endpoints=http://127.0.0.1:2379 endpoint status --write-out=json'
  )"
  if [[ "$status" != *'"leader"'* ]]; then
    echo "endpoint status JSON missing leader metadata" >&2
    return 1
  fi

  echo "etcd raft smoke ok: key=$key"
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
  smoke-raft)
    require_docker
    wait_for_health
    assert_raft_write_read
    ;;
  endpoint)
    echo "$CLIENT_URL"
    ;;
  *)
    usage
    exit 2
    ;;
esac
