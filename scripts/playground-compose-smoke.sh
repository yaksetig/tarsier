#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY_DIR="$ROOT_DIR/playground/deploy"
COMPOSE_FILE="$DEPLOY_DIR/docker-compose.yml"
ENV_FILE="$DEPLOY_DIR/.env"
ENV_TEMPLATE="$DEPLOY_DIR/.env.example"
WAIT_SECS="${WAIT_SECS:-90}"
TEMP_ENV_CREATED=0

usage() {
  cat <<USAGE
Usage: $(basename "$0") <command>

Commands:
  config    Validate compose config (default + proxy profile).
  start     Start playground compose stack.
  stop      Stop playground compose stack.
  reset     Stop stack and remove volumes.
  status    Print stack container status.
  logs      Tail stack logs.
  wait      Wait for playground health endpoint.
  endpoint  Print playground base URL.
  smoke     Run config + start + wait + stop.
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

ensure_env_file() {
  if [[ -f "$ENV_FILE" ]]; then
    return
  fi
  if [[ ! -f "$ENV_TEMPLATE" ]]; then
    echo "missing env template: $ENV_TEMPLATE" >&2
    exit 2
  fi
  cp "$ENV_TEMPLATE" "$ENV_FILE"
  TEMP_ENV_CREATED=1
}

cleanup() {
  if [[ "$TEMP_ENV_CREATED" -eq 1 ]]; then
    rm -f "$ENV_FILE"
  fi
}
trap cleanup EXIT

compose() {
  docker compose -f "$COMPOSE_FILE" "$@"
}

read_env_value() {
  local key="$1"
  local default_val="$2"
  local raw
  raw="$(grep -E "^${key}=" "$ENV_FILE" | tail -n 1 || true)"
  if [[ -z "$raw" ]]; then
    echo "$default_val"
    return
  fi
  raw="${raw#*=}"
  raw="${raw%\"}"
  raw="${raw#\"}"
  echo "$raw"
}

endpoint_url() {
  ensure_env_file
  local host_port="${PLAYGROUND_HOST_PORT:-$(read_env_value PLAYGROUND_HOST_PORT 7878)}"
  echo "http://127.0.0.1:${host_port}"
}

wait_for_health() {
  local base_url
  base_url="$(endpoint_url)"
  local health_url="${base_url}/api/health"
  local deadline=$((SECONDS + WAIT_SECS))

  while ((SECONDS < deadline)); do
    if curl -fsS "$health_url" >/dev/null 2>&1; then
      echo "playground is healthy at ${health_url}"
      return 0
    fi
    sleep 1
  done

  echo "timed out waiting for playground health at ${health_url}" >&2
  return 1
}

cmd="${1:-}"
case "$cmd" in
  config)
    require_docker
    ensure_env_file
    compose config >/dev/null
    compose --profile proxy config >/dev/null
    echo "playground compose config validation passed"
    ;;
  start)
    require_docker
    ensure_env_file
    compose up -d --build --remove-orphans
    ;;
  stop)
    require_docker
    ensure_env_file
    compose down
    ;;
  reset)
    require_docker
    ensure_env_file
    compose down --volumes --remove-orphans
    ;;
  status)
    require_docker
    ensure_env_file
    compose ps
    ;;
  logs)
    require_docker
    ensure_env_file
    compose logs --tail "${TAIL_LINES:-200}" -f
    ;;
  wait)
    wait_for_health
    ;;
  endpoint)
    endpoint_url
    ;;
  smoke)
    require_docker
    ensure_env_file
    compose config >/dev/null
    compose up -d --build --remove-orphans
    wait_for_health
    compose down
    echo "playground compose smoke completed"
    ;;
  *)
    usage
    exit 2
    ;;
esac
