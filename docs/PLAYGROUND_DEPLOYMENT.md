# Playground Deployment Guide (PLAY-02)

This guide describes local and hosted deployment for the Tarsier playground
using the Compose template in `playground/deploy`.

## Deployment Assets

- Compose template: `playground/deploy/docker-compose.yml`
- Builder/runtime image recipe: `playground/deploy/Dockerfile`
- Optional reverse proxy config: `playground/deploy/Caddyfile`
- Environment contract template: `playground/deploy/.env.example`

## Local Deployment (single host)

1. Prepare environment file:

```bash
cp playground/deploy/.env.example playground/deploy/.env
```

2. Start playground directly:

```bash
docker compose -f playground/deploy/docker-compose.yml up -d --build
```

3. Check health:

```bash
curl -fsS http://127.0.0.1:7878/api/health
```

4. Stop:

```bash
docker compose -f playground/deploy/docker-compose.yml down
```

## Compose Smoke Check (PLAY-03)

Fast config validation (CI-friendly):

```bash
./scripts/playground-compose-smoke.sh config
```

Live local smoke (starts stack, waits for `/api/health`, then tears down):

```bash
./scripts/playground-compose-smoke.sh smoke
```

Manual operator helpers:

```bash
./scripts/playground-compose-smoke.sh start
./scripts/playground-compose-smoke.sh wait
./scripts/playground-compose-smoke.sh status
./scripts/playground-compose-smoke.sh stop
```

## Hosted Deployment (behind proxy)

1. Set security-related env vars in `playground/deploy/.env`:

- `TARSIER_AUTH_TOKEN`: required for protected POST endpoints
- `TARSIER_ALLOWED_ORIGINS`: comma-separated list of trusted origins
- resource limits (`TARSIER_MAX_*`, `TARSIER_RATE_LIMIT_PER_MIN`)

2. Start with proxy profile:

```bash
docker compose -f playground/deploy/docker-compose.yml --profile proxy up -d --build
```

3. Put TLS termination in front of port `8080` (cloud LB or edge proxy).

4. Keep playground service private to the host/network perimeter where possible.

## Environment Contract

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `PLAYGROUND_HOST_PORT` | No | `7878` | Host port mapped to playground HTTP |
| `PROXY_HTTP_PORT` | No | `8080` | Host port mapped to proxy profile |
| `TARSIER_AUTH_TOKEN` | Hosted: Yes | empty | Bearer token for protected endpoints |
| `TARSIER_ALLOWED_ORIGINS` | Hosted: Yes | empty | CORS allow-list |
| `TARSIER_MAX_DEPTH` | No | `12` | Max analysis depth accepted by API |
| `TARSIER_MAX_TIMEOUT_SECS` | No | `60` | Max timeout accepted by API |
| `TARSIER_MAX_CONCURRENT_SOLVERS` | No | `4` | Concurrent solver request cap |
| `TARSIER_RATE_LIMIT_PER_MIN` | No | `30` | Per-minute request limit |
| `TARSIER_MAX_REQUEST_BYTES` | No | `524288` | Max HTTP request body |
| `TARSIER_MAX_SOURCE_BYTES` | No | `262144` | Max `.trs` source size |
| `TARSIER_MAX_RESPONSE_BYTES` | No | `8388608` | Max API response body |

## Operational Notes

- Monitor container health and restart counts (`docker compose ps`).
- CI now runs `./scripts/playground-compose-smoke.sh config` in `.github/workflows/ci.yml`
  as a non-flaky compose contract check.
- Capture logs for both services during incidents:

```bash
docker compose -f playground/deploy/docker-compose.yml logs --tail 200 playground
```

```bash
docker compose -f playground/deploy/docker-compose.yml --profile proxy logs --tail 200 proxy
```

- If solver-heavy workloads increase latency, tune:
  - `TARSIER_MAX_CONCURRENT_SOLVERS`
  - `TARSIER_MAX_TIMEOUT_SECS`
  - `TARSIER_RATE_LIMIT_PER_MIN`

## Troubleshooting

| Symptom | Likely Cause | Action |
|---|---|---|
| `/api/health` fails | Playground not healthy yet | Check `docker compose ps` and playground logs |
| 401 on POST endpoints | Missing/invalid bearer token | Set `TARSIER_AUTH_TOKEN` and send matching header |
| Browser CORS failures | Origin not allowed | Add frontend origin to `TARSIER_ALLOWED_ORIGINS` |
| 503 `server busy` | Concurrency cap reached | Increase `TARSIER_MAX_CONCURRENT_SOLVERS` or reduce traffic |
| Frequent 504/timeout | Timeout cap too low for workload | Increase `TARSIER_MAX_TIMEOUT_SECS` within safe budget |
