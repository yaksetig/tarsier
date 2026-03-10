# Playground Compose Template (PLAY-01)

This directory provides a Docker Compose deployment template for the Tarsier
playground.

Services:
- `playground`: `tarsier-playground` HTTP server
- `proxy` (optional profile): Caddy reverse proxy in front of playground

## Quick Start

```bash
cp playground/deploy/.env.example playground/deploy/.env
docker compose -f playground/deploy/docker-compose.yml up -d --build
```

Open:
- direct: `http://127.0.0.1:${PLAYGROUND_HOST_PORT:-7878}`
- via proxy profile: `http://127.0.0.1:${PROXY_HTTP_PORT:-8080}`

Enable proxy profile:

```bash
docker compose -f playground/deploy/docker-compose.yml --profile proxy up -d --build
```

Stop:

```bash
docker compose -f playground/deploy/docker-compose.yml down
```
