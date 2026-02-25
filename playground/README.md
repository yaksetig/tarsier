# Tarsier Playground

Browser UI for running Tarsier analyses locally.

Features:

- In-browser protocol editor with bundled examples.
- Guided scaffold generation (`pbft` / `hotstuff` / `raft`) via `/api/assist`.
- `verify` / `liveness` / `fair-liveness` / `prove` / `prove-fair`.
- Interactive trace replay slider for counterexample traces with sender/recipient/message/kind/variant/field filters.
- CTI rendering for failed k-induction proofs.
- Built-in semantic lint endpoint (`/api/lint`) with source spans and structured fix snippets.
- Download/export actions for JSON, Markdown, timeline, Mermaid, and artifact bundle outputs.
- CI snapshot regression coverage for CLI/playground UX projections (`scripts/ux_snapshot_regression.py` + `docs/ux-regression-snapshots-v1.json`).

## Run

```bash
cargo run -p tarsier-playground
```

Open `http://127.0.0.1:7878`.

Optional env vars:

- `TARSIER_PLAYGROUND_HOST` (default `127.0.0.1`)
- `TARSIER_PLAYGROUND_PORT` (default `7878`)

## UX Snapshot Gate

Run the deterministic UX snapshot regression locally:

```bash
python3 scripts/ux_snapshot_regression.py
```

If a UX contract change is intentional, update snapshots and commit the diff:

```bash
python3 scripts/ux_snapshot_regression.py --update
```

## API

- `GET /api/health`
- `GET /api/examples`
- `POST /api/assist`
- `POST /api/lint`
- `POST /api/run`

`POST /api/assist` body:

```json
{
  "kind": "pbft"
}
```

`POST /api/run` body:

```json
{
  "source": "protocol ...",
  "check": "verify",
  "solver": "z3",
  "depth": 12,
  "timeout_secs": 60,
  "soundness": "strict",
  "proof_engine": "kinduction",
  "fairness": "weak"
}
```

## Deployment Profiles

### Local mode (default)

No configuration needed. All security middleware is permissive:

```bash
cargo run -p tarsier-playground
```

### Hosted mode

Set env vars to enable auth, CORS restrictions, and tighter limits:

```bash
export TARSIER_AUTH_TOKEN="your-secret-token"
export TARSIER_ALLOWED_ORIGINS="https://your-app.example.com"
export TARSIER_MAX_DEPTH=12
export TARSIER_MAX_TIMEOUT_SECS=60
export TARSIER_MAX_CONCURRENT_SOLVERS=4
export TARSIER_RATE_LIMIT_PER_MIN=30
cargo run -p tarsier-playground
```

## Security Configuration Reference

| Env Var | Default | Purpose |
|---------|---------|---------|
| `TARSIER_MAX_REQUEST_BYTES` | `524288` | Max request body size (transport-level, returns 413) |
| `TARSIER_MAX_SOURCE_BYTES` | `262144` | Max `.trs` source length in POST body |
| `TARSIER_MAX_RESPONSE_BYTES` | `8388608` | Response truncation threshold |
| `TARSIER_MAX_DEPTH` | `20` | Hard cap on `depth` parameter (clamped silently) |
| `TARSIER_MAX_TIMEOUT_SECS` | `120` | Hard cap on `timeout_secs` parameter |
| `TARSIER_MAX_CONCURRENT_SOLVERS` | `4` | Concurrent `/api/run` requests (503 when full) |
| `TARSIER_RATE_LIMIT_PER_MIN` | `60` | Per-IP POST rate limit (429 when exceeded) |
| `TARSIER_AUTH_TOKEN` | (unset) | Bearer token; enables auth on POST endpoints when set |
| `TARSIER_ALLOWED_ORIGINS` | (unset) | Comma-separated CORS origins; permissive when unset |

## Security Checklist

- [ ] Set `TARSIER_AUTH_TOKEN` to a strong random value
- [ ] Set `TARSIER_ALLOWED_ORIGINS` to your frontend domain(s)
- [ ] Place behind a TLS-terminating reverse proxy (nginx, Caddy, cloud LB)
- [ ] Monitor logs for 429/503/504 status codes
- [ ] Set appropriate `TARSIER_MAX_CONCURRENT_SOLVERS` for your hardware
