# Tarsier Playground

Browser UI for running Tarsier analyses locally.

Features:

- In-browser protocol editor with bundled examples.
- Guided scaffold generation (`pbft` / `hotstuff` / `raft`) via `/api/assist`.
- `verify` / `liveness` / `fair-liveness` / `prove` / `prove-fair`.
- Interactive trace replay slider for counterexample traces.
- CTI rendering for failed k-induction proofs.
- Built-in semantic lint endpoint (`/api/lint`).

## Run

```bash
cargo run -p tarsier-playground
```

Open `http://127.0.0.1:7878`.

Optional env vars:

- `TARSIER_PLAYGROUND_HOST` (default `127.0.0.1`)
- `TARSIER_PLAYGROUND_PORT` (default `7878`)

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
