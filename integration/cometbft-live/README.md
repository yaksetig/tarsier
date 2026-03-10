# CometBFT Live Harness (INTEG-01)

This harness provides a reproducible, containerized CometBFT node for live
integration work.

Scope:
- bootstrap a real CometBFT node from deterministic genesis and validator keys;
- expose deterministic RPC/P2P endpoints for downstream conformance work.

Out of scope:
- model-to-implementation conformance assertions (handled by `INTEG-03`).

## Layout

- `docker-compose.yml`: single-node CometBFT service and persistent volume.
- `bootstrap/bootstrap.sh`: deterministic bootstrap entrypoint.
- `bootstrap/config/*.json`: fixed genesis/key/state artifacts.

## Commands

From repo root:

```bash
scripts/cometbft-live-harness.sh start
scripts/cometbft-live-harness.sh status
scripts/cometbft-live-harness.sh endpoint
scripts/cometbft-live-harness.sh stop
```

To force a clean deterministic restart (drops persisted state):

```bash
scripts/cometbft-live-harness.sh reset
scripts/cometbft-live-harness.sh start
```

## Determinism Contract

- Chain ID is fixed to `tarsier-integ-01`.
- Genesis time and validator set are fixed.
- Node/validator key material is fixed in `bootstrap/config`.
- RPC endpoint is fixed at `http://127.0.0.1:26657`.

The harness intentionally runs one validator (`proxy_app=kvstore`) so upstream
integration tests can have stable startup and transport behavior before moving
to multi-node scenarios in later tasks.
