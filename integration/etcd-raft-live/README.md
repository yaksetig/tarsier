# etcd-raft Live Harness (INTEG-02)

This harness provides a reproducible, containerized single-node etcd runtime
for live etcd-raft integration bring-up.

Scope:
- bootstrap a real etcd server with deterministic raft settings;
- expose stable client/peer endpoints for downstream conformance tasks.

Out of scope:
- model-to-implementation conformance assertions (handled by `INTEG-04`).

## Layout

- `docker-compose.yml`: single-node etcd service and persistent volume.

## Commands

From repo root:

```bash
scripts/etcd-raft-live-harness.sh start
scripts/etcd-raft-live-harness.sh status
scripts/etcd-raft-live-harness.sh endpoint
scripts/etcd-raft-live-harness.sh stop
```

To force a clean deterministic restart (drops persisted state):

```bash
scripts/etcd-raft-live-harness.sh reset
scripts/etcd-raft-live-harness.sh start
```

## Determinism Contract

- Cluster token is fixed to `tarsier-integ-02`.
- Node name is fixed to `node0`.
- Heartbeat/election timings are fixed.
- Client endpoint is fixed at `http://127.0.0.1:2379`.

The harness intentionally runs one etcd member to keep startup deterministic and
fast for follow-on live conformance work.
