#!/usr/bin/env sh
set -eu

HOME_DIR="${CMTHOME:-/comet}"
CONFIG_DIR="$HOME_DIR/config"
DATA_DIR="$HOME_DIR/data"

mkdir -p "$CONFIG_DIR" "$DATA_DIR"

if [ ! -f "$CONFIG_DIR/config.toml" ]; then
  cometbft init --home "$HOME_DIR" --chain-id tarsier-integ-01 --moniker tarsier-comet-node0 >/dev/null 2>&1
fi

cp /harness/config/genesis.json "$CONFIG_DIR/genesis.json"
cp /harness/config/node_key.json "$CONFIG_DIR/node_key.json"
cp /harness/config/priv_validator_key.json "$CONFIG_DIR/priv_validator_key.json"
cp /harness/config/priv_validator_state.json "$DATA_DIR/priv_validator_state.json"

exec cometbft node \
  --home "$HOME_DIR" \
  --proxy_app kvstore \
  --rpc.laddr tcp://0.0.0.0:26657 \
  --p2p.laddr tcp://0.0.0.0:26656
