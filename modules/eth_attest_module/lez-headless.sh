#!/usr/bin/env bash
# Headless submit_update + read_instance against a live LEZ sequencer on the Docker host. Runs INSIDE
# the nix container:
#   modules/nix-docker.sh -- "ATTEST=<b58> INSTANCE=0x.. KEY_FILE=<repo path, mode 0600> bash modules/eth_attest_module/lez-headless.sh"
# LEZ_RPC defaults to http://host.docker.internal:3040 (the host's sequencer, bound on 0.0.0.0).
# KEY_FILE = operator key (32-byte hex) of a funded LEZ public account; must live under the repo mount.
set -euo pipefail
ROOT="${ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
W="$(mktemp -d)"; chmod 700 "$W"  # private: session state lives here
FLAKE="git+file://$ROOT?dir=modules/eth_attest_module"
LOCK="$ROOT/modules/eth_attest_module/flake.lock"
LEZ_RPC="${LEZ_RPC:-http://host.docker.internal:3040}"
run() { echo; echo "\$ ${*/#$W\//}"; "$@" 2>&1 || echo "(exit $?)"; }

BEACON_REV="$(nix eval --impure --raw --expr "(builtins.fromJSON (builtins.readFile $LOCK)).nodes.beacon_api_module.locked.rev")"
nix build 'github:logos-co/logos-logoscore-cli#ctl' --out-link "$W/logos"
nix build "github:logos-co/logos-evm-beacon-api-module/$BEACON_REV#lgx" --out-link "$W/beacon-lgx"
ETHRPC_REV="$(nix eval --impure --raw --expr "(builtins.fromJSON (builtins.readFile $LOCK)).nodes.eth_rpc_module.locked.rev")"
nix build "github:logos-co/logos-evm-eth-rpc-module/$ETHRPC_REV#lgx" --fallback --out-link "$W/ethrpc-lgx"
# eth_attest_module declares verified_proxy_module as a dependency (EL headers/receipts); it does not load without it
VP_REV="$(nix eval --impure --raw --expr "(builtins.fromJSON (builtins.readFile $LOCK)).nodes.verified_proxy_module.locked.rev")"
nix build "github:logos-co/logos-verified-proxy-module/$VP_REV#lgx" --fallback --out-link "$W/vp-lgx"
nix build "$FLAKE#lgx" --out-link "$W/attest-lgx"

export HOME="$W/home"; mkdir -p "$HOME"
# submit_update waits for two LEZ blocks (15 s each locally); logosctl's default call budget is 20 s.
export LOGOSCTL_TIMEOUT="${LOGOSCTL_TIMEOUT:-300000}"
ctl() { "$W/logos/bin/logosctl" --config-dir "$W/session" "$@"; }
trap 'ctl daemon stop >/dev/null 2>&1 || true' EXIT
echo "# eth_attest_module LEZ headless transcript — $(date -u +%FT%TZ), $(uname -m)-linux, sequencer $LEZ_RPC"
run ctl daemon start --detach
run ctl install "$W"/beacon-lgx/*.lgx -y
run ctl install "$W"/ethrpc-lgx/*.lgx -y
run ctl install "$W"/vp-lgx/*.lgx -y
run ctl install "$W"/attest-lgx/*.lgx -y
run ctl module load beacon_api_module
run ctl module load eth_rpc_module
run ctl module load verified_proxy_module
run ctl module load eth_attest_module
run ctl call eth_attest_module read_instance "$INSTANCE"
run ctl call eth_attest_module set_chain_config 11155111 "str:{\"lezRpc\":\"$LEZ_RPC\",\"attestProgram\":\"$ATTEST\"}"
run ctl call eth_attest_module read_instance "$INSTANCE"
run ctl call eth_attest_module read_instance 0x$(printf 'ee%.0s' $(seq 32))
run ctl call eth_attest_module submit_update "$INSTANCE" 'str:{}'
# Negative check: a group/world-readable key file is refused before it is read. A throwaway dummy, never a
# copy of the operator key.
printf '%064d\n' 0 > "$W/dummy-key-0644"; chmod 644 "$W/dummy-key-0644"
run ctl call eth_attest_module set_chain_config 11155111 "str:{\"operatorKeyFile\":\"$W/dummy-key-0644\"}"
run ctl call eth_attest_module submit_update "$INSTANCE" 'str:{}'
run ctl call eth_attest_module set_chain_config 11155111 "str:{\"operatorKeyFile\":\"$KEY_FILE\"}"
run ctl call eth_attest_module submit_update "$INSTANCE" 'str:{}'
run ctl call eth_attest_module read_instance "$INSTANCE"
# With relayers running they usually apply each update first (1106 here); SUBMIT_TRIES > 1 retries every
# 20 s so the module lands one inside a relayer's deferral window.
for i in $(seq 1 "${SUBMIT_TRIES:-1}"); do
  out="$(ctl call eth_attest_module submit_update "$INSTANCE" 'str:{}' 2>&1 || true)"
  echo; echo "\$ ctl call eth_attest_module submit_update $INSTANCE 'str:{}'   # try $i, $(date -u +%T)"; echo "$out"
  echo "$out" | grep -q '\\"ok\\":true' && break
  sleep 20
done
run ctl call eth_attest_module read_instance "$INSTANCE"
