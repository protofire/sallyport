#!/usr/bin/env bash
# Headless Logos Core run (RFP U3): logosctl daemon + beacon_api_module + eth_attest_module, then
# call the module on fixtures. Runs INSIDE the nix container: `modules/nix-docker.sh headless`.
# Transcript is printed; evidence/module/headless-transcript.txt is the recorded copy.
set -euo pipefail
ROOT="${ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
W="$(mktemp -d)"
FLAKE="git+file://$ROOT?dir=modules/eth_attest_module"
LOCK="$ROOT/modules/eth_attest_module/flake.lock"
run() { echo; echo "\$ ${*/#$W\//}"; "$@" 2>&1 || echo "(exit $?)"; }

BEACON_REV="$(nix eval --impure --raw --expr "(builtins.fromJSON (builtins.readFile $LOCK)).nodes.beacon_api_module.locked.rev")"
nix build 'github:logos-co/logos-logoscore-cli#ctl' --out-link "$W/logos"
nix build "github:logos-co/logos-evm-beacon-api-module/$BEACON_REV#lgx" --out-link "$W/beacon-lgx"
ETHRPC_REV="$(nix eval --impure --raw --expr "(builtins.fromJSON (builtins.readFile $LOCK)).nodes.eth_rpc_module.locked.rev")"
nix build "github:logos-co/logos-evm-eth-rpc-module/$ETHRPC_REV#lgx" --fallback --out-link "$W/ethrpc-lgx"
VP_REV="$(nix eval --impure --raw --expr "(builtins.fromJSON (builtins.readFile $LOCK)).nodes.verified_proxy_module.locked.rev")"
nix build "github:logos-co/logos-verified-proxy-module/$VP_REV#lgx" --fallback --out-link "$W/vp-lgx"
nix build "$FLAKE#lgx" --out-link "$W/attest-lgx"

export LOGOSCTL_TIMEOUT="${LOGOSCTL_TIMEOUT:-300000}"   # proxy start() blocks up to 120 s; produce fetches LC + EL
export HOME="$W/home"; mkdir -p "$HOME"   # the bundled package downloader writes under $HOME
ctl() { "$W/logos/bin/logosctl" --config-dir "$W/session" "$@"; }
trap 'ctl daemon stop >/dev/null 2>&1 || true' EXIT
echo "# eth_attest_module headless transcript — $(date -u +%FT%TZ), $(uname -m)-linux, beacon_api_module @ ${BEACON_REV:0:7}, eth_rpc_module @ ${ETHRPC_REV:0:7}, verified_proxy_module @ ${VP_REV:0:7}"

run ctl daemon start --detach
run ctl install "$W"/beacon-lgx/*.lgx -y
run ctl install "$W"/ethrpc-lgx/*.lgx -y
run ctl install "$W"/vp-lgx/*.lgx -y
run ctl install "$W"/attest-lgx/*.lgx -y
run ctl package ls
run ctl module load beacon_api_module
run ctl module load eth_rpc_module
run ctl module load verified_proxy_module
run ctl module load eth_attest_module

A="$ROOT/fixtures/adversarial"
# positive controls (expect ok, errorCode 0) and one rejection per verifier layer
for v in ok_attest_account ok_attest_storage ok_attest_log \
         attest_predicate_false attest_el_state_root_tampered attest_account_proof_node_tampered \
         attest_under_unknown_header bootstrap_committee_branch_tampered; do
  echo; echo "## $v (expected_error $(grep -o '"expected_error": [0-9]*' "$A/$v.json" | grep -o '[0-9]*$'))"
  run ctl call eth_attest_module verify_attestation_dry_run "@$A/$v.json"
done
run ctl call eth_attest_module verify_attestation_dry_run 'str:{"config":{}}'
run ctl call eth_attest_module submit_update inst-1 'str:{}'
run ctl call eth_attest_module read_instance inst-1

if [ "${LIVE:-0}" = 1 ]; then
  # Live Sepolia through beacon_api_module. The checkpoint here is the current finalized root as
  # reported by providers: fine for a demo, NOT a trust anchor (an operator must pin one).
  run ctl call beacon_api_module init_defaults
  FH="$(ctl call beacon_api_module finalized_header 11155111 2>&1 || true)"; echo; echo "\$ ctl call beacon_api_module finalized_header 11155111"; echo "$FH"
  ROOT_HEX="$(echo "$FH" | grep -o 'root[^0-9a-fx]*0x[0-9a-f]\{64\}' | grep -o '0x[0-9a-f]*' | head -1 || true)"
  run ctl call eth_attest_module set_chain_config 11155111 "str:{\"checkpointRoot\":\"$ROOT_HEX\"}"
  # EL routing (inclusion::host::el_route): headers + block receipts via verified_proxy_module, eth_getProof
  # via eth_rpc_module. Unconfigured proxy -> produce refuses (no raw fallback).
  echo; echo '$ ctl call eth_attest_module produce_attestation ... (verified_proxy_module not configured) | first 300 chars'
  ctl call eth_attest_module produce_attestation 11155111 'str:' 0x7b79995e5f793a07bc00c21412e50ecae098e7f9 'str:' -1 -1 \
    'str:{"field":"nonce","op":"ge","value":"0x00"}' 2>&1 | cut -c1-300 || true
  # The proxy syncs its light client from the same trusted root the attestation uses. The default
  # Sepolia execution endpoint (ethpandaops) keeps proof history. VP_HTTP=1 also opens its JSON-RPC
  # endpoint (for the standalone relayer's --exec-verified).
  VPCFG="{\"network\":\"sepolia\",\"trustedBlockRoot\":\"$ROOT_HEX\"}"
  [ "${VP_HTTP:-0}" = 1 ] && VPCFG="{\"network\":\"sepolia\",\"trustedBlockRoot\":\"$ROOT_HEX\",\"httpServer\":{\"enabled\":true,\"host\":\"0.0.0.0\",\"port\":18545}}"
  run ctl call verified_proxy_module configure "json:$VPCFG"
  run ctl call verified_proxy_module start
  run ctl call verified_proxy_module status
  run ctl call verified_proxy_module ethGetBlockByNumber finalized false
  # No eth_getProof on the proxy: this is why the account/storage proof stays on eth_rpc_module.
  run ctl call verified_proxy_module rpc eth_getProof 'json:["0x7b79995e5f793a07bc00c21412e50ecae098e7f9",[],"finalized"]'
  echo; echo '$ ctl call eth_attest_module produce_attestation 11155111 "" <WETH> "" -1 -1 nonce>=0  | first 700 chars'
  ctl call eth_attest_module produce_attestation 11155111 'str:' 0x7b79995e5f793a07bc00c21412e50ecae098e7f9 'str:' -1 -1 \
    'str:{"field":"nonce","op":"ge","value":"0x00"}' 2>&1 | cut -c1-700 || true
  # A claim's inclusion material: a receipt log in the latest finalized block (header + receipts both
  # verified). Pick the first receipt with a log, from the verified receipts of that block.
  FIN="$(ctl call verified_proxy_module ethGetBlockByNumber finalized false 2>&1 | grep -o 'number[\\"]*:[\\"]*0x[0-9a-f]*' | grep -o '0x[0-9a-f]*' | head -1 || true)"
  RC="$(ctl call verified_proxy_module ethGetBlockReceipts "$FIN" 2>&1 || true)"
  echo; echo "# finalized block $FIN via verified_proxy_module: $(echo "$RC" | grep -o 'cumulativeGasUsed' | wc -l) receipts"
  for t in 0 1 2 3 4 5 6 7 8 9; do
    OUT="$(ctl call eth_attest_module produce_attestation 11155111 'str:' 'str:' 'str:' $t 0 'str:{"field":"log.status","op":"eq","value":"0x01"}' 2>&1 || true)"
    if echo "$OUT" | grep -q 'errorCode[\\"]*:0[,}]'; then
      echo; echo "\$ ctl call eth_attest_module produce_attestation 11155111 \"\" \"\" \"\" $t 0 log.status==1  | first 900 chars"
      echo "$OUT" | cut -c1-900; break
    fi
    echo "# tx $t: $(echo "$OUT" | grep -o 'errorCode[^,]*,[^,]*error[^,]*' | head -1 | cut -c1-200)"
  done
  if [ -n "${VP_HOLD:-}" ]; then echo "# holding the daemon ${VP_HOLD}s (relayer --exec-verified)"; sleep "$VP_HOLD"; fi
fi
