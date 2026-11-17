#!/usr/bin/env bash
# Run Nix inside Docker (nixos/nix, native aarch64-linux on Apple Silicon). Never installs Nix on the host.
#   modules/nix-docker.sh build        nix build the module (+ .lgx) -> modules/out/
#   modules/nix-docker.sh headless     build logosctl + beacon_api_module and run the headless transcript
#   modules/nix-docker.sh shell        interactive shell in the same environment
#   modules/nix-docker.sh -- <cmd...>  run any command (e.g. -- nix flake show ...)
# The /nix store lives in the named volume $NIX_VOL (cached across runs; `docker volume rm rfp021-nix` to reset).
# New files must be `git add`-ed before building: the flake is a git+file flake and ignores untracked files.
set -euo pipefail

ROOT="$(git -C "$(dirname "$0")/.." rev-parse --show-toplevel)"
GIT_COMMON="$(git -C "$ROOT" rev-parse --path-format=absolute --git-common-dir)"
NIX_VOL="${NIX_VOL:-rfp021-nix}"
IMAGE="${NIX_IMAGE:-nixos/nix:latest}"

NIX_CONF='experimental-features = nix-command flakes
accept-flake-config = true
sandbox = false
max-jobs = auto
cores = 0
substituters = https://cache.nixos.org https://cache.nix.logos.co/public
trusted-public-keys = cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY= public:l4HrXgL4nw246+LBh2SOJyhz64BoGegOYLheT/iIAPU='

FLAKE="git+file://$ROOT?dir=modules/eth_attest_module"

case "${1:-build}" in
  build)  CMD="set -e; cd '$ROOT'
           nix build -L '$FLAKE#lib' --out-link /tmp/lib
           nix build -L '$FLAKE#lgx' --out-link /tmp/lgx
           rm -rf modules/out && mkdir -p modules/out
           (cd -P /tmp/lib && find -L . -type f) | while read -r f; do install -D -m644 \"/tmp/lib/\$f\" \"modules/out/lib/\$f\"; done
           install -m644 /tmp/lgx/*.lgx modules/out/
           echo \"lib: \$(readlink -f /tmp/lib)\"; echo \"lgx: \$(readlink -f /tmp/lgx)\"
           find modules/out -type f | sort | xargs ls -la" ;;
  headless) CMD="bash '$ROOT/modules/headless/run.sh'" ;;
  shell)  CMD="bash" ;;
  --)     shift; CMD="$*" ;;
  *)      echo "usage: $0 build|headless|shell|-- cmd" >&2; exit 2 ;;
esac

TTY=(); [ -t 0 ] && TTY=(-it)
exec docker run --rm "${TTY[@]}" \
  -v "$NIX_VOL:/nix" \
  -v "$ROOT:$ROOT" \
  -v "$GIT_COMMON:$GIT_COMMON" \
  -e NIX_CONFIG="$NIX_CONF" \
  -e ROOT="$ROOT" -e LIVE="${LIVE:-0}" -e VP_HTTP="${VP_HTTP:-0}" -e VP_HOLD="${VP_HOLD:-}" \
  ${DOCKER_ARGS:-} \
  -w "$ROOT" \
  "$IMAGE" sh -c "git config --global --add safe.directory '*'; $CMD"
