#!/bin/sh
# Downloads the pinned Ethereum test vectors into $SPEC_TESTS_DIR (default ~/spectests), checks
# sha256, and extracts only the suites crates/spec-tests reads. Never inside the repo.
# Usage: crates/spec-tests/fetch.sh [dir]; then SPEC_TESTS_DIR=<dir> cargo test -p spec-tests
set -eu
DIR=${1:-${SPEC_TESTS_DIR:-$HOME/spectests}}
CS=v1.7.0-beta.4   # ethereum/consensus-specs release (Electra/Fulu/Gloas light client)
BLS=v0.1.2         # ethereum/bls12-381-tests release
mkdir -p "$DIR/dl" && cd "$DIR/dl"
get() { # name url sha256
  [ -f "$1" ] || { curl -fsSL -o "$1.part" "$2" && mv "$1.part" "$1"; }
  echo "$3  $1" | sha256sum -c -
}
get mainnet.tar.gz https://github.com/ethereum/consensus-specs/releases/download/$CS/mainnet.tar.gz \
  67762986572372a08d3b182535aa760433c86e174e14e0bbd756f350dd19398c
get minimal.tar.gz https://github.com/ethereum/consensus-specs/releases/download/$CS/minimal.tar.gz \
  26d09aea70c62ed235a120a95082d544ab1c2e6fe36bd35ea1bd5da62f3b7b68
get bls_tests_json.tar.gz https://github.com/ethereum/bls12-381-tests/releases/download/$BLS/bls_tests_json.tar.gz \
  0dc1dfabfa7b3e0f8e8029f9cb2bb8733597526fa085b18f160d2c4eb0b448bc
cd "$DIR"
rm -rf consensus bls && mkdir -p consensus bls
for p in mainnet minimal; do
  tar -xzf dl/$p.tar.gz -C consensus --wildcards \
    "tests/$p/electra/light_client/*" "tests/$p/fulu/light_client/*" "tests/$p/gloas/light_client/*" \
    "tests/$p/electra/ssz_static/*" "tests/$p/fulu/ssz_static/*" "tests/$p/gloas/ssz_static/*"
done
# ssz_static: keep only the containers lc-core decodes/hashes
find consensus/tests/*/*/ssz_static -mindepth 1 -maxdepth 1 -type d \
  ! -name BeaconBlockHeader ! -name SyncCommittee ! -name SyncAggregate ! -name 'LightClient*' \
  -exec rm -rf {} +
tar -xzf dl/bls_tests_json.tar.gz -C bls
echo "$CS $BLS" > VERSIONS
echo "spec tests ready in $DIR ($CS, bls12-381-tests $BLS)"
