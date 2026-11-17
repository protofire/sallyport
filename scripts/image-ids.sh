#!/bin/sh
# Builds every guest with risc0's reproducible Docker builder (risczero/risc0-guest-builder r0.1.97.0 linux/amd64, pinned by
# digest in crates/program-methods/build.rs) and prints the ImageIDs. Needs Docker; the result does not depend on
# the host OS/arch, the local risc0 toolchain or the checkout path.
set -eu
cd "$(dirname "$0")/.."
RISC0_USE_DOCKER=1 cargo run -q --release --locked -p program-methods --example image_ids
