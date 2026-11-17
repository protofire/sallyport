#!/usr/bin/env bash
# Builds the bench binary. On macOS with a recent Xcode Metal compiler risc0-sys 1.5.0 (pulled by
# risc0-zkvm 3.0.5) fails to compile poseidon2.metal ("ambiguous operator="); we build against a
# patched copy kept in target/ (patch: patches/risc0-sys-poseidon2-metal.patch). The Metal Toolchain
# itself comes from `xcodebuild -downloadComponent MetalToolchain` (no sudo).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export PATH="$PATH:$HOME/.risc0/bin"
export AR_riscv32im_risc0_zkvm_elf="${AR_riscv32im_risc0_zkvm_elf:-$HOME/.risc0/toolchains/v2024.1.5-cpp-aarch64-apple-darwin/riscv32im-osx-arm64/bin/riscv32-unknown-elf-ar}"
cd "$ROOT"
CFG=()
if [[ "$(uname -s)" == Darwin ]]; then
  P="$ROOT/target/risc0-sys-patched"
  if [[ ! -d "$P" ]]; then
    cp -R "$(ls -d "$HOME"/.cargo/registry/src/*/risc0-sys-1.5.0 | head -1)" "$P"
    patch -d "$P" -p1 < crates/bench/patches/risc0-sys-poseidon2-metal.patch
  fi
  CFG=(--config "patch.crates-io.risc0-sys.path='$P'")
fi
cargo build -p bench --release "${CFG[@]}"
