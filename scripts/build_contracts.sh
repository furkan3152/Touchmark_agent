#!/usr/bin/env bash
# Build the contracts so the WASM is byte-identical on any machine.
#
# rustc writes the path of each dependency's source into the WASM. The deployed contracts
# were built with the cargo home at /root/.cargo, so that path is mapped back here; the
# toolchain is pinned in rust-toolchain.toml and the dependencies in Cargo.lock.
set -euo pipefail
cd "$(dirname "$0")/.."
home="${CARGO_HOME:-$HOME/.cargo}"
RUSTFLAGS="--remap-path-prefix=${home}=/root/.cargo" \
  cargo build --workspace --target wasm32v1-none --release --locked
