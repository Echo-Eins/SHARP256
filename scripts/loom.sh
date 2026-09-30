#!/bin/sh
# The loom models (docs/SANITIZERS.md): the synchronisations the crate's
# shared invariants rest on — the keys of a session's epochs, the
# receiver's memory budget, the handshake timestamps — run in every
# interleaving of their threads that can differ. They are the tests named
# loom_*, built with --cfg sharp_loom, which puts loom's atomics and lock in
# place of the standard ones (src/sync.rs).
set -eu
cd "$(dirname "$0")/.."
RUSTFLAGS="${RUSTFLAGS:-} --cfg sharp_loom" \
  cargo test --release --no-default-features --features nat-traversal --lib \
  --target-dir target/loom -- loom_
