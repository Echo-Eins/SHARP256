#!/bin/sh
# Runs the end-to-end tests that change the network under a transfer — the
# path MTU dropping, the local address disappearing for a moment — inside a
# private network namespace, where they cannot disturb anything else.
#
# Needs Linux with unprivileged user namespaces (`unshare -rn`).
set -eu
cd "$(dirname "$0")/.."
cargo test --all-features --test e2e --no-run
BIN=$(ls -t target/debug/deps/e2e-* | grep -v '\.d$' | head -1)
exec unshare -rn env SHARP_NETNS=1 "$BIN" --ignored --test-threads=1 netns_
