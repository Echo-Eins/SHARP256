#!/bin/sh
# Timing measurements of the checks that must not depend on secrets
# (src/crypto/dudect.rs), in release mode, on one core, with a header that
# says what was measured and where. Output: standard output; the log in
# docs/evidence/crypto/dudect.log is one run of this.
#
#   scripts/dudect.sh [core]      (core: default 2)
set -eu
cd "$(dirname "$0")/.."
core=${1:-2}
cargo test --release --no-default-features --features nat-traversal --lib --no-run >/dev/null 2>&1
bin=$(ls -t target/release/deps/sharp256-* | grep -v '\.d$' | head -1)
echo "# dudect run"
echo "# commit:  $(git rev-parse --short HEAD)$(git diff --quiet HEAD -- src Cargo.toml Cargo.lock || echo ' (with local changes)')"
echo "# rustc:   $(rustc -V)"
echo "# cpu:     $(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ //') (pinned to core $core)"
echo "# kernel:  $(uname -sr)"
echo "# command: taskset -c $core <lib tests> dudect --ignored --nocapture --test-threads=1"
echo "# |t| > 4.5 = the two classes' times differ (dudect's threshold)"
echo
taskset -c "$core" "$bin" dudect --ignored --nocapture --test-threads=1 2>&1 |
  sed -n 's/^test crypto::dudect::tests::\([a-z_0-9]*\) \.\.\. /\1:\n/p; /runs  medians/p; /^test result/p' |
  grep -v '^dudect_' | awk '!seen[$0]++'
