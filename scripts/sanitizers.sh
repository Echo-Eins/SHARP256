#!/bin/sh
# The tests under the sanitizers (docs/SANITIZERS.md), with the standard
# library built instrumented too (-Zbuild-std), so that what it does is
# seen as well:
#
#   scripts/sanitizers.sh address   AddressSanitizer: memory used out of
#                                   bounds, after it is freed, leaked
#   scripts/sanitizers.sh thread    ThreadSanitizer: data races
#   scripts/sanitizers.sh memory    MemorySanitizer: memory read before it
#                                   is written (BLAKE3 in Rust: its assembly
#                                   is not instrumented)
#   scripts/sanitizers.sh           all three
#
# Each runs the library's tests and the end-to-end ones, less those that
# cannot hold under it, each named below with why. RUSTFLAGS adds to the
# sanitizer's own: -Zsanitizer-memory-track-origins, say, to learn where a
# value MemorySanitizer reports came from.
#
#   rustup toolchain install nightly --profile minimal --component rust-src
set -eu
cd "$(dirname "$0")/.."
target=$(rustc -vV | sed -n 's/^host: //p')

# The crypto pool at four workers, whatever the machine: its jobs are what
# runs on threads of the crate's own.
export SHARP256_CRYPTO_THREADS=4

# The crate optimised a little, as the sanitizers' own documentation
# advises (its dependencies are at level 2 in every test build already,
# Cargo.toml): instrumented and unoptimised, it ran the end-to-end tests
# past their time bounds — eleven of them under MemorySanitizer. Debug
# assertions and overflow checks stay on.
export CARGO_PROFILE_DEV_OPT_LEVEL=1

# The sanitizers intercept mlock and do nothing (their shadow memory would
# be locked too), so the kernel reports no locked pages.
SKIP_LIB="--skip keys_are_locked_here --skip a_page_is_locked_and_kept_out_of_dumps"
SKIP_E2E=""

run() {
  sanitizer=$1
  shift
  echo "== $sanitizer"
  RUSTFLAGS="-Zsanitizer=$sanitizer $EXTRA_RUSTFLAGS" RUSTDOCFLAGS="-Zsanitizer=$sanitizer" \
    cargo +nightly test -Zbuild-std --target "$target" --target-dir "target/$sanitizer" \
    --no-default-features --features "$FEATURES" "$@"
}

EXTRA_RUSTFLAGS="${RUSTFLAGS:-}"
for sanitizer in ${1:-address thread memory}; do
  FEATURES=nat-traversal
  lib="$SKIP_LIB"
  e2e="$SKIP_E2E"
  case "$sanitizer" in
    address) ;;
    thread)
      # tokio hands sockets to its I/O thread through epoll, which the
      # sanitizer cannot see (scripts/tsan.supp says how narrowly).
      export TSAN_OPTIONS="suppressions=$PWD/scripts/tsan.supp ${TSAN_OPTIONS:-}"
      ;;
    memory)
      FEATURES=nat-traversal,blake3/pure
      ;;
    *) echo "address, thread or memory, not $sanitizer" >&2; exit 2 ;;
  esac
  # shellcheck disable=SC2086 # the skips are lists of arguments
  run "$sanitizer" --lib -- $lib
  # shellcheck disable=SC2086
  run "$sanitizer" --test e2e -- $e2e
done
