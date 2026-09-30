#!/bin/sh
# What CI's lint job runs, and the tests: run it before pushing. (The
# laboratory, fuzzing and the other operating systems are CI's.)
set -eu
cargo fmt --check
cargo clippy --all-features --all-targets -- -D warnings
cargo clippy --no-default-features --all-targets -- -D warnings
cargo clippy --no-default-features --features nat-traversal --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --lib
if rustup target list --installed 2>/dev/null | grep -q x86_64-unknown-freebsd; then
  cargo clippy --target x86_64-unknown-freebsd --no-default-features \
    --features nat-traversal,blake3/pure --all-targets -- -D warnings
else
  echo "(the FreeBSD target is not installed, so its lint is skipped: rustup target add x86_64-unknown-freebsd)"
fi
for t in x86_64-pc-windows-gnu x86_64-apple-darwin; do
  if rustup target list --installed 2>/dev/null | grep -q "$t"; then
    cargo clippy --target "$t" --all-features --features blake3/pure --all-targets -- -D warnings
  else
    echo "(the $t target is not installed, so its lint is skipped: rustup target add $t)"
  fi
done
cargo test --no-default-features --features nat-traversal
