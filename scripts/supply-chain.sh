#!/bin/sh
# The dependency checks, as CI runs them (.github/workflows/supply-chain.yml;
# docs/SUPPLY_CHAIN.md says what each is for):
#
#   cargo-deny   advisories (vulnerable, unsound, unmaintained, yanked),
#                licenses, duplicates and sources, by deny.toml
#   cargo-audit  vulnerabilities again, by another implementation, in the
#                crate's lockfile and the fuzzing crate's
#   cargo-vet    every crate audited by someone trusted, or exempted by
#                name (supply-chain/)
#   fuzz lock    the fuzzing crate builds with the versions that ship: every
#                one in fuzz/Cargo.lock is in Cargo.lock, but libFuzzer's
#
#   cargo install --locked cargo-deny@0.20.2 cargo-audit@0.22.2 cargo-vet@0.10.2
set -eu
cd "$(dirname "$0")/.."
cargo deny --locked check
cargo deny --locked --no-default-features --features nat-traversal check bans
cargo audit
cargo audit --file fuzz/Cargo.lock
cargo vet --locked

# Its own workspace resolves on its own, and drifts: to bring it back, copy
# Cargo.lock over fuzz/Cargo.lock and run `cargo metadata` in fuzz/.
versions() { awk '/^name = /{n=$3} /^version = /{print n, $3}' "$1" | LC_ALL=C sort -u; }
shipped=$(mktemp)
versions Cargo.lock >"$shipped"
drift=$(versions fuzz/Cargo.lock |
    grep -v -e '^"arbitrary" ' -e '^"libfuzzer-sys" ' -e '^"sharp256-fuzz" ' |
    LC_ALL=C comm -23 - "$shipped")
rm -f "$shipped"
if [ -n "$drift" ]; then
    echo "fuzz/Cargo.lock has versions Cargo.lock does not:" >&2
    echo "$drift" >&2
    exit 1
fi
