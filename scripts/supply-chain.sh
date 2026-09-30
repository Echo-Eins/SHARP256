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
#
#   cargo install --locked cargo-deny@0.20.2 cargo-audit@0.22.2 cargo-vet@0.10.2
set -eu
cd "$(dirname "$0")/.."
cargo deny --locked check
cargo deny --locked --no-default-features --features nat-traversal check bans
cargo audit
cargo audit --file fuzz/Cargo.lock
cargo vet --locked
