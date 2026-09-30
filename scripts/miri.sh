#!/bin/sh
# Miri on what it can run of the crate's unsafe code (docs/UNSAFE.md): the
# rest calls into the system, which Miri does not emulate. Alignment is
# checked symbolically — against what the allocation promises, not against
# the address it happened to get, which could let a misaligned read pass.
#
#   rustup toolchain install nightly --profile minimal --component miri,rust-src
set -eu
cd "$(dirname "$0")/.."
export MIRIFLAGS="${MIRIFLAGS:--Zmiri-symbolic-alignment-check}"
# getaddrinfo's list read wherever its addresses lie; keys in memory (with
# the calls that lock them left out, as on a system without them).
cargo +nightly miri test --no-default-features --lib -- \
  address::dns::tests::addresses_are_read_from_the_list_wherever_they_lie crypto::secret
# DPAPI's empty answer, as the Windows code is compiled (Miri runs it here).
cargo +nightly miri test --target x86_64-pc-windows-gnu --no-default-features --lib -- \
  crypto::keystore::dpapi
