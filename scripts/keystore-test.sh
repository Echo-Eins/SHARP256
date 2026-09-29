#!/bin/sh
# Runs the test that seals an identity file with a key the operating system
# keeps (src/crypto/identity_file.rs, the_keystore_seals_and_opens_it)
# against a Secret Service of its own: gnome-keyring in a private D-Bus
# session, with its keyrings in a temporary directory, so that nobody's own
# keyring is read or written. Needs dbus-run-session, gnome-keyring-daemon
# and secret-tool (Debian and Ubuntu: dbus, gnome-keyring, libsecret-tools).
set -eu
cd "$(dirname "$0")/.."

# The program itself, not a sandbox's wrapper of it (firejail installs
# links named after the programs it confines, and a confined secret-tool
# may refuse to run where the test does).
real() {
  IFS=:
  for dir in $PATH; do
    if [ -x "$dir/$1" ] && [ "$(basename "$(readlink -f "$dir/$1")")" != firejail ]; then
      echo "$dir/$1"
      return
    fi
  done
  echo "$1 not found (outside a sandbox's wrappers)" >&2
  exit 1
}
tool=$(real secret-tool)
daemon=$(real gnome-keyring-daemon)

cargo test --no-default-features --features nat-traversal --lib --no-run >/dev/null 2>&1
bin=$(ls -t target/debug/deps/sharp256-* | grep -v '\.d$' | head -1)
home=$(mktemp -d)
trap 'rm -rf "$home"' EXIT
mkdir -m 700 "$home/run"
HOME="$home" XDG_DATA_HOME="$home/data" XDG_CONFIG_HOME="$home/config" \
XDG_CACHE_HOME="$home/cache" XDG_RUNTIME_DIR="$home/run" SHARP256_SECRET_TOOL="$tool" \
  dbus-run-session -- sh -c '
    printf "keystore test" | "$1" --unlock --components=secrets >/dev/null
    "$0" --ignored --exact crypto::identity_file::tests::the_keystore_seals_and_opens_it
  ' "$bin" "$daemon"
