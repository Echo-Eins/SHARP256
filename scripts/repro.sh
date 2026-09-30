#!/bin/sh
# Reproducible builds: the release binaries for Linux, built from a commit
# in a container pinned by its digest (the compiler, the linker and the C
# library in it), come out the same byte for byte whoever builds them,
# wherever, whenever.
#
#   scripts/repro.sh build [COMMIT] [OUT]  builds COMMIT (default HEAD) and
#                                          writes the binaries and their
#                                          SHA256SUMS to OUT (default
#                                          target/repro/COMMIT-VARIANT)
#   scripts/repro.sh check [COMMIT]        builds it twice, the second time
#                                          differing in everything but the
#                                          source and the image (directory,
#                                          user, umask, time zone, locale,
#                                          host name, parallel jobs, a
#                                          registry downloaded afresh), and
#                                          fails unless every binary matches
#
# REPRO_VARIANT picks what is built:
#   headless (default)  the four binaries without the GUI, for servers
#   gui                 sharp-sender and sharp-receiver with it, against
#                       GTK 3 from Debian's archive as it was on the day the
#                       image was made (snapshot.debian.org)
#
# Only the commit is built — `git archive`, not the working tree — and only
# Docker is needed on the host. A release publishes the same SHA256SUMS
# (.github/workflows/release.yml), so anyone can check a release against
# its source with this script.
set -eu

# rust:1.95.0-slim-bookworm (the index: linux/amd64 among others).
IMAGE="rust:1.95.0-slim-bookworm@sha256:d7482085ff5b415f84dba5647ae71606650bdef00db7aeb69f4b3d170c3e4082"
# The Debian snapshot that image was made from (its debian.sources says so).
SNAPSHOT="20260518T000000Z"

cd "$(dirname "$0")/.."
VARIANT="${REPRO_VARIANT:-headless}"
case "$VARIANT" in
  headless)
    FEATURES="--no-default-features --features nat-traversal"
    BINS="sharp-sender sharp-receiver sharp-relay sharp-probe"
    ;;
  gui)
    FEATURES=""
    BINS="sharp-sender sharp-receiver"
    ;;
  *) echo "REPRO_VARIANT is headless or gui, not $VARIANT" >&2; exit 2 ;;
esac

# One build in a fresh container: the source comes in on stdin as a tar,
# the binaries go out on stdout as one, the build's output goes to stderr.
# $1: `docker run` options; then the build's user id, source directory,
# CARGO_HOME, parallel jobs and umask.
build_in() {
  # shellcheck disable=SC2086 # $1 is a list of options
  docker run --rm -i $1 \
    -e BUILD_UID="$2" -e SRC="$3" -e CARGO_HOME="$4" -e JOBS="$5" -e MASK="$6" \
    -e FEATURES="$FEATURES" -e BINS="$BINS" -e VARIANT="$VARIANT" -e SNAPSHOT="$SNAPSHOT" \
    "$IMAGE" sh -euc '
      if [ "$VARIANT" = gui ]; then
        rm -f /etc/apt/sources.list.d/debian.sources
        {
          echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/$SNAPSHOT bookworm main"
          echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/$SNAPSHOT bookworm-updates main"
          echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/$SNAPSHOT bookworm-security main"
        } > /etc/apt/sources.list
        apt-get -q update >&2
        apt-get -q install -y --no-install-recommends libgtk-3-dev >&2
      fi
      mkdir -p "$SRC" "$CARGO_HOME"
      chown "$BUILD_UID:$BUILD_UID" "$SRC" "$CARGO_HOME"
      exec setpriv --reuid="$BUILD_UID" --regid="$BUILD_UID" --clear-groups sh -euc "
        umask $MASK
        tar -x -C \"\$SRC\"
        cd \"\$SRC\"
        # Paths into the source and the registry end up in panic messages:
        # the same ones, whatever they are here.
        export RUSTFLAGS=\"--remap-path-prefix=\$SRC=/sharp256 --remap-path-prefix=\$CARGO_HOME=/cargo\"
        bins=
        for b in \$BINS; do bins=\"\$bins --bin \$b\"; done
        cargo build --release --locked -j \"\$JOBS\" \$FEATURES \$bins >&2
        cd target/release
        tar -c \$BINS
      "
    '
}

first() {
  git archive --format=tar "$1" | build_in "" 0 /build/sharp256 /usr/local/cargo "$(nproc)" 022
}

second() {
  git archive --format=tar "$1" | build_in \
    "--hostname elsewhere -e HOME=/tmp -e TZ=Asia/Tokyo -e LANG=C.UTF-8 -e LC_ALL=C.UTF-8" \
    4321 /tmp/some/other/place/sharp-256 /tmp/another-cargo-home 2 077
}

build() {
  rev=$(git rev-parse --verify "${1:-HEAD}^{commit}")
  out="${2:-target/repro/$rev-$VARIANT}"
  mkdir -p "$out"
  echo "building $rev ($VARIANT) in $IMAGE" >&2
  first "$rev" | tar -x -C "$out"
  # shellcheck disable=SC2086
  (cd "$out" && sha256sum $BINS > SHA256SUMS && cat SHA256SUMS)
}

check() {
  rev=$(git rev-parse --verify "${1:-HEAD}^{commit}")
  dir="target/repro/check-$rev-$VARIANT"
  rm -rf "$dir"
  mkdir -p "$dir/a" "$dir/b"
  echo "first build of $rev ($VARIANT)" >&2
  first "$rev" | tar -x -C "$dir/a"
  echo "second build: another user, directory, registry, umask, zone, locale, host, jobs" >&2
  second "$rev" | tar -x -C "$dir/b"
  # shellcheck disable=SC2086
  (cd "$dir/a" && sha256sum $BINS > SHA256SUMS)
  # shellcheck disable=SC2086
  (cd "$dir/b" && sha256sum $BINS > SHA256SUMS)
  echo "commit:  $rev"
  echo "image:   $IMAGE"
  echo "variant: $VARIANT"
  cat "$dir/a/SHA256SUMS"
  if cmp -s "$dir/a/SHA256SUMS" "$dir/b/SHA256SUMS"; then
    echo "check: both builds are the same, byte for byte"
  else
    echo "check: the builds differ"
    diff "$dir/a/SHA256SUMS" "$dir/b/SHA256SUMS" || true
    exit 1
  fi
}

case "${1:-}" in
  build) shift; build "$@" ;;
  check) shift; check "$@" ;;
  *) sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
