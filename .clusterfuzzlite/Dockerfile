# The image ClusterFuzzLite builds the fuzz targets in (build.sh): OSS-Fuzz's
# for Rust — its nightly toolchain, cargo-fuzz and libFuzzer — pinned by
# digest, like every image the project builds with. To move it on, take the
# digest the tag has now:
#
#   curl -sI -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' \
#     https://gcr.io/v2/oss-fuzz-base/base-builder-rust/manifests/v1 | grep -i digest
FROM gcr.io/oss-fuzz-base/base-builder-rust:v1@sha256:973fc05cf533db8853c01eb4a13f94781bcae62bcc65057988c8bc37641df07d
COPY . $SRC/sharp256
WORKDIR $SRC/sharp256
COPY .clusterfuzzlite/build.sh $SRC/
