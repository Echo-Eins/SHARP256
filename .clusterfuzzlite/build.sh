#!/bin/bash -eu
# ClusterFuzzLite's build (Dockerfile): every target in fuzz/, and its seeds,
# into $OUT. The image's cargo adds the sanitizer's flags; for a coverage
# build it makes this a plain instrumented build (in debug, which has no
# debug assertions to stop at).
set -eu
cd "$SRC/sharp256"

if [ "$SANITIZER" = coverage ]; then
    # Which way each condition went, not only which lines ran.
    export RUSTFLAGS="$RUSTFLAGS -Zcoverage-options=branch"
fi

# Optimised, and with the debug assertions the code has: they are checks
# too.
cargo fuzz build -O --debug-assertions
for t in $(cargo fuzz list); do
    cp "fuzz/target/x86_64-unknown-linux-gnu/release/$t" "$OUT/"
    # The seeds, and every input that ever crashed a target.
    seeds="fuzz/corpus/$t"
    if [ -n "$(ls -A "$seeds" 2>/dev/null)" ]; then
        (cd "$seeds" && zip -q -r "$OUT/${t}_seed_corpus.zip" .)
    fi
done
