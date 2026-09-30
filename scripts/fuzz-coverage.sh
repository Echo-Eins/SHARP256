#!/bin/sh
# What a corpus of the fuzz targets reaches, down to the branches: the
# targets built with coverage instrumentation as ClusterFuzzLite's coverage
# build is (debug, no debug assertions, and branch coverage), each run once
# over its corpus, and a report per source file of the crate — functions,
# lines, regions and branches (docs/FUZZING.md, docs/evidence/fuzzing/).
#
#   sh scripts/fuzz-coverage.sh CORPUS [TARGET...]
#
# CORPUS holds a directory per target: fuzz/corpus is the seeds; what the
# batch runs keep is the artifact cifuzz-corpus-<target> of the last one
# (a tar inside). Needs the nightly toolchain with llvm-tools. Writes into
# target/fuzz-coverage (or $SHARP_COVERAGE_DIR): the build, the profiles,
# each run's log, and report.txt.
set -eu
cd "$(dirname "$0")/.."
corpus=$(cd "$1" && pwd)
shift
out=${SHARP_COVERAGE_DIR:-$(pwd)/target/fuzz-coverage}
host=$(rustc +nightly -vV | sed -n 's/^host: //p')
llvm="$(rustc +nightly --print sysroot)/lib/rustlib/$host/bin"

# With --target the flags reach the targets only: build scripts and
# proc-macros instrumented would leave profiles wherever they ran.
RUSTFLAGS="--cfg fuzzing -Cinstrument-coverage -Zcoverage-options=branch -Cdebug-assertions=no" \
    cargo +nightly build --manifest-path fuzz/Cargo.toml --bins --target "$host" --target-dir "$out/build"

rm -rf "$out/prof"
mkdir -p "$out/prof"
first=
objects=
for t in ${*:-$(ls fuzz/fuzz_targets | sed 's/\.rs$//')}; do
    [ -d "$corpus/$t" ] || continue
    exe="$out/build/$host/debug/$t"
    # -runs=0: every input once, and nothing new.
    LLVM_PROFILE_FILE="$out/prof/$t.profraw" "$exe" -runs=0 "$corpus/$t" >"$out/prof/$t.log" 2>&1
    echo "$t: $(ls "$corpus/$t" | wc -l) inputs"
    if [ -z "$first" ]; then first=$exe; else objects="$objects -object $exe"; fi
done

"$llvm/llvm-profdata" merge -sparse "$out"/prof/*.profraw -o "$out/merged.profdata"
# The crate's own code only: not its dependencies, not the targets, not the
# harnesses in src/fuzz/ that drive it.
# shellcheck disable=SC2086
"$llvm/llvm-cov" report "$first" $objects \
    -instr-profile="$out/merged.profdata" \
    -ignore-filename-regex='/\.cargo/|/rustlib/|/rustc/|/fuzz_targets/|/src/fuzz/' \
    -show-branch-summary >"$out/report.txt"
echo "report: $out/report.txt"
