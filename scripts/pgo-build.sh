#!/bin/bash
# Build nginx with profile-guided optimization (docs/PERF_PLAN.md §4): an
# instrumented build, a training run of the benchmark's scenarios, the merged
# profile, and the release build that uses it. Measured on 11 scenarios: +8%
# to +32% requests per second, +17.8% on their geometric mean.
#
# Usage: scripts/pgo-build.sh [-o output] [-s scenarios] [-d seconds]
#   -o  where to copy the binary (it is built as target/pgo/use/release/nginx)
#   -s  the training scenarios, comma-separated names of bench.py --list
#   -d  seconds of load per scenario (default 3)
#
# Needs the llvm-tools component (rustup component add llvm-tools) and the
# benchmark harness set up (bench/README.md): the training is bench.py run
# with the instrumented binary. Takes about 10 minutes.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
T=$ROOT/target/pgo
OUT=
SECS=3
# a broad mix, so that no protocol or module on the hot paths is left cold:
# a profile from a narrow load makes the rest slower
SCENARIOS=h1-return,h1-static-1k,h1-static-100k,h1-conn-close,h1-regex-rewrite,h1-access-log,h1-gzip,h1-sub-filter,h1-limit-req,tls-h1-1k,tls-resume-ecdsa,h2-tls-1k,h2c-1k,h2c-100k,h3-1k,proxy-1k-keepalive,proxy-1k-no-keepalive,proxy-100k,proxy-post-10k,proxy-tls-terminate,proxy-to-tls-upstream,proxy-cache-hit,proxy-h2-upstream,grpc-pass,fastcgi-1k,stream-tcp-proxy,stream-tls-terminate
while getopts "o:s:d:" o; do
    case $o in
    o) OUT=$(realpath -m "$OPTARG") ;;
    s) SCENARIOS=$OPTARG ;;
    d) SECS=$OPTARG ;;
    *) exit 2 ;;
    esac
done

PROFDATA=$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/llvm-profdata
if [ ! -x "$PROFDATA" ]; then
    echo "llvm-profdata not found: rustup component add llvm-tools" >&2
    exit 1
fi

# the instrumented build: each process merges its counts into the profile
# of the directory when it exits (the workers on QUIT or TERM). The build
# scripts and proc macros, instrumented too, leave theirs while it builds:
# they go before the training
mkdir -p "$T/data"
RUSTFLAGS="${RUSTFLAGS:-} -Cprofile-generate=$T/data" cargo build --release -p nginx --target-dir "$T/gen"
rm -f "$T"/data/*.profraw "$T"/data/merged.profdata

# the training, under the lock of the benchmark's ports and CPUs
cd "$ROOT/bench"
NGX_BENCH_BIN=$T/gen/release/nginx flock /tmp/nginx-bench.lock \
    python3 bench.py --only "$SCENARIOS" --servers custom --reps 1 --duration "$SECS" --warmup 1 --out "$T/train.jsonl"

if ! ls "$T"/data/*.profraw > /dev/null 2>&1; then
    echo "the training wrote no profile" >&2
    exit 1
fi
"$PROFDATA" merge -o "$T/data/merged.profdata" "$T"/data/*.profraw

cd "$ROOT"
RUSTFLAGS="${RUSTFLAGS:-} -Cprofile-use=$T/data/merged.profdata" cargo build --release -p nginx --target-dir "$T/use"

if [ -n "$OUT" ]; then
    cp "$T/use/release/nginx" "$OUT"
fi
echo "built: $T/use/release/nginx${OUT:+, copied to $OUT}"
