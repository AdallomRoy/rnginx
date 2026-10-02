#!/bin/bash
# Build C nginx with exactly the module set the Rust port reports in `nginx -V`
# (HTTP/3 included), at -O2 (distro-style); keep --with-debug because the Rust
# port always compiles its debug-log checks in (runtime-checked, like C
# --with-debug). The build runs in a copy of the C source (src/nginx-c), so
# the oracle build in ../nginx-c is not touched.
#
#     build-c.sh [RUST_BINARY]        (default: bin/nginx-rust)
set -euo pipefail
B=$(cd "$(dirname "$0")" && pwd)
RUST=${1:-$B/bin/nginx-rust}
ARGS=$("$RUST" -V 2>&1 | sed -n 's/^configure arguments: //p')
mkdir -p "$B/bin" "$B/logs" "$B/src"
[ -d "$B/src/nginx-c" ] || cp -a "$B/../nginx-c" "$B/src/nginx-c"
cd "$B/src/nginx-c"
rm -rf objs Makefile
./auto/configure $ARGS --with-cc-opt=-O2 > "$B/logs/nginx-c-O2-configure.log" 2>&1
make -j4 > "$B/logs/nginx-c-O2-build.log" 2>&1
cp objs/nginx "$B/bin/nginx-c-O2"
