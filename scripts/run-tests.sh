#!/bin/bash
# Run nginx-tests against the Rust binary and compare with the C baseline (docs/c-pass.txt).
# Usage: scripts/run-tests.sh [-b binary] [-j N] [tests...]   (default: all tests, release binary)
set -u
ROOT=/home/ubuntu/rnginx
BIN=$ROOT/target/release/nginx
JOBS=8
while getopts "b:j:" o; do case $o in b) BIN=$OPTARG;; j) JOBS=$OPTARG;; esac; done
shift $((OPTIND-1))
OUT=${OUT:-/tmp/rnginx-tests.txt}
cd $ROOT/nginx-tests
if [ $# -eq 0 ]; then set -- .; fi
TEST_NGINX_BINARY=$BIN timeout 1200 prove -j $JOBS --timer --exec "timeout 60 perl" "$@" > $OUT 2>&1
grep -aE "\.t \.+ ok" $OUT | sed -E 's/^\[[^]]*\] \.\///; s/ \.+ ok.*//' | sort > /tmp/rnginx-pass.txt
echo "pass: $(wc -l < /tmp/rnginx-pass.txt)   C-pass: $(wc -l < $ROOT/docs/c-pass.txt)"
if [ "$1" = "." ]; then
  echo "--- passing under C but not under Rust: $(comm -13 /tmp/rnginx-pass.txt $ROOT/docs/c-pass.txt | wc -l)"
  comm -13 /tmp/rnginx-pass.txt $ROOT/docs/c-pass.txt | tr '\n' ' '; echo
fi
grep -aE "^(Files=|Result:)" $OUT
