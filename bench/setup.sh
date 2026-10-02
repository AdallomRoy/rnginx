#!/bin/bash
# What bench.py and analyze.py need that is not in git: the certificates, the
# files served, the helper tools, oha, and the two nginx builds. Each step is
# skipped when its output exists. The packages it needs are in README.md.
set -euo pipefail
B=$(cd "$(dirname "$0")" && pwd)
R=$(cd "$B/.." && pwd)
mkdir -p "$B"/{bin,certs,www,www-extra,src,run,logs,results}

# certificates for localhost: RSA for the TLS scenarios, ECDSA for the
# handshake one
cd "$B/certs"
SUBJ=(-subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1")
[ -f rsa.crt ] || openssl req -x509 -newkey rsa:2048 -nodes -keyout rsa.key -out rsa.crt -days 3650 "${SUBJ[@]}" 2>/dev/null
[ -f ec.crt ] || openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout ec.key -out ec.crt -days 3650 "${SUBJ[@]}" 2>/dev/null

# the files served: random bodies, and HTML text from a fixed seed (the
# checks of the sub_filter and gzip scenarios expect its size, 102575 bytes
# for 100k.html, and its count of "quick")
cd "$B/www"
for f in 1k:1024 100k:102400 1m:1048576 10m:10485760; do
    [ -f "${f%%:*}.bin" ] || head -c "${f#*:}" /dev/urandom > "${f%%:*}.bin"
done
[ -f index.html ] || echo ok > index.html
[ -f 100k.html ] || python3 - <<'EOF'
import random
random.seed(42)
words = "the quick brown fox jumps over lazy dog nginx server request response header body proxy upstream cache connection keepalive worker process event loop buffer chain filter module location rewrite variable".split()
parts = ["<!DOCTYPE html><html><head><title>bench</title></head><body>\n"]
size = 0
i = 0
while size < 100*1024:
    line = "<p class=\"c%d\">%s</p>\n" % (i % 17, " ".join(random.choice(words) for _ in range(random.randint(8, 20))))
    parts.append(line); size += len(line); i += 1
parts.append("</body></html>\n")
open("100k.html","w").write("".join(parts))
small = "".join(parts)[:1024-15] + "</body></html>\n"
open("1k.html","w").write(small)
EOF
cd "$B/www-extra"
[ -f post10k.bin ] || head -c 10240 /dev/zero | tr '\0' a > post10k.bin
[ -f ssi.html ] || printf 'head <!--# include virtual="/inc/1k.html" --> tail\n' > ssi.html

# the FastCGI backend, the idle-connection client, the malloc counter
GO=$(command -v go || echo /usr/local/go/bin/go)
cd "$B/tools"
[ -x "$B/bin/fcgiserver" ] || "$GO" build -o "$B/bin/fcgiserver" ./fcgiserver
[ -x "$B/bin/idleconns" ] || "$GO" build -o "$B/bin/idleconns" ./idleconns
[ -f "$B/bin/libmcount.so" ] || gcc -O2 -fPIC -shared -o "$B/bin/libmcount.so" mcount/mcount.c -lpthread

# oha 1.16, and a build of it with HTTP/3 for the h3 scenarios
[ -x "$B/bin/oha" ] || { cargo install oha --version 1.16.0 --root "$B/src/oha" && cp "$B/src/oha/bin/oha" "$B/bin/oha"; }
[ -x "$B/bin/oha-h3" ] || { cargo install oha --version 1.16.0 --features http3 --root "$B/src/oha-h3" && cp "$B/src/oha-h3/bin/oha" "$B/bin/oha-h3"; }

# the Rust build, then C nginx with its module list
[ -x "$B/bin/nginx-rust" ] || { (cd "$R" && cargo build --release) && cp "$R/target/release/nginx" "$B/bin/nginx-rust"; }
[ -x "$B/bin/nginx-c-O2" ] || "$B/build-c.sh"
echo "setup done"
