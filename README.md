# rnginx

rnginx is a drop-in replacement for [nginx](https://nginx.org), written in Rust. It is a function-by-function port of nginx 1.31.7. It reads the same configuration files, takes the same command-line options and signals, and produces the same responses and log messages. nginx's [documentation](https://nginx.org/en/docs/) applies to it.

- **Coverage:** every nginx module is ported except mail and three HTTP modules that wrap external libraries: embedded Perl, XSLT and the image filter. rnginx runs on Linux only.
- **Performance:** rnginx has 80–90% of C nginx's throughput overall. Small proxied requests run at 0.63× C's speed, and HTTP/2 at up to 1.46×.
- **Memory safety:** all of the code compiles under `#![forbid(unsafe_code)]`, except one small crate of system and OpenSSL calls. That rules out buffer overflows, use-after-free and memory disclosure in the server's own code. Bugs of that kind are behind more than half of nginx's security advisories.

## Status

rnginx aims to behave exactly like nginx: the same directives, defaults and variables, the same error and log messages, the same response bytes and header order. nginx's own test suite, [nginx-tests](https://github.com/nginx/nginx-tests), checks this. rnginx passes 455 of its 501 test files. Of the other 46:
- 31 need a module that is not ported (see below);
- 15 are skipped on the test machine with C nginx too: Windows-only tests, tests that need root or OpenSSL 3.5, and long-running tests.

What is ported:
- **Core:** master and worker processes, the signals (reload, log reopening, graceful shutdown, binary upgrade), shared memory zones, the resolver, and the control API (`-l`).
- **HTTP:** HTTP/1.1, HTTP/2, HTTP/3 over QUIC, TLS, and every HTTP module except the three listed below. That includes:
  - proxying to HTTP/1.x and HTTP/2 upstreams, FastCGI, uwsgi, SCGI, gRPC and memcached;
  - caching and load balancing;
  - rewrite, SSI, gzip, sub, slice, mp4, DAV, auth_request, limit_req and json.
- **Stream:** TCP and UDP proxying, TLS, ssl_preread, load balancing, and the other stream modules.

What is not ported:

| | |
|---|---|
| mail (POP3, IMAP and SMTP proxy) | The `mail` block is parsed, so a configuration that has one still starts, but no mail listener is opened. |
| the `perl`, `xslt` and `image_filter` HTTP modules | Their directives are accepted and do nothing. |
| the `google_perftools` module | Its directive is unknown. |
| dynamic modules | `load_module` fails, so third-party C modules (njs, Lua, Brotli, ...) cannot be loaded. |
| platforms other than Linux | The event loop uses epoll. nginx's Windows port and its other event methods (kqueue, eventport, /dev/poll, select, poll) are not ported. |

Some directives are accepted but have no effect:
- `thread_pool`, `aio on` and `aio threads`: files are read synchronously.
- `quic_bpf`, `epoll_events` and `worker_aio_requests`.

[docs/SAFETY.md](docs/SAFETY.md#differences-from-c-introduced-by-the-conversion) lists the smaller differences from C. For example, gzip output can differ from C's byte for byte (the decompressed content is the same).

## Performance

The benchmark ran on 2026-10-05, against C nginx 1.31.7 built at `-O2` with the same modules. The machine had 8 CPUs: the server under test was pinned to two of them, and the load generators (wrk, h2load, oha) to four others. rnginx and C took turns, three runs of each scenario, and the ratios compare the medians. The harness is in [bench/](bench/README.md), and [bench/PLAN.md §1.6](bench/PLAN.md#16-after-phase-0-the-full-run-master-aabbd30) has the full results.

| | rnginx ÷ C |
|---|--:|
| requests per second, geometric mean of 35 scenarios | **0.87×** |
| the same without `h1-sub-filter-sendfile`, where C is unusually slow | 0.83× |
| CPU time per request | 1.17× |

| Workload | Scenario | rnginx ÷ C |
|---|---|--:|
| static file, 1 MB | `h1-static-1m` | 1.00× |
| static file, 1 KB | `h1-static-1k` | 0.74× |
| `return 200` | `h1-return` | 0.72× |
| HTTPS, 1 KB | `tls-h1-1k` | 0.75× |
| TLS handshakes, RSA | `tls-handshake-rsa` | 0.97× |
| gzip | `h1-gzip` | 0.98× |
| HTTP/2 over TLS, 1 KB | `h2-tls-1k` | 1.06× |
| HTTP/2 cleartext, 1 KB | `h2c-1k` | 1.46× |
| HTTP/3, 1 KB | `h3-1k` | 0.65× |
| reverse proxy, 1 KB, keepalive to the upstream | `proxy-1k-keepalive` | 0.63× |
| reverse proxy, 100 KB | `proxy-100k` | 0.84× |
| proxy cache hit | `proxy-cache-hit` | 0.69× |
| gRPC | `grpc-pass` | 0.75× |
| TCP proxy (stream) | `stream-tcp-proxy` | 0.88× |

- **At parity:** large transfers, TLS handshakes and gzip, where most of the time goes to the kernel, OpenSSL or zlib.
- **Ahead of C:** HTTP/2 with small responses. rnginx batches frames into fewer writes, so it spends less time in the kernel.
- **Behind C:** small HTTP/1.1 and proxied requests, at 0.63–0.78×. rnginx makes the same system calls as C, but spends more user-space CPU per request, on allocations and async layers.
- **Memory per idle connection:** 2.3 KB for HTTP/1.1, against C's 0.55 KB. For TLS it is 1.1× C's, and for HTTP/2 1.5×.

## Memory safety

rnginx is about 190,000 lines of Rust in six crates. Five of them are `#![forbid(unsafe_code)]`: `ngx-core`, `ngx-http`, `ngx-stream`, `ngx-mail` and the `nginx` binary. The compiler rejects any `unsafe` code in them. This code cannot have buffer overflows or over-reads, use-after-free, double frees, or reads of uninitialized memory. An index past the end of a buffer stops the worker instead of reading or writing outside the buffer, and a use-after-free does not compile.

This class of bug is behind more than half of nginx's [security advisories](https://nginx.org/en/security_advisories.html). As of October 2026, 35 of the 63 are buffer overflows, over-reads, use-after-free, memory corruption or memory disclosure. Examples:
- "Stack-based buffer overflow with specially crafted request" (CVE-2013-2028);
- "1-byte memory overwrite in resolver" (CVE-2021-23017);
- "Use-after-free in HTTP/3" (CVE-2024-24990).

The guarantee does not cover:
- **`crates/ngx-sys`:** 2,500 lines with 127 `unsafe` blocks, each with a `// SAFETY:` comment. It holds the OpenSSL calls that the `openssl` crate has no safe API for, and a few system calls such as `fork` and `setproctitle`. No raw pointer crosses its API.
- **C libraries:** OpenSSL, PCRE2 and zlib, the same ones C nginx uses.
- **Dependencies:** the `unsafe` code inside std, tokio, the `openssl` crate, nix, rustix and rnginx's other dependencies.
- **Other kinds of bugs:** logic bugs, request smuggling and resource exhaustion. A panic, such as an out-of-bounds index, aborts the worker process and its connections, and the master starts a new worker, as it does when a C worker crashes.

[docs/SAFETY.md](docs/SAFETY.md) describes what replaced each use of `unsafe`.

## Building

You need Linux, a stable Rust toolchain (development uses 1.96), a C compiler, pkg-config, and the development files of OpenSSL, PCRE2 and zlib. On Debian or Ubuntu:

```sh
sudo apt install build-essential pkg-config libssl-dev libpcre2-dev zlib1g-dev
cargo build --release
```

The binary is `target/release/nginx`. The release profile uses fat LTO and links jemalloc. To build with glibc's malloc instead, use `cargo build --release --no-default-features`.

## Running

rnginx takes nginx's command line:

```sh
nginx -t -c /etc/nginx/nginx.conf           # test a configuration
nginx -c /etc/nginx/nginx.conf              # start
nginx -c /etc/nginx/nginx.conf -s reload    # or stop, quit, reopen
```

`nginx -V` lists the built-in modules.

The compiled-in paths are those of a default `./configure` build:
- the prefix is `/usr/local/nginx/`;
- the configuration file is `conf/nginx.conf`;
- logs and temporary files go under the prefix.

Distribution packages compile in other paths. If you replace a packaged nginx:
- Pass its paths with `-p`, `-c` and `-e`, or set them in nginx.conf (`pid`, `error_log`, `client_body_temp_path`, `proxy_temp_path` and so on).
- Remove the `load_module` lines, such as the ones Debian and Ubuntu include from `/etc/nginx/modules-enabled/`. The stream and GeoIP modules are built in, and other dynamic modules cannot be loaded.

## Testing

nginx's test suite runs against any nginx binary:

```sh
git clone https://github.com/nginx/nginx-tests
cd nginx-tests
TEST_NGINX_BINARY=/path/to/rnginx/target/release/nginx prove -j 8 .
```

The suite skips a test file whose prerequisites are missing. The 455 passing files above are from nginx-tests revision `4061685`, on Ubuntu 22.04 with these packages:

```sh
sudo apt install libio-socket-ssl-perl libio-socket-inet6-perl libcryptx-perl \
    libprotocol-websocket-perl libfcgi-perl libscgi-perl libcache-memcached-perl \
    libcache-memcached-fast-perl memcached uwsgi uwsgi-plugin-python3 ffmpeg
```

To run the unit tests, use `cargo test --workspace`.

## Layout

| | |
|---|---|
| `crates/ngx-core` | the core: configuration, processes, the event loop and connections (on tokio), shared memory, the resolver, TLS, QUIC, regular expressions, logging |
| `crates/ngx-http` | HTTP/1.1, HTTP/2, HTTP/3 and the HTTP modules |
| `crates/ngx-stream` | the stream (TCP and UDP) modules |
| `crates/ngx-mail` | parsing of the `mail` block only |
| `crates/nginx` | the binary |
| `crates/ngx-sys` | the only crate with `unsafe` code: the system and OpenSSL calls that no safe crate provides |
| `bench/` | the benchmark harness against C nginx, its reports, and the plan to reach parity |
| `docs/SAFETY.md` | how the port avoids `unsafe` code, and the differences from C that this causes |
| `CONVENTIONS.md` | rules for contributors |

## License

rnginx uses the BSD 2-Clause license, the same as nginx; see [LICENSE](LICENSE). rnginx is an independent project, not affiliated with F5, Inc. or the nginx project. NGINX is a trademark of F5, Inc.
