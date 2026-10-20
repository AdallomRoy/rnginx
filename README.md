# rnginx

rnginx is a drop-in replacement for [nginx](https://nginx.org), written in Rust. It is a function-by-function port of nginx 1.31.7. It reads the same configuration files, takes the same command-line options and signals, and produces the same responses and log messages. nginx's [documentation](https://nginx.org/en/docs/) applies to it.

- **Coverage:** every nginx module is ported except mail and three HTTP modules that wrap external libraries: embedded Perl, XSLT and the image filter. rnginx runs on Linux only.
- **Performance:** built with profile-guided optimization (`scripts/pgo-build.sh`), rnginx has 108% of C nginx's throughput overall, at 94% of its CPU time per request. Small static files and HTTP/2 run faster than C (1.28× and up to 2.17×), small proxied requests at 0.80–0.87× of C's speed. A plain `cargo build --release` has 96% of C's throughput.
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
| platforms other than Linux | The event loop uses io_uring where the kernel allows it (Linux 6.0 and later; containers often block it), epoll otherwise; `use epoll;` selects epoll. nginx's Windows port and its other event methods (kqueue, eventport, /dev/poll, select, poll) are not ported. |

Some directives are accepted but have no effect:
- `thread_pool`, `aio on` and `aio threads`: files are read synchronously.
- `quic_bpf`, `epoll_events` and `worker_aio_requests`.

[docs/SAFETY.md](docs/SAFETY.md#differences-from-c-introduced-by-the-conversion) lists the smaller differences from C. For example, gzip output can differ from C's byte for byte (the decompressed content is the same).

## Performance

The benchmark ran on 2026-10-20, against C nginx 1.31.7 built at `-O2` with the same modules. rnginx used io_uring, its default event method; C nginx uses epoll. The machine had 8 CPUs: the server under test was pinned to two of them, and the load generators (wrk, h2load, oha) to four others. C and two rnginx builds of the same code took turns, three runs of each scenario, and the ratios compare the medians: the build with profile-guided optimization (`scripts/pgo-build.sh`), and a plain `cargo build --release`. The harness is in [bench/](bench/README.md), and [bench/PLAN.md §1.8](bench/PLAN.md#18-with-profile-guided-optimization-the-full-run-master-bee4068) has the full results.

| | rnginx ÷ C, PGO | plain release build |
|---|--:|--:|
| requests per second, geometric mean of 35 scenarios | **1.08×** | 0.96× |
| the same without `h1-sub-filter-sendfile`, where C is unusually slow | **1.03×** | 0.92× |
| CPU time per request | **0.94×** | 1.06× |

| Workload | Scenario | rnginx ÷ C, PGO | plain |
|---|---|--:|--:|
| static file, 1 MB | `h1-static-1m` | **1.01×** | 1.01× |
| static file, 1 KB | `h1-static-1k` | **1.28×** | 1.11× |
| `return 200` | `h1-return` | **1.05×** | 0.94× |
| HTTPS, 1 KB | `tls-h1-1k` | **1.08×** | 0.91× |
| TLS handshakes, RSA | `tls-handshake-rsa` | **0.98×** | 0.96× |
| gzip | `h1-gzip` | **1.00×** | 0.99× |
| HTTP/2 over TLS, 1 KB | `h2-tls-1k` | **1.25×** | 1.08× |
| HTTP/2 cleartext, 1 KB | `h2c-1k` | **1.70×** | 1.47× |
| HTTP/3, 1 KB | `h3-1k` | **0.88×** | 0.64× |
| reverse proxy, 1 KB, keepalive to the upstream | `proxy-1k-keepalive` | **0.84×** | 0.68× |
| reverse proxy, 100 KB | `proxy-100k` | **0.90×** | 0.83× |
| proxy cache hit | `proxy-cache-hit` | **1.11×** | 0.95× |
| gRPC | `grpc-pass` | **0.92×** | 0.78× |
| TCP proxy (stream) | `stream-tcp-proxy` | **0.99×** | 0.97× |
| TCP proxy (stream), bulk transfer | `stream-bulk-iperf` | **0.96×** | 0.92× |

- **Profile-guided optimization** makes rnginx 12% faster on these scenarios: the 40 MB binary carries every module, and the profile lays out the code that requests run together. It cuts user-space CPU per request by 20–40%.
- **At parity:** large transfers, TLS handshakes and gzip, where most of the time goes to the kernel, OpenSSL or zlib.
- **Ahead of C:** small requests on HTTP/1.1 and HTTP/2, small static files, the proxy cache. With io_uring, one system call submits the reads and writes of many connections. With `sendfile on`, a static file of up to 16 KB goes out in one send with its header, where C makes a `writev()` and a `sendfile()` (and, with `tcp_nopush on`, two `setsockopt()` calls). The HTTP/2 code batches frames into fewer writes.
- **Behind C:** proxied requests (0.80–0.93×), HTTP/3 (0.86–0.88×; its UDP sockets do not use io_uring) and `sub_filter` (0.89×). There rnginx spends more user-space CPU per request than C, on allocations and async layers ([docs/PERF_PLAN.md](docs/PERF_PLAN.md)).
- **With epoll** (`use epoll;`, or where the kernel does not allow io_uring, as in many containers), the plain build is at about 0.87× of C overall (the run of 2026-10-05, [bench/PLAN.md §1.6](bench/PLAN.md#16-after-phase-0-the-full-run-master-aabbd30)).
- **Memory per idle connection:** 2.5 KB for HTTP/1.1, against C's 0.56 KB. For TLS it is 1.1× C's, and for HTTP/2 1.5×.

## Memory safety

rnginx is about 195,000 lines of Rust in six crates. Five of them are `#![forbid(unsafe_code)]`: `ngx-core`, `ngx-http`, `ngx-stream`, `ngx-mail` and the `nginx` binary. The compiler rejects any `unsafe` code in them. This code cannot have buffer overflows or over-reads, use-after-free, double frees, or reads of uninitialized memory. An index past the end of a buffer stops the worker instead of reading or writing outside the buffer, and a use-after-free does not compile.

This class of bug is behind more than half of nginx's [security advisories](https://nginx.org/en/security_advisories.html). As of October 2026, 35 of the 63 are buffer overflows, over-reads, use-after-free, memory corruption or memory disclosure. Examples:
- "Stack-based buffer overflow with specially crafted request" (CVE-2013-2028);
- "1-byte memory overwrite in resolver" (CVE-2021-23017);
- "Use-after-free in HTTP/3" (CVE-2024-24990).

The guarantee does not cover:
- **`crates/ngx-sys`:** 4,000 lines with 157 `unsafe` blocks, each with a `// SAFETY:` comment. It holds the OpenSSL calls that the `openssl` crate has no safe API for, the io_uring ring, which owns every buffer the kernel may use until the operation completes, and a few system calls such as `fork` and `setproctitle`. No raw pointer crosses its API.
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

For the fastest binary, build with profile-guided optimization: `scripts/pgo-build.sh` builds an instrumented binary, runs the benchmark's scenarios through it, and builds `target/pgo/use/release/nginx` with the profile they leave. In the benchmark it handles 8–32% more requests per second than the plain release build. It takes about 10 minutes, and needs the rustup component `llvm-tools` and the benchmark harness ([bench/README.md](bench/README.md)).

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
| `crates/ngx-core` | the core: configuration, processes, the event loop and connections (on tokio, with io_uring or epoll), shared memory, the resolver, TLS, QUIC, regular expressions, logging |
| `crates/ngx-http` | HTTP/1.1, HTTP/2, HTTP/3 and the HTTP modules |
| `crates/ngx-stream` | the stream (TCP and UDP) modules |
| `crates/ngx-mail` | parsing of the `mail` block only |
| `crates/nginx` | the binary |
| `crates/ngx-sys` | the only crate with `unsafe` code: the system and OpenSSL calls that no safe crate provides, and the io_uring ring |
| `bench/` | the benchmark harness against C nginx, its reports, and the plan to reach parity |
| `docs/SAFETY.md` | how the port avoids `unsafe` code, and the differences from C that this causes |
| `docs/IO_URING_PLAN.md` | the design of the io_uring event method, what it measured, and its status |
| `docs/PERF_PLAN.md` | where rnginx's CPU time per request goes against C's, and the plan to cut it |
| `scripts/pgo-build.sh` | the build with profile-guided optimization |
| `CONVENTIONS.md` | rules for contributors |

## License

rnginx uses the BSD 2-Clause license, the same as nginx; see [LICENSE](LICENSE). rnginx is an independent project, not affiliated with F5, Inc. or the nginx project. NGINX is a trademark of F5, Inc.
