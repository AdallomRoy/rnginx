# nginx C vs. Rust port (rnginx): benchmark report

Date: 2026-10-01. Compared: nginx 1.31.7 C (`nginx-c/`) and the Rust port (`master` @ `1196fa6`).
Raw data: `results/*.jsonl`. Harness: `bench.py`, `report.py`, `extra.py`, `profile2.py`.

## TL;DR

* **Throughput:** across 32 saturation scenarios the Rust port delivers **0.50× the requests/s of C** (geometric mean).
  It spends **2.06× the CPU per request**. The range runs from 0.11× (sub_filter) to 1.13× (1 MB static files, where C was not CPU-bound).
* **At equal load (10k req/s fixed)** Rust uses **2.2–3.0× the CPU**, and its p99 latency is 2–2.6× C's
  (static 1 KB: 0.60 ms vs 0.23 ms).
* **Close to parity** where a shared C library does the work: gzip (0.98×), TLS handshakes (0.93–1.01×, OpenSSL),
  bulk TLS (0.84×), HTTP/2 with 100 KB bodies (0.81×), and the **stream (L4) module (0.75–0.78×)**. The stream module is the most efficient part of the port.
* **Furthest from parity:** small HTTP/1.1 requests (0.31–0.38×), proxying (0.30–0.37×), proxy_cache hits (0.30×),
  POST bodies through the proxy (0.19×), sub_filter (0.11×).
* **Memory:** Rust has a smaller idle footprint (16.6 vs 28.6 MB PSS). Most of that gap is C preallocating
  `worker_connections` slots; at `worker_connections 1024` C is smaller (13.0 vs 16.5 MB). But Rust uses **about 11× more per idle HTTP/1.1
  connection** (10.8 KB vs about 0.95 KB), 1.7× per TLS connection, and 2.1× per HTTP/2 connection. Under HTTP/2 connection
  churn, Rust with glibc malloc grows to **about 3.3 GB** where C stays at 180 MB.
* **Bugs found in the Rust port** (details in [Correctness issues](#correctness-issues-found-in-the-rust-port)):
  1. **File-descriptor leak when upstream keepalive connections are reused** under concurrency (proxy, proxy_ssl and
     FastCGI). A worker hits its fd limit after a few hundred thousand requests, and new requests then fail with
     `connect() failed (24: Too many open files)`.
  2. **Stream proxy bulk relay stalls**, and both workers then **spin at 100% CPU** (3/3 runs).
  3. **`sub_filter` is silently not applied when `sendfile on`.**
  4. **Request bodies of 8–10 KB are spooled to temp files** (C keeps them in memory). That alone makes proxied POSTs 5× costlier.
* **HTTP/3 cannot be compared:** the Rust port only has a stub for `ngx_http_v3_module` and QUIC. C does about 85k req/s over HTTP/3.

## Setup

| | |
|---|---|
| Machine | AWS r6i.8xlarge, Xeon Platinum 8375C @ 2.9 GHz, Linux 7.0.0-1013-aws, Docker container limited to 8 physical cores (CPUs 0–7, no HT siblings), 247 GB RAM |
| C build | nginx 1.31.7, gcc 11.4 `-O2`, **same module list as the Rust binary reports in `nginx -V`** (no perl/xslt/image_filter/v3/json/control-api), `--with-debug` kept because the Rust port always compiles its debug-log checks in (runtime-checked, like C `--with-debug` and like Ubuntu's nginx packages). `build-c.sh` builds it. The repo's `nginx-c/objs/nginx` is `-O1` and was not used. |
| C HTTP/3 build | as above plus `--with-http_v3_module` (OpenSSL 3.0 compat QUIC), used only for the h3 scenario |
| Rust build | `master` @ 1196fa6 (not the WIP `slice` branch), rustc 1.96.1, release profile `opt-level=3`, no LTO, glibc malloc |
| Libraries | OpenSSL 3.0.2, zlib 1.2.11, PCRE2 10.39, glibc 2.35 (shared by both) |
| CPU layout | nginx under test: 2 workers pinned to CPUs 0 and 1 (`worker_cpu_affinity`). Backends: CPUs 2–3 (a C nginx -O2 as HTTP/HTTPS upstream, a Go FastCGI server, iperf3). Load generators: CPUs 4–7 |
| Tools | wrk 4.1.0 (HTTP/1.1, HTTPS), h2load 1.43 (h2, h2c), oha 1.16 (fixed rate; a `--features http3` build for h3), iperf3 3.9, a Go idle-connection tool (`tools/idleconns`) |
| Config | One template for both (`bench.py: SERVER_CONF`): sendfile + tcp_nopush, keepalive_requests 1M, access_log off (except the log test), worker_connections 20000, ECDSA P-256 cert, TLS 1.3/X25519 |

**Method.** Every run starts a fresh nginx, takes an idle memory snapshot, verifies the response with curl
(status, size, and body content where it matters), warms up for 3 s and then measures for 10 s. Each scenario
runs 3 times with C and Rust alternating, and the tables show medians. Run-to-run spread was usually within 2%.

CPU is the utime+stime of the master and all children, read from `/proc/<pid>/stat` and schedstat.
Memory is the PSS of the master and children (`smaps_rollup`), sampled during the run.

A run counts as valid only if it has zero errors and passes its response checks. The harness also verifies that workers go idle
after the load (spin detection). For proxy scenarios it counts the backend's accepted connections to verify keepalive.

Fairness fixes applied during the work:
* Upstream keepalive is **on by default in nginx 1.31** (`keepalive 32`). The no-keepalive scenario uses
  `keepalive 0` + `Connection: close`, verified at 1.001 new upstream connections per request.
* wrk resumes TLS sessions, so the full-handshake tests use servers with tickets and cache off (verified via `$ssl_session_reused`).
* The sub_filter test uses `sendfile off`, because the Rust port skips the filter with sendfile on (bug 3).

## Results

Columns: throughput (median req/s), Rust/C ratio, wrk/h2load latency (closed loop, so at saturation it mostly reflects
queueing; see the fixed-rate table for latency at equal load), server CPU per request, and peak PSS of all nginx processes.

### HTTP/1.1 (cleartext)

| Scenario | C req/s | Rust req/s | **Rust/C** | C p50 / p99 ms | Rust p50 / p99 ms | C CPU µs/req | Rust CPU µs/req | C peak PSS MB | Rust peak PSS MB |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| `return 200` (12 B, no file I/O) | 250,488 | 96,170 | **0.38×** | 1.05 / 1.28 | 2.65 / 2.84 | 8.0 | 20.7 | 26.2 | 17.3 |
| static 1 KB | 126,929 | 41,964 | **0.33×** | 2.01 / 2.25 | 6.07 / 7.00 | 15.7 | 47.6 | 26.3 | 17.9 |
| static 100 KB (sendfile) | 87,147 | 38,969 | **0.45×** | 0.72 / 0.92 | 1.64 / 1.86 | 22.9 | 51.3 | 26.3 | 15.8 |
| static 1 MB (sendfile) ¹ | 15,732 | 17,798 | **1.13×** | 1.25 / 2.06 | 1.11 / 2.24 | 64.5 | 97.9 | 26.3 | 15.3 |
| new TCP connection per request | 73,416 | 27,874 | **0.38×** | 0.82 / 1.02 | 2.23 / 2.56 | 27.0 | 71.6 | 26.3 | 15.1 |
| 2000 concurrent keep-alive conns | 121,392 | 40,896 | **0.34×** | 16.3 / 18.6 | 44.6 / 55.4 | 16.4 | 48.9 | 27.3 | 37.7 |
| regex location + map + set + if + rewrite + add_header | 210,861 | 68,660 | **0.33×** | 1.21 / 1.41 | 3.72 / 4.56 | 9.5 | 29.1 | 26.4 | 17.6 |
| static 1 KB + buffered access_log | 123,382 | 38,827 | **0.31×** | 2.06 / 2.36 | 6.66 / 7.21 | 16.2 | 51.4 | 26.5 | 18.1 |
| gzip on the fly, 100 KB HTML (level 1) | 2,265 | 2,226 | **0.98×** | 28.0 / 67.0 | 28.5 / 107.7 | 884 | 899 | 27.0 | 32.3 |
| sub_filter, 100 KB HTML, 424 replacements | 7,614 | 826 | **0.11×** | 8.46 / 9.93 | 91.8 / **360–2000** | 263 | 2,426 | 26.3 | 15.9 |
| limit_req (shm zone, never rejects) | 123,023 | 41,196 | **0.33×** | 2.07 / 2.29 | 6.24 / 6.77 | 16.2 | 48.5 | 26.4 | 17.8 |

¹ Not server-bound for C. Its two workers were only 57% and 46% busy, while Rust's were at 87–88% (`results/extra/balance.json`).
The throughput difference comes from the I/O pattern. Rust spends 1.5× the CPU per byte (0.09 vs 0.06 CPU-s/GB).

### HTTPS (TLS 1.3, ECDSA P-256 unless noted)

| Scenario | C req/s | Rust req/s | **Rust/C** | C p50 / p99 ms | Rust p50 / p99 ms | C CPU µs/req | Rust CPU µs/req | C peak PSS MB | Rust peak PSS MB |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| 1 KB, keep-alive | 103,366 | 45,292 | **0.44×** | 2.45 / 2.85 | 5.61 / 6.55 | 19.3 | 44.0 | 37.9 | 27.0 |
| 1 MB, keep-alive (19.3 vs 16.3 Gbit/s) | 2,307 | 1,943 | **0.84×** | 12.9 / 17.2 | 19.4 / 77.4 | 867 | 1,029 | 29.2 | 17.8 |
| new connection per request, session resumption | 6,570 | 5,553 | **0.85×** | – | – | 304 | 359 | 29.9 | 18.3 |
| full handshake per request, ECDSA ² | 4,246 | 4,273 | **1.01×** | – | – | 326 | 373 | 31.1 | 19.6 |
| full handshake per request, RSA 2048 | 3,282 | 3,045 | **0.93×** | – | – | 607 | 656 | 30.1 | 18.8 |

² Neither server was fully CPU-saturated in the ECDSA test (C at 138%, Rust at 160% CPU), so compare CPU per handshake there.

### HTTP/2 and HTTP/3

| Scenario | C req/s | Rust req/s | **Rust/C** | C p50 / p99 ms | Rust p50 / p99 ms | C CPU µs/req | Rust CPU µs/req | C peak PSS MB | Rust peak PSS MB |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| h2 over TLS, 1 KB, 64 conns × 16 streams | 131,702 | 72,664 | **0.55×** | 7.88 / 8.88 | 13.9 / 17.9 | 15.2 | 27.5 | 30.5 | 48.5 |
| h2 over TLS, 100 KB, 32 × 8 | 17,882 | 14,510 | **0.81×** | 14.5 / 19.4 | 17.3 / 25.8 | 112 | 138 | 29.4 | 38.6 |
| h2c (cleartext, prior knowledge), 1 KB | 109,093 | 78,712 | **0.72×** | 9.37 / 17.1 | 12.9 / 15.5 | 18.3 | 25.5 | 27.1 | 46.8 |
| h2 over TLS, `return 200`, 16 × 100 streams | 272,797 | 132,970 | **0.49×** | 5.86 / 8.35 | 13.0 / 14.1 | 7.3 | 15.0 | 28.3 | 40.9 |
| **HTTP/3 (QUIC)**, 1 KB, 32 conns | 84,938 | *not implemented* | – | 0.37 / 0.55 | – | 23.5 | – | 32.2 | – |

### Reverse proxy and FastCGI (C nginx backend on its own cores)

| Scenario | C req/s | Rust req/s | **Rust/C** | C p50 / p99 ms | Rust p50 / p99 ms | C CPU µs/req | Rust CPU µs/req | C peak PSS MB | Rust peak PSS MB |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| proxy_pass 1 KB, upstream keepalive ³ | 104,296 | 35,774 | **0.34×** | 2.43 / 2.79 | 7.23 / 8.26 | 19.1 | 55.8 | 28.3 | 21.2 |
| proxy_pass 1 KB, new upstream connection per request | 35,251 | 17,781 | **0.50×** | 7.19 / 8.56 | 14.4 / 17.3 | 56.6 | 112.2 | 28.3 | 20.0 |
| proxy_pass 100 KB (buffering on) | 19,278 | 12,047 | **0.62×** | 3.34 / 4.74 | 4.81 / 10.2 | 104 | 166 | 26.9 | 16.7 |
| proxy_pass 1 MB (buffering on) ⁴ | 1,818 | 1,980 | **1.09×** | 15.9 / 31.0 | 15.0 / 32.1 | 1,101 | 1,010 | 27.9 | 16.0 |
| POST 10 KB body through proxy_pass ⁵ | 85,284 | 16,009 | **0.19×** | 1.51 / 2.14 | 8.02 / 12.6 | 23.4 | 123.8 | 28.6 | 20.7 |
| HTTPS in → HTTP keepalive upstream | 80,072 | 29,586 | **0.37×** | 3.16 / 4.31 | 8.59 / 10.4 | 24.9 | 67.4 | 37.8 | 27.5 |
| HTTP in → HTTPS keepalive upstream (proxy_ssl) | 79,751 | 29,452 | **0.37×** | 3.14 / 5.41 | 8.73 / 11.5 | 25.0 | 67.8 | 39.0 | 28.4 |
| h2/TLS in → HTTP/1.1 keepalive upstream | 81,282 | 36,151 | **0.44×** | 10.2 / 24.6 | 26.4 / 50.4 | 24.6 | 55.4 | 43.3 | 65.3 |
| proxy_cache HIT, 1 KB | 104,042 | 30,866 | **0.30×** | 2.44 / 2.57 | 8.42 / 9.96 | 19.2 | 64.7 | 25.8 | 18.3 |
| fastcgi_pass, keepalive, 1 KB ⁶ | 39,544 | 37,262 | **0.94×** | 3.21 / 11.9 | 3.29 / 8.16 | 30.8 | 53.0 | 26.9 | 18.7 |

³ The 10 s windows stayed just under the fd limit, so these runs are clean. A longer run fails (bug 1).
⁴ Not investigated. C did **not** spool to temp files here: only 2 of about 5,400 responses spilled (one warning each).
⁵ Rust writes every 10 KB body to a temp file and reads it back (bug 4).
⁶ The Go FastCGI backend is the bottleneck for C (C at 120% CPU), so compare CPU per request (Rust 1.7×).

### Stream (L4) module

| Scenario | C req/s | Rust req/s | **Rust/C** | C p50 / p99 ms | Rust p50 / p99 ms | C CPU µs/req | Rust CPU µs/req | C peak PSS MB | Rust peak PSS MB |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| TCP relay to HTTP backend, 1 KB keep-alive | 151,260 | 118,044 | **0.78×** | 1.67 / 2.18 | 2.14 / 2.62 | 13.2 | 16.9 | 28.5 | 23.8 |
| TLS termination + TCP relay, 1 KB | 117,812 | 87,861 | **0.75×** | 2.15 / 2.63 | 2.88 / 3.63 | 16.9 | 22.7 | 39.8 | 30.4 |
| iperf3 single-stream bulk relay | 12.7 Gbit/s | **FAILED 3/3** | – | | | 0.61 CPU-s/GB | – | 25.4 | – |

### Equal load: CPU and latency at a fixed 10,000 req/s (oha with coordinated-omission correction)

| Scenario | C CPU | Rust CPU | **Rust/C** | C p50 / p90 / p99 ms | Rust p50 / p90 / p99 ms |
|---|--:|--:|--:|--:|--:|
| static 1 KB, 50 conns | 18% | 50% | **2.76×** | 0.10 / 0.15 / 0.23 | 0.22 / 0.39 / 0.60 |
| HTTPS 1 KB, 50 conns | 23% | 53% | **2.34×** | 0.12 / 0.18 / 0.30 | 0.24 / 0.42 / 0.71 |
| h2 1 KB, 10 conns × 10 streams | 20% | 44% | **2.18×** | 0.15 / 0.22 / 0.34 | 0.41 / 0.63 / 0.84 |
| proxy_pass keepalive 1 KB | 21% | 62% | **2.98×** | 0.15 / 0.22 / 0.40 | 0.33 / 0.51 / 0.78 |

## Memory

| | C | Rust |
|---|--:|--:|
| Idle PSS 1 s after start, master + 2 workers + cache procs, `worker_connections 20000` | 28.6 MB | 16.6 MB |
| Same with `worker_connections 1024` | 13.0 MB | 16.5 MB |
| Per idle HTTP/1.1 keep-alive connection (10k connections) | 0.55 KB (+ ~0.39 KB preallocated slot) | **10.8 KB** |
| Per idle HTTPS connection | 15.0 KB | 25.0 KB |
| Per idle HTTP/2 (TLS) connection | 15.5 KB | 33.2 KB |
| Total with 10k idle HTTP/1.1 connections (from 25.2 / 13.7 MB at start) | 30.6 MB | 119.6 MB |
| Total with 10k idle HTTP/2 connections | 176 MB | 338 MB |
| After 4 rounds of open/close 10k idle HTTP/1.1 connections | 29.4 MB | 123.5 MB (plateau: glibc keeps freed memory but reuses it) |
| After repeated open/close rounds of 10k HTTP/2 connections | ~180 MB (4 rounds, flat) | **3,330 MB** (10 rounds, plateau from round 4); **≈280 MB with jemalloc** preloaded |

C preallocates the connection and event arrays for all `worker_connections` (about 7.8 MB per worker at 20000), which explains
its higher idle number. The Rust port allocates per connection instead. Rust's 10.8 KB per idle HTTP/1.1 connection is the same with every allocator,
so it is live per-connection state (C frees the request pool and header buffer when a connection goes idle).
The HTTP/2 churn growth is not a leak (it stays bounded with jemalloc). It comes from glibc heap fragmentation under the port's
allocation pattern. A fixed `MALLOC_MMAP_THRESHOLD_` only slows it (2.5 GB after 6 rounds).

## Correctness issues found in the Rust port

1. **fd leak in the upstream keepalive cache (critical).** `crates/ngx-http/src/upstream_keepalive.rs:259`,
   `spawn_close_handler`, `dup()`s the cached socket. The raw fd is only wrapped in an `OwnedFd` inside the spawned
   `async move` block, on its first poll. When a cached connection is reused before that task has run, the task is
   `abort()`ed unpolled and the duplicate is never closed. Measured at about 0.6 leaked fds per proxied request (wrk -c64),
   with up to 690 duplicates of one socket. Each worker reached 134k–141k fds after 12 s. Requests then fail with
   `connect() failed (24: Too many open files)` and 502 (seen in the LTO/jemalloc runs, which reach the 200k
   limit sooner). Sequential requests on one connection do not leak. Confirmed for proxy_pass, proxy_ssl upstreams
   (54k fds after 3 s) and fastcgi_pass (81k fds after 3 s). Since nginx 1.31 enables upstream keepalive by default,
   this affects every `upstream {}` block. Fix: create the `OwnedFd` before the `async move`.
2. **Stream proxy bulk relay stall and spin (critical).** An iperf3 transfer through `stream { proxy_pass }` stops
   within the first second (after 20–60 MB). Both workers then burn 100% CPU in user space with almost no syscalls
   (13 s user, 0.01 s sys). Backtrace:
   `ngx_stream::proxy::relay` → `Relay::update_timer` (`crates/ngx-stream/src/proxy.rs` ~1350–1545). The likely cause (not confirmed)
   is that `src.readable()` resolves at once while `try_recv` reports `WouldBlock` from cached readiness, which
   makes the loop syscall-free. Short request/response traffic through the stream proxy works.
3. **`sub_filter` silently not applied with `sendfile on`.** The response is sent unmodified (as chunked).
   C forces in-memory buffers for body filters (`r->filter_need_in_memory`). With `sendfile off` it works but costs 9× C's CPU, with p99 of 0.4–2 s.
4. **Request bodies of 8–10 KB are spooled to disk.** C keeps a body in memory when it is under 1.25 ×
   `client_body_buffer_size` (`ngx_http_request_body.c:175-181`, `size += size >> 2`). The port spills anything ≥ 8 KB
   (`request_body.rs:521-528`). That is more than 40k temp files in 3 s of load, about 5.3× the CPU per proxied 10 KB POST,
   and contention on the temp directory's inode lock between workers.
5. **HTTP/2 memory under connection churn with glibc malloc:** 3.3 GB vs C's 180 MB (see Memory).
6. **Not implemented:** HTTP/3/QUIC and gRPC (stubs only).

All other scenarios produced zero errors and correct responses on both. The access log line counts match the request counts on both.

## Where the Rust port spends its time

Server CPU per request split into user and kernel time (saturation runs):

| Scenario | C user µs | C kernel µs | Rust user µs | Rust kernel µs | user ratio | kernel ratio |
|---|--:|--:|--:|--:|--:|--:|
| `return 200` | 1.6 | 6.4 | 10.6 | 10.0 | 6.8× | 1.6× |
| static 1 KB | 3.1 | 12.6 | 21.7 | 26.2 | 7.1× | 2.1× |
| regex/rewrite | 2.7 | 6.8 | 18.1 | 11.0 | 6.7× | 1.6× |
| HTTPS 1 KB | 7.3 | 12.0 | 27.8 | 16.2 | 3.8× | 1.3× |
| h2 TLS 1 KB | 6.2 | 9.1 | 22.2 | 5.3 | 3.6× | **0.6×** |
| h2c 1 KB | 4.0 | 14.4 | 20.6 | 4.8 | 5.2× | **0.3×** |
| proxy keepalive 1 KB | 4.9 | 14.2 | 32.8 | 23.0 | 6.7× | 1.6× |
| POST 10 KB via proxy | 5.8 | 17.8 | 55.5 | 67.9 | 9.6× | 3.8× |
| proxy_cache HIT | 5.1 | 14.0 | 35.0 | 29.7 | 6.9× | 2.1× |
| stream TCP relay | 0.9 | 12.3 | 2.7 | 14.2 | 3.1× | 1.2× |

* C spends 60–80% of its CPU in the kernel; it is close to the cost of the syscalls themselves. Rust spends **3–10× more user-space
  time per request**, and 1.2–3.8× more kernel time on HTTP/1.x paths (more syscalls and epoll work per request).
* Rust's HTTP/2 output is **better than C's on the kernel side**. It coalesces frames into fewer, larger writes
  (`/proc/<pid>/io` shows about 0.2 write calls per request vs 1.0), so its kernel time per request is 0.3–0.6× C's.
  The user-space overhead outweighs that.
* perf (`results/extra/perf2-*.txt`): for static 1 KB the shares are kernel / binary / libc = 74 / 15 / 4% for C and 50 / 32 / 12% for Rust.
  In Rust, **glibc takes 12% (static), 22% (proxy) and 33% (h2) of worker CPU, almost all of it in malloc/free/memmove**
  (`_int_malloc`, `_int_free`, `malloc_consolidate`, `unlink_chunk`). C uses pool allocators and spends 4–7% in libc. The rest of Rust's user time is spread thinly across async state machines (`process_request`,
  `connection_task`, filter closures, `drop_in_place<Request>`). There is no single hot spot.

### What-ifs: build flags and allocator (no code changes)

| Scenario (median req/s, CPU µs/req) | C | Rust | + jemalloc | + mimalloc ⁷ | fat LTO | LTO + jemalloc |
|---|--:|--:|--:|--:|--:|--:|
| `return 200` | 251,459 / 7.9 | 95,762 / 20.8 | 101,836 (+6%) | 67,301 (−30%) | 108,694 (+14%) | 115,662 (+21%) / 17.3 |
| static 1 KB | 123,708 / 16.1 | 42,446 / 47.0 | 43,785 (+3%) | 33,267 (−22%) | 47,798 (+13%) | 49,453 (+17%) / 40.3 |
| h2 TLS 1 KB | 132,423 / 15.1 | 72,625 / 27.6 | 83,582 (+15%) | 48,023 (−34%) | 77,025 (+6%) | 89,560 (+23%) / 22.4 |
| proxy keepalive 1 KB | 104,360 / 19.1 | 35,770 / 55.8 | 37,138 (+4%) ⁸ | 24,988 (−30%) | 40,274 (+13%) ⁸ | 45,443 (+27%) / 43.9 ⁸ |
| POST 10 KB via proxy | 85,866 / 23.3 | 15,863 / 124.5 | 16,530 (+4%) | 12,166 (−23%) | 14,886 (−6%) | 15,505 (−2%) |

⁷ Ubuntu's libmimalloc 2.0 package via `LD_PRELOAD`.
⁸ These runs hit the fd leak (4.7k–128k failed requests).

Fat LTO plus jemalloc gains 17–27% on request-heavy paths (not on POST) and fixes the HTTP/2 memory growth. That is worth doing, but Rust stays at about 0.4–0.7× C.
The remaining gap is per-request work in the port's design (allocation per request, buffer copies, async plumbing),
not compiler settings.

## Caveats

* Everything runs over loopback on one host. Absolute numbers are higher than over a NIC, but the per-request CPU
  comparison is what matters, and both servers run under identical conditions.
* Two workers only. nginx scales roughly linearly with workers, so the ratios should carry over.
* Some scenarios are not CPU-bound on the server for C: static 1 MB (client/kernel bound), FastCGI (backend bound),
  and the ECDSA handshake test (C at about 70% of 2 cores). For those, compare CPU per request rather than req/s.
* The wrk/h2load latencies at saturation are closed-loop. Use the fixed-rate table for latency comparisons.
* The keepalive-proxy numbers for Rust come from 13 s runs. In longer runs the fd leak breaks it.

## Reproduce

```sh
cd /home/ubuntu/nginx-bench
./build-c.sh                       # C -O2 builds (module list taken from bin/nginx-rust -V)
python3 bench.py --list            # scenarios
python3 bench.py --reps 3          # full suite, ~75 min, results/run-*.jsonl
python3 bench.py --only h2-tls-1k,proxy-1k-keepalive --reps 1 --servers c,rust,rust-lto-jemalloc
python3 report.py results/full-*.jsonl results/rerun-*.jsonl results/rerun2-*.jsonl   # tables (later files override)
python3 extra.py balance|baseline|accesslog|leak          # follow-up experiments
python3 profile2.py h1-static-1k rust                      # perf profile (needs perf_event_paranoid <= 1)
```

The session needed these apt packages on this box: `wrk nghttp2-client apache2-utils iperf3 libxslt1.1 libgd3 libgeoip1`
(plus the `-dev` packages to build C). oha is downloaded from GitHub, and its HTTP/3 build was done with `cargo install oha --features http3`.
