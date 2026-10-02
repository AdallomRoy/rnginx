# nginx C vs. Rust port (rnginx): performance comparison and analysis

Date: 2026-10-01.

**Compared:**
- nginx 1.31.7 in C (`nginx-c/`);
- the Rust port at **`master` @ `7f01d41`** ("Merge branch 'fixes'"): the bench fixes plus the upstream core port, HTTP/3/QUIC, gRPC and proxy HTTP/2.

Earlier reports: `REPORT-ad69792-bench-fixes.md` (previous master, after the benchmark bug fixes) and `REPORT-before-fixes.md` (first pass).

**Raw data:**
- `results/master-20261001-161949.jsonl`: 270 runs, with the generated tables in `results/master-20261001-161949.md`.
- `results/analysis/*.json`: the analysis measurements.
- `results/exp-20261001.jsonl`: the fix experiment.
- `results/whatif-20261001.jsonl`: the LTO and allocator variants.

**Tools:**
- `bench.py`: the harness.
- `report.py`: generates the tables.
- `analyze.py`: allocation counts and call sites, idle-connection heap, syscall counts, profiles.
- `tools/mcount`: an LD_PRELOAD allocation counter and stack sampler.

## TL;DR

* **Throughput:** the geometric mean over 35 saturation scenarios is **0.52× C**, at **1.99× C's CPU per request**. The range runs from 0.25× (POST through `proxy_pass`) to 3.18× (`sub_filter` with `sendfile on`, where C is pathological).
* **Where Rust is level:** work dominated by the kernel or by OpenSSL:
  * static 1 MB: 1.03×;
  * iperf3 through `stream`: 0.95×;
  * TLS handshakes: 0.92–1.00×;
  * gzip: 0.94×;
  * TCP stream proxy: 0.80×.
* **Where it is 3× behind:** small requests, where the server's own code matters:
  * HTTP/1.1: 0.30–0.40×;
  * proxy: 0.25–0.39×;
  * HTTP/3: 0.31×;
  * HTTP/2: 0.42–0.63×.
* **Why: on small requests, user-space CPU per request is 4–11× C's.** On `return 200` it is 12.8 µs vs 1.6 µs.
  * Rust makes **81–281 heap allocations per request; C makes 3–22**, because it allocates from per-request pools.
  * The main sources:
    * the async filter chain: a boxed future for every filter call, 27 per request;
    * owned copies of every request-line part and header: 7 allocations per header line;
    * clones of the cached time (5 strings), of rewrite programs and of config values on every request;
    * a boxed future per phase handler.
  * The remaining overhead is tokio (timers, task polls), `Rc`/`RefCell`/`dyn Any` config lookups, and memcpy.
* **Why: kernel CPU per request is 1.2–1.8× C's on HTTP/1.x and proxying.** Part of this is extra syscalls:
  * after every short read, one `recv()` that fails with EAGAIN;
  * for each proxied request, `dup` + 2 × `epoll_ctl` + `close`, from the watcher for the client closing the connection (`ClientWatch`); the upstream keep-alive close watcher did the same, but was usually cancelled before it ran.
  * The other part: the same syscalls take ~1.4× longer in Rust (likely cache pollution, see [§4](#4-kernel-time-syscalls-per-request)).
* **HTTP/2 is the exception:** Rust's kernel time is lower than C's because it batches ~5 responses per `write`, where C writes once per stream.
* **One hotspot is a one-line bug.** For POST bodies, 23% of the CPU goes to a byte-by-byte iterator copy of the body. Replacing it with slice copies gave **+37%** (21.0k → 28.9k req/s). Clearing read readiness after a short read gave +3% on HTTP/1. Both are only experiments on a scratch copy; master is unchanged.
* **Memory:** the idle baseline is lower in Rust (15.6 vs 25.9 MB PSS, since C preallocates `worker_connections`). But an idle keep-alive connection costs **11.4 KB of heap in 37 blocks vs C's 0.5 KB in 1 block**:
  * the Rust connection task keeps the last request's `Request` (2.6 KB plus 2.1 KB of per-request vectors) alive while idle;
  * it also keeps 2 KB of header buffers and a 2 KB task future.
* **Build settings and allocator explain little of the gap.** Fat LTO plus jemalloc gives +14 to +29% with no code changes, which still leaves Rust at 0.29–0.60× C.
* **Since the previous master (ad69792):** proxy/FastCGI are 15–24% slower, return/TLS/h2 8–12% slower. The faithful `ngx_http_upstream.c` port added layers rather than one hotspot: on the proxy path, +9 µs of user time and +5 µs of kernel time per request, including 2 more EAGAIN reads.

## Setup

| | |
|---|---|
| Machine | AWS r6i.8xlarge (Xeon Platinum 8375C @ 2.9 GHz), Linux 7.0.0-1013-aws, Docker container with 8 cores (CPUs 0–7, no HT siblings), no PMU (no hardware counters in the VM) |
| C build | nginx 1.31.7, gcc 11.4 `-O2`, the **same module list as the Rust binary**, HTTP/3 included (`build-c.sh`), `--with-debug` (the Rust port always compiles its debug-log checks in) |
| Rust build | `master` @ `7f01d41`, rustc 1.96.1, release profile `opt-level=3`, `debug=1`, no LTO, glibc malloc |
| CPU layout | nginx under test: 2 workers pinned to CPUs 0 and 1. Backends: CPUs 2–3 (C nginx as HTTP/HTTPS/h2 upstream, Go FastCGI server, iperf3). Load generators: CPUs 4–7 |
| Tools | wrk 4.1.0, h2load 1.43, oha 1.16 (plus an HTTP/3 build), iperf3, `tools/idleconns` (Go) |
| Method | Fresh nginx per run, response checked (status, size, body), 3 s warm-up, 10 s measurement, 3 alternating reps, medians, zero errors required. After each run: spin detection, error.log scan, worker fd count. For proxies, the backend's new-connection count confirms keepalive |

## Results

The full tables (latency, PSS, bandwidth view, run health) are in [the appendix](#appendix-full-result-tables).

CPU is µs per request over all nginx processes; "user" and "kernel" come from `/proc/<pid>/stat`.

| Scenario | C req/s | Rust req/s | **Rust/C** | C user / kernel µs | Rust user / kernel µs | user × | kernel × |
|---|--:|--:|--:|--:|--:|--:|--:|
| `h1-return`: `return 200`, keep-alive | 245,537 | 84,848 | **0.35×** | 1.6 / 6.5 | 12.8 / 10.5 | 8.2 | 1.6 |
| `h1-static-1k` | 124,655 | 47,396 | **0.38×** | 3.3 / 12.7 | 22.9 / 19.2 | 7.0 | 1.5 |
| `h1-static-100k` (sendfile) | 86,967 | 41,041 | **0.47×** | 3.3 / 19.6 | 23.1 / 25.6 | 6.9 | 1.3 |
| `h1-static-1m` (sendfile) | 15,814 | 16,331 | **1.03×** | 3.8 / 62.0 | 25.5 / 68.4 | 6.7 | 1.1 |
| `h1-conn-close`: new TCP connection per request | 72,558 | 28,979 | **0.40×** | 4.9 / 22.5 | 35.3 / 33.5 | 7.2 | 1.5 |
| `h1-2k-conns` | 142,558 | 45,917 | **0.32×** | 3.1 / 10.9 | 24.2 / 19.2 | 7.8 | 1.8 |
| `h1-regex-rewrite` | 204,836 | 61,836 | **0.30×** | 2.9 / 6.9 | 20.8 / 11.4 | 7.2 | 1.7 |
| `h1-gzip` 100 KB | 2,263 | 2,128 | **0.94×** | 859 / 25 | 904 / 36 | 1.1 | 1.4 |
| `h1-sub-filter` (sendfile off) | 7,624 | 4,762 | **0.62×** | 144 / 120 | 273 / 149 | 1.9 | 1.2 |
| `h1-sub-filter-sendfile` (sendfile on) | 1,499 | 4,767 | **3.18×** | 210 / 1,067 | 272 / 147 | 1.3 | 0.1 |
| `tls-h1-1k` | 102,682 | 38,943 | **0.38×** | 7.2 / 12.2 | 32.5 / 18.7 | 4.5 | 1.5 |
| `tls-h1-1m` | 2,299 | 1,909 | **0.83×** | 342 / 528 | 465 / 588 | 1.4 | 1.1 |
| `tls-handshake-ecdsa` | 4,189 | 4,210 | **1.00×** | 284 / 49 | 323 / 57 | 1.1 | 1.2 |
| `tls-handshake-rsa` | 3,266 | 2,990 | **0.92×** | 564 / 48 | 612 / 55 | 1.1 | 1.1 |
| `h2-tls-1k` (64 conns × 16 streams) | 132,391 | 63,342 | **0.48×** | 6.3 / 8.8 | 25.8 / 5.7 | 4.1 | **0.6** |
| `h2c-1k` | 107,702 | 67,514 | **0.63×** | 4.0 / 14.5 | 24.2 / 5.5 | 6.0 | **0.4** |
| `h2-tls-return` (16 × 100 streams) | 269,817 | 114,550 | **0.42×** | 3.4 / 4.0 | 16.9 / 0.5 | 4.9 | **0.1** |
| `h3-1k` | 87,314 | 27,393 | **0.31×** | 9.8 / 12.9 | 53.3 / 19.5 | 5.4 | 1.5 |
| `h3-100k` | 5,102 | 3,124 | **0.61×** | 135 / 256 | 336 / 302 | 2.5 | 1.2 |
| `proxy-1k-keepalive` | 103,689 | 30,880 | **0.30×** | 4.9 / 14.3 | 38.7 / 25.9 | 8.0 | 1.8 |
| `proxy-1k-no-keepalive` | 34,691 | 17,871 | **0.52×** | 8.1 / 49.4 | 49.5 / 61.9 | 6.1 | 1.3 |
| `proxy-100k` | 19,304 | 9,004 | **0.47×** | 11.9 / 91.9 | 91.8 / 130.6 | 7.7 | 1.4 |
| `proxy-post-10k` | 84,858 | 21,419 | **0.25×** | 5.7 / 17.8 | 63.1 / 29.6 | 11.1 | 1.7 |
| `proxy-cache-hit` | 102,903 | 33,651 | **0.33×** | 5.2 / 14.3 | 36.4 / 23.1 | 7.1 | 1.6 |
| `proxy-h2-upstream` (`proxy_http_version 2`) | 76,937 | 26,420 | **0.34×** | 10.6 / 15.4 | 49.2 / 26.4 | 4.6 | 1.7 |
| `grpc-pass` | 67,524 | 25,211 | **0.37×** | 13.5 / 16.1 | 59.9 / 19.8 | 4.4 | 1.2 |
| `fastcgi-1k` ¹ | 40,249 | 29,521 | **0.73×** | 6.6 / 24.0 | 40.4 / 27.3 | 6.1 | 1.1 |
| `stream-tcp-proxy` | 147,992 | 118,504 | **0.80×** | 0.9 / 12.5 | 2.6 / 14.2 | 2.8 | 1.1 |
| `stream-tls-terminate` | 116,784 | 87,792 | **0.75×** | 4.0 / 13.1 | 7.2 / 15.5 | 1.8 | 1.2 |
| `rate-h1-static-1k`: 10k req/s fixed | 9,997 | 9,997 | CPU **2.70×** | 4.3 / 13.6 | 28.5 / 20.1 | 6.6 | 1.5 |
| `rate-proxy-1k`: 10k req/s fixed | 9,997 | 9,997 | CPU **3.41×** | 5.7 / 14.9 | 44.4 / 26.4 | 7.8 | 1.8 |

¹ C is not CPU-bound here (123% of 200%): the Go FastCGI backend limits it.

At an equal 10k req/s, Rust's median latency is 2–3× C's. p50 by protocol:
* static: 0.21 vs 0.10 ms;
* TLS: 0.27 vs 0.12 ms;
* h2: 0.46 vs 0.15 ms;
* proxy: 0.38 vs 0.15 ms.

This follows from 2.3–3.4× more CPU per request.

Memory:

| | C | Rust |
|---|--:|--:|
| Idle PSS (master + 2 workers), `worker_connections 20000` | 25.9 MB | **15.6 MB** |
| Per idle HTTP/1.1 keep-alive connection (PSS) | 0.56 KB | 11.71 KB |
| Per idle HTTPS connection | 14.97 KB | 26.00 KB |
| Per idle HTTP/2 connection | 15.45 KB | 24.91 KB |

## Why: analysis

Measurements behind this section (all in `analyze.py`, results in `results/analysis/`):

| Measurement | How |
|---|---|
| CPU profiles | `perf record -e cpu-clock` with call graphs, 6 s at full load. C: DWARF unwinding. Rust: a frame-pointer build of the same commit (`-C force-frame-pointers=yes`), because perf 5.15 does not unwind the Rust binary's DWARF past the first frame. The frame-pointer build runs `h1-return` at the same speed as the release build (84,982 vs 84,848 req/s) |
| Allocations per request | `tools/mcount`, an LD_PRELOAD wrapper of malloc/calloc/realloc/free/memalign with counters in shared memory |
| Allocation call sites | `mcount` sampling 1 in 397 allocations with `backtrace()`, symbolized with `addr2line -i`. The sampled totals match the counters exactly (81.2/req on `h1-return`) |
| Heap per idle connection | `mcount`'s live-block counters around opening 5,000 idle connections |
| Syscalls per request | `perf stat` on the `raw_syscalls` tracepoints, filtered per syscall number and for `ret == -EAGAIN`, at full load (and at 10k req/s), with an idle baseline subtracted |
| Sizes of Rust types and futures | A probe build printing `size_of` values |

### 1. Where the CPU goes

CPU per request, split with the profiles (µs per request, at full load; "alloc" = malloc/free plus Rust's alloc/dealloc/`drop_in_place`):

| Scenario | | total | kernel | of which send | recv | epoll | file ops | user | alloc | memcpy | OpenSSL | tokio | rest of server code |
|---|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| `h1-return` | C | 8.1 | 6.6 | 5.2 | 0.5 | 0.1 | – | 1.6 | 0.1 | 0.0 | – | – | 1.4 |
| | Rust | 23.5 | 10.7 | 8.3 | 0.8 | 0.1 | – | 12.8 | **4.0** | 0.7 | – | 1.1 | **7.1** |
| `h1-static-1k` | C | 16.0 | 12.6 | 2.3 ² | 0.6 | 0.1 | 2.2 | 3.4 | 0.3 | 0.1 | – | – | 3.0 |
| | Rust | 42.1 | 19.1 | 3.2 ² | 1.0 | 0.2 | 3.5 | 23.0 | **7.1** | 1.1 | – | 1.6 | **13.2** |
| `tls-h1-1k` | C | 19.4 | 12.1 | 7.0 | 0.9 | 0.2 | 3.0 | 7.3 | 0.7 | 0.4 | 2.9 | – | 3.3 |
| | Rust | 51.2 | 18.9 | 10.5 | 1.6 | 0.2 | 4.7 | 32.2 | **8.5** | 1.8 | 5.1 | 1.6 | **15.2** |
| `h2-tls-1k` | C | 15.1 | 9.0 | 5.4 | 0.1 | 0.0 | 2.8 | 6.1 | 0.6 | 0.3 | 1.8 | – | 3.4 |
| | Rust | 31.6 | **6.1** | **1.9** | 0.1 | 0.0 | 2.9 | 25.6 | **9.8** | 1.8 | 0.9 | 1.6 | **11.5** |
| `h3-1k` | C | 22.8 | 13.0 | 7.7 | 0.6 | 0.4 | 3.1 | 9.8 | 0.4 | 0.6 | 1.6 | – | 7.3 |
| | Rust | 72.8 | 19.6 | 10.8 | 0.9 | 0.5 | 5.5 | 53.2 | **14.2** | 2.6 | 2.8 | 3.9 | **29.7** |
| `proxy-1k-keepalive` | C | 19.3 | 14.2 | 11.1 | 1.3 | 0.3 | – | 5.0 | 0.5 | 0.2 | – | – | 4.4 |
| | Rust | 64.7 | 25.5 | 16.8 | 2.2 | **2.2** | 0.1 | 39.1 | **13.9** | 2.0 | – | 3.3 | **19.9** |
| `proxy-post-10k` | C | 23.6 | 17.9 | 13.0 | 2.4 | 0.3 | – | 5.6 | 0.8 | 0.2 | – | – | 4.7 |
| | Rust | 93.2 | 30.2 | 19.4 | 3.0 | 2.5 | 0.2 | 63.0 | **14.5** | 2.7 | – | 3.6 | **42.1** ³ |
| `grpc-pass` | C | 29.6 | 15.8 | 13.4 | 1.1 | 0.1 | – | 13.8 | 1.5 | 0.7 | 5.5 | – | 6.1 |
| | Rust | 79.3 | 20.5 | 14.6 | 2.1 | 1.2 | 0.1 | 58.8 | **17.5** | 3.3 | 7.1 | 4.2 | **26.8** |
| `stream-tcp-proxy` | C | 13.4 | 12.4 | 9.6 | 1.2 | 0.3 | – | 1.0 | 0.0 | 0.0 | – | – | 1.0 |
| | Rust | 16.8 | 14.4 | 10.4 | 1.6 | 0.3 | – | 2.4 | 0.2 | 0.0 | – | 1.0 | 1.3 |

² On `h1-static-1k` most of the transmit happens in `setsockopt(TCP_CORK, 0)`, which is not in the "send" column: 5.9 µs in C, 8.7 µs in Rust.
³ Of these 42 µs, 21.7 are one function. See [§3](#3-hotspots).

The C server spends 60–93% of its CPU in the kernel. Its own user-space code takes 1–6 µs per request (more with TLS). The Rust port takes 12–63 µs. What fills that gap, in order:

* **Allocation, 25–35% of Rust's user time** (4–17 µs per request): the allocations of [§2](#2-allocations-81281-per-request-vs-322). glibc's fast path (tcache) covers only blocks up to 1,032 bytes. Larger ones go to `_int_malloc`/`malloc_consolidate`, and many per-request objects are larger:
  * the `Request`: 2,576 B;
  * `r.ctx`: 1,152 B;
  * the header buffers: 1 KB each;
  * boxed filter futures.
  * That's why HTTP/2 shows malloc/free at 26% of the profile.
* **Async machinery:** 3–5 µs per request.
  * The filter closures alone take 3.0 µs self time on `h1-return`: each layer boxes and polls the next filter's future.
  * tokio itself takes 1.1–4.2 µs: `Timeout` futures register and cancel timer-wheel entries for every read, plus task polls, waker clones and `LocalSet::tick`.
* **Everything else is spread thin.** No other function takes over 2% on `h1-return`. Examples:
  * `conf_rc` (an `Rc` clone and a `dyn Any` downcast on every config lookup, where C reads `r->loc_conf[ctx_index]`): 1.1%;
  * `times::cached()` calling `clock_gettime` each time (C updates its time once per event-loop iteration): 1.0%;
  * `RefCell` borrow checks;
  * header lookups through hash maps.

### 2. Allocations: 81–281 per request vs 3–22

| Scenario | C allocations/req | Rust allocations/req | C KB requested/req | Rust KB requested/req |
|---|--:|--:|--:|--:|
| `h1-return` | 3.0 | **81.2** | 9.0 | 23.5 |
| `h1-static-1k` | 3.0 | **124.3** | 9.0 | 30.0 |
| `h1-conn-close` | 4.0 | **144.1** | 9.5 | 33.6 |
| `tls-h1-1k` | 11.4 | **140.4** | 74.1 | 129.6 |
| `h2-tls-1k` | 9.1 | **175.5** | 32.6 | 54.5 |
| `h2c-1k` | 3.1 | **168.2** | 9.3 | 47.1 |
| `h3-1k` | 3.2 | **252.0** | 24.1 | 126.4 |
| `proxy-1k-keepalive` | 5.0 | **226.2** | 17.0 | 52.8 |
| `proxy-post-10k` | 7.0 | **231.0** | 27.1 | 104.1 |
| `fastcgi-1k` | 5.0 | **218.9** | 17.0 | 53.2 |
| `grpc-pass` | 22.4 | **281.1** | 105.7 | 204.1 |
| `stream-tcp-proxy` (per 1 KB echo) | 0.0 | **8.0** | 0.0 | 1.5 |

C allocates almost nothing per request. Each request gets a pool (`ngx_create_pool`, one aligned 4 KB block, plus one for the request), and everything else is bump-pointer allocation from it, freed at once. The Rust port allocates each object individually.

Where the 81 allocations of a `return 200` come from (sampled call stacks):

| Allocations/req | Source | C equivalent |
|--:|---|---|
| **27.1** | **Filter chain:** `install_header_filter`/`install_body_filter` (`lib.rs:378/393`) wrap every filter as `Box::pin(async move { f(r, next).await })`, so each of the ~14 header and ~13 body filters allocates a future on every call | Direct calls through function pointers (`ngx_http_top_header_filter`) |
| **13.2** | **Request line and URI:** `request_line`, `method_name`, `http_protocol`, `uri`, `args`, `exten`, `unparsed_uri`, host… are all copied into separate `Vec`s (`request_rt.rs:566–571`, `validate_host`, `process_request_uri_data`) | `ngx_str_t`s pointing into the header buffer |
| **10.0** | **`times::cached()`:** clones the whole `CachedTime`, including its 5 `String`s, just to read the seconds (`alloc_request`, logging). `with_cached()` exists and borrows instead | `ngx_cached_time` is a pointer |
| **5.0** | **Phase handlers:** `Box::pin` per phase handler call (`rewrite.rs:881`, realip, try_files, limit_req/conn, …) | Direct calls |
| **4.1** | **Per-request objects:** the `Rc<Request>` plus `r.ctx` (72 × 16 B) and `r.variables` (30 × 32 B) | Pool allocations |
| **3.9** | **Header lines:** 7 allocations per line. The parser copies key, value and lowercase key (`to_vec()`), then `TableElt::with_hash` copies key and value again, inside a new `Rc` (`request_rt.rs:693–715`) | Pointers into the buffer, lowercase key from the pool |
| **3.0** | **Config clones:** the rewrite program (`c.codes.clone()`, a deep clone of the location's `Vec<Code>` on every rewrite-phase call) and `ComplexValue`. This grows with the number of rewrite directives, which is why `h1-regex-rewrite` is the worst HTTP/1 ratio (0.30×) | Walks the config arrays by pointer |
| 2.1 | Date/ETag/Content-Type strings, `format!` in the header filter | `ngx_sprintf` into a buffer |
| 2.0 | **Keep-alive:** two zero-filled 1 KB buffers per keep-alive cycle (`request_rt.rs:1361, 1403`) | One buffer, freed when idle |
| ~11 | Other single sites (`log_request` clones the log-handler `Vec`, `send_chain`, …) | |

The proxy adds ~71 allocations per request for the upstream response headers. `proxy::process_header` copies name, value and lowercase name (`proxy.rs:2460–2463`). `TableElt::with_hash` copies them again, and `copy_header` copies them into `headers_out`.

HTTP/3 adds ~60 more:
* QPACK lookups and encoding: `v3/table.rs:415` returns owned copies of static-table entries;
* QUIC frame and buffer objects (`ngx_quic_alloc_frame`/`_buf`);
* cloned connection IDs per packet.

C builds packets in static buffers (`static u_char dst[...]` in `ngx_event_quic_output.c`).

### 3. Hotspots

The profiles found one real hotspot:

* **`request_body_filter`** (`request_body.rs:454`) collects the request body with `input.iter().filter_map(...).flatten().copied().collect()`. That is a byte-at-a-time copy the compiler cannot vectorize, followed by a second copy (`data[..take].to_vec()`).
* On `proxy-post-10k` it takes **23% of all CPU**, about 21.7 µs per request: `Copied::next` 14.9% and `Vec::from_iter` 8.4%.
* C's length filter links the existing buffers without copying.

### 4. Kernel time: syscalls per request

Syscalls per request at full load. Rust's `close` on the proxy paths is the `close` of a `dup`ed descriptor (a separate run counted `dup` = `close` = 1.19 per request).

| Scenario | C | Rust | failed with EAGAIN, C / Rust | Difference |
|---|--:|--:|--:|---|
| `h1-return` | 2.01 | 3.02 | 0 / **1.00** | Rust: one extra `recvfrom` → EAGAIN per request |
| `h1-static-1k` | 8.02 | 9.04 | 0 / **1.00** | same; otherwise identical (open, fstat, writev + sendfile, 2× TCP_CORK, close) |
| `h1-conn-close` | 11.13 | 13.13 | 0 / 1.00 | also `epoll_ctl` 2.13 vs 1.12: tokio deregisters (`EPOLL_CTL_DEL`) before `close`, C lets `close` do it |
| `tls-h1-1k` | 7.03 | 9.05 | 1.00 / **2.99** | the TLS read path does 3 failing `read`s per request |
| `h2-tls-1k` | 5.14 | **4.53** | 0.06 / 0.19 | Rust **0.19 `write`s per request vs 1.00**: it batches ~5 responses per write |
| `h2c-1k` | 10.07 | **4.33** | 0 / 0.06 | C: 4× `setsockopt` (TCP_CORK on/off), 2× `writev` and a `sendfile` per response. Rust reads the file and batches frames |
| `h3-1k` | 7.33 | 7.26 | 0 / 0 | identical (one `recvmsg` and one `sendmsg` per request) |
| `proxy-1k-keepalive` | 5.03 | **11.94** | 0 / **2.79** | +`dup`, +2 `epoll_ctl`, +`close` per request, +2.8 EAGAIN reads |
| `proxy-post-10k` | 7.04 | 12.85 | 0 / 2.80 | same |
| `fastcgi-1k` | 7.18 | 11.63 | 0 / 2.58 | same |
| `grpc-pass` | 6.32 | 9.83 | 1.14 / **4.57** | |
| `stream-tcp-proxy` | 4.02 | 6.04 | 0 / **2.00** | one EAGAIN read per relayed chunk in each direction |

Three Rust-specific causes:

1. **No short-read optimization.** `Connection::recv` (`connection.rs:944`) keeps the socket's read readiness after a read that returned fewer bytes than asked. The next wait therefore returns at once, and its `recv()` fails with EAGAIN.
   * C clears `rev->ready` after a short read when EPOLLRDHUP is available (`ngx_unix_recv`).
   * tokio's own `TcpStream::poll_read` does the same, and tokio keeps the closed bits when readiness is cleared.
   * The TLS, upstream and stream read paths have the same pattern (`try_recv`/`try_io` until `WouldBlock`).
2. **Two watchers on `dup()`ed sockets.** C leaves a connection's socket registered with epoll and only changes its read handler, with no syscalls. The Rust port gave each watcher its own descriptor:
   * `ClientWatch` (`upstream_rt.rs:815`), the port of `ngx_http_upstream_check_broken_connection`, `dup()`ed the client socket for every upstream request. It registered the duplicate with epoll to see the client close the connection. That is a `dup`, two `epoll_ctl` and a `close` per proxied request, most of the extra syscalls on the proxy rows.
   * The upstream keep-alive close watcher (`upstream_keepalive.rs:262`) did the same with the upstream socket each time a connection went back into the cache. Since the next request usually took the connection before the task ran, it cost only about 0.2 per request.
   * (An earlier version of this section put all of it on the keep-alive watcher. The per-step measurements in the [update](#update-fixes-on-branch-perf-fixes) separate the two.)
3. **tokio deregisters explicitly** (`EPOLL_CTL_DEL`) before closing a socket: one syscall per connection.

These explain only part of the kernel gap. In `h1-static-1k` at a fixed 10k req/s, the two servers make the same syscalls (8.33 vs 9.29 per request, the difference being the EAGAIN `recv`), yet Rust spends 1.5× the kernel time (20.1 vs 13.6 µs per request).

The full-load profile of the same scenario shows the extra time spread evenly over every kind of kernel work, Rust vs C per request:
* `recv`: 0.97 vs 0.58 µs;
* `writev` + `sendfile`: 3.2 vs 2.3 µs;
* `setsockopt(TCP_CORK)`, where the transmit happens: 8.7 vs 5.9 µs;
* open/fstat/close: 3.5 vs 2.2 µs;
* loopback softirq delivery of the same packets: 5.9 vs 4.0 µs.

On `h1-return`, the largest single kernel item is waking the client (`__wake_up_sync_key`): 2.9 vs 1.4 µs per request. The cause is not page faults (0.01% of samples) and not other kernel work. The VM exposes no hardware counters, so I could not measure cache misses. The most likely explanation is cache and TLB pollution: Rust's user-space work per request is 7× larger and touches hundreds of freshly allocated heap blocks, so the kernel's socket, dentry and skb data are colder each time it runs.

**HTTP/2 is the exception: Rust's kernel time is 0.1–0.6× C's.** For each finished stream, C calls `ngx_http_v2_send_output_queue` from `ngx_http_v2_filter_send` and writes immediately: one `write` (TLS record) per response. On h2c that is even 7 syscalls per response, with TCP_CORK on/off around a `sendfile` of 1 KB. The Rust driver queues frames and writes the connection's output buffer once per pass, about 5 responses per write. That is why the h2 ratios (0.42–0.64×) are better than HTTP/1.1's despite a similar user-space overhead.

### 5. HTTP/3: 0.31×

* **Same syscalls:** 7.3 per request in both, with one `recvmsg` and one `sendmsg`; GSO doesn't come into play at 1 KB.
* **The kernel ratio (1.5×)** is the same as on HTTP/1.
* **User space is 53 vs 10 µs:**
  * 251 allocations per request (vs 3.2), costing 14.2 µs;
  * the QUIC/HTTP/3 code takes 13.7 µs vs 3.9 µs;
  * the shared HTTP request path adds the same filter and phase overhead as HTTP/1.
* **On every packet,** the port allocates:
  * a fresh `Vec` for the datagram (`output.rs:103/281`; 64 KB capacity when GSO-batching);
  * frames as heap objects;
  * clones of `dcid`/`scid`/keys (`output.rs:566–574`).
* **Each request stream** is a new tokio task with its own `HttpConnection`, log context and boxed futures.

### 6. Proxying, and the slowdown since the previous master

On `proxy-1k-keepalive` the 45 µs per request gap consists of:
* 34 µs of user time:
  * allocation 13.9 µs (226 allocations, a third of them header copies);
  * the async filter and phase layers;
  * the upstream module;
  * tokio 3.3 µs;
* 11 µs of kernel time, from the 7 extra syscalls per request of §4 and the general kernel slowdown.

Compared with the previous master `ad69792`, profiled the same way (frame-pointer builds):

| µs per request (under profiling) | ad69792 | 7f01d41 | Δ |
|---|--:|--:|--:|
| Total | 59.2 | 72.8 | **+13.6** |
| Kernel | 24.0 | 28.8 | +4.7 (2 more EAGAIN reads per request; `writev` instead of `send` for the upstream request) |
| Filters / upstream module / other code | 8.9 | 13.4 | +4.5 |
| Allocation (malloc/free + Rust alloc/drop) | 13.4 | 15.7 | +2.3, despite fewer allocations (226 vs 244 per request) and fewer bytes requested (52.8 vs 61.5 KB) |
| Request lifecycle, tokio, rest | 12.8 | 14.9 | +2.0 |

No single function accounts for the regression. The port of `ngx_http_upstream.c` runs more and deeper async layers:
* `init_request` → `send_request` → `send_buffered` → `send_chain`;
* per-header `hidden`/`copy_header` processing;
* more timers (`sleep_until`).

The −9% on `return 200` is spread just as thinly (+1.8 µs per request over dozens of functions: QUIC-stream checks, `set_reusable`, `send_chain` layers).

### 7. Memory per connection

Heap held per idle connection, measured with `mcount`'s live counters (5,000 connections, each idle after one request):

| | C | Rust |
|---|--:|--:|
| HTTP/1.1 keep-alive | **0.51 KB in 1 block** | **11.37 KB in 37 blocks** |
| HTTPS | 14.42 KB in 45 blocks | 25.15 KB in 83 blocks |
| HTTP/2 (TLS) | 14.98 KB in 46 blocks | 24.99 KB in 64 blocks |

OpenSSL's ~14 KB per TLS connection is the same in both. The Rust extra is the same ~10.5 KB whatever the protocol. For HTTP/1.1, from the size probe (`size_of` in a probe build):

| Rust, per idle HTTP/1.1 connection | Bytes | Why it is held |
|---|--:|---|
| Last request: `Request` 2,576 + `r.ctx` 1,152 + `r.variables` 960 + header/URI copies ~600 | ~5,300 | `connection_task` keeps `r` alive across `keepalive(&r, &hc).await`. `free_request` runs the cleanups but frees no memory. C destroys the request pool before going idle |
| Header buffers: the keep-alive read buffer + `hc.buffer` (cleared, capacity kept) | 2,048 | C frees the buffer while idle (`ngx_pfree` of `c->buffer`) and allocates it again on the first byte |
| The connection task (the `connection_task` future, 2,016 B, in tokio's task cell) | ~2,150 | The future is sized for its largest state (`run_request`: 1,688 B) |
| `Connection` 584 + `HttpConnection` 200 + log context, `AsyncFd` and tokio registration | ~1,200 | C: `ngx_connection_t` and its events are preallocated in arrays (the 0.39 KB counted in the idle PSS) |
| malloc headers of 37 blocks | ~500 | |
| **Sum** | **~11,200** | measured 11,370 |

Dropping the request and freeing the header buffers while idle would bring this down to ~3–4 KB.

### 8. Where Rust is level or ahead, and why

* **Kernel-bound bulk work** (static 1 MB 1.03×, iperf3 via `stream` 0.95×, `stream-tcp-proxy` 0.80×): per-request overhead is amortized over large transfers or nonexistent. The stream relay makes 8 allocations per relayed request.
* **OpenSSL-bound work** (handshakes 0.92–1.00×, TLS 1 MB 0.83×, gzip 0.94× in zlib): the same libraries do the work.
* **`sub_filter` with `sendfile on`: 3.18×.** C sends the unchanged stretches between the 424 replacements as hundreds of small `sendfile()` calls (1,067 µs of kernel time per request). Rust reads the body into memory and writes it in a few large writes.
* **HTTP/2 frame batching:** fewer, larger writes and TLS records (§4). OpenSSL time per request is half of C's (0.9 vs 1.8 µs).
* **Idle PSS** is 10 MB lower: C preallocates `ngx_connection_t` and event arrays for `worker_connections 20000`.

### 9. Experiment: two small fixes

To check the analysis, I applied two of the fixes it suggests to a scratch copy of master. They are **not committed**; the diff is in `experiment-fixes.patch`:

1. `request_body_filter` collects the body with `extend_from_slice` per buffer instead of the byte iterator.
2. `Connection::recv` calls `guard.clear_ready()` after a short read.

| Scenario (3 reps, median) | master | + 2 fixes | Δ |
|---|--:|--:|--:|
| `proxy-post-10k` | 21,042 req/s, 95.0 µs/req | **28,932 req/s, 69.0 µs/req** | **+37%** |
| `h1-return` | 85,779 | 88,242 | +2.9% |
| `h1-static-1k` | 47,756 | 49,223 | +3.1% |
| `proxy-1k-keepalive` | 30,942 | 31,120 | ±0 (its EAGAIN reads happen in other functions: the upstream read, the watchers) |

### 10. What-ifs: build and allocator (no code changes)

Each cell is median req/s / CPU µs per request, 3 reps. Variants:
* jemalloc: `LD_PRELOAD` of the system libjemalloc;
* fat LTO: the same commit built with `lto = "fat"`, `codegen-units = 1`.

| Scenario | C | Rust | + jemalloc | fat LTO | LTO + jemalloc | **LTO+je vs C** |
|---|--:|--:|--:|--:|--:|--:|
| `h1-return` | 245,537 / 8.1 | 85,273 / 23.4 | 89,881 (+5%) | 97,720 (+15%) | 103,654 (+22%) / 19.2 | **0.42×** |
| `h1-static-1k` | 124,655 / 16.0 | 47,489 / 42.0 | 49,495 (+4%) | 55,980 (+18%) | 58,601 (+23%) / 34.0 | **0.47×** |
| `h2-tls-1k` | 132,391 / 15.1 | 63,570 / 31.5 | 72,248 (+14%) | 69,328 (+9%) | 79,582 (+25%) / 25.1 | **0.60×** |
| `h3-1k` | 87,314 / 22.8 | 27,382 / 72.8 | 27,920 (+2%) | 35,446 (+29%) | 35,320 (+29%) / 56.4 | **0.40×** |
| `proxy-1k-keepalive` | 103,689 / 19.3 | 30,924 / 64.5 | 32,662 (+6%) | 35,042 (+13%) | 38,435 (+24%) / 51.9 | **0.37×** |
| `proxy-post-10k` | 84,858 / 23.6 | 21,391 / 93.4 | 21,950 (+3%) | 22,943 (+7%) | 24,331 (+14%) / 82.1 | **0.29×** |

* **LTO is worth more than the allocator:** +7 to +29%. Without it, nothing is inlined across the crates (`ngx-core` ↔ `ngx-http`: `Connection` methods, `conf_rc`, buffer and time helpers) except generics and `#[inline]` functions.
* **jemalloc helps most where the allocations are largest:** h2 +14%, where glibc's `_int_malloc`/`malloc_consolidate` dominate.
* **Together:** +14 to +29%, still 0.29–0.60× C. The gap is in what the code does per request, not in how it is compiled.

## What would close the gap, by expected gain

| # | Change | Expected effect |
|--:|---|---|
| 1 | Request body: slice copies instead of the per-byte iterator (`request_body.rs:454`) | **Measured +37%** on POST via proxy |
| 2 | The client-close and keep-alive watchers on the connection's own registration instead of a `dup()`ed socket | −4 to −5 syscalls per proxied request (`epoll_ctl` ×2, `dup`, `close`, peek) |
| 3 | Clear read readiness after short reads, everywhere: `Connection::recv` (measured +3%), `try_recv`, the TLS path (3 failing reads per HTTPS request), the upstream and stream relays | −1 to −4.6 syscalls per request |
| 4 | Filter and phase chains without a `Box::pin` per call: synchronous filters with an async slow path, or a static chain | −32 allocations per request, plus the poll layers (~3 µs on `return 200`) |
| 5 | Stop per-request clones: `times::cached()` → `with_cached()`, the rewrite program as `Rc<[Code]>`, the log-handler `Vec`, `ComplexValue` | −15 allocations per request; the rewrite clone grows with config size |
| 6 | Headers and request line as offsets into the header buffer (or `bytes::Bytes` slices) instead of 7 copies per header line | −10 to −70 allocations per request, the most on proxy paths |
| 7 | Free the request and the header buffers before the keep-alive wait | ~11.4 → ~3–4 KB per idle connection |
| 8 | A per-request arena (nginx's pool model) for request-scoped data | Most of the remaining allocations |
| 9 | jemalloc/mimalloc and LTO in the release profile | **Measured +14 to +29%**, no code changes (§10) |

## Method notes and caveats

* **Closed-loop latency:** wrk/h2load latency at saturation is mostly queueing. Use the fixed-rate rows for latency comparisons.
* **Analysis runs vs benchmark runs:** the profiles, `mcount` and `perf stat` runs slow the server somewhat (perf stat's syscall tracepoints cost C about 17% at saturation). Their counts per request are what is used, never their throughput.
* **Allocation sites:** sampled stacks charge allocator and container plumbing (`alloc::`, `<T as Clone>`, `RawVec`, …) to the first caller in the port's own code.
* **No hardware counters in this VM:** the kernel "cache pollution" explanation in §4 is an inference from the timing pattern, not a measurement.
* **Not investigated:** Rust's p99 is markedly worse on large responses (`tls-h1-1m` 98 vs 20 ms, `h1-gzip` 122 vs 53 ms, `h3-100k` 52 vs 10 ms). On `proxy-h2-frontend`, C opens far more upstream connections (124k vs 3.4k per run): it has more requests in flight than the 32-connection keep-alive pool holds. It is still 2.6× faster.
* **Changes to the machine, all undone afterwards:**
  * tracefs was mounted at `/sys/kernel/tracing` for `perf stat` (`analyze.py sysstat` needs it again);
  * `kernel.perf_event_paranoid` and `kernel.kptr_restrict` were lowered for profiling.
* **Host BPF:** the profiles show BPF programs on the syscall path (`trace_call_bpf`, `bpf_lru_*`). This adds the same cost to every syscall of both servers.

## Appendix: full result tables

Generated by `report.py results/master-20261001-161949.jsonl` (medians of 3 reps; wrk/h2load latency is closed-loop; CPU is µs per request over all nginx processes; PSS is the peak of master plus workers).

Saturation scenarios: 35; Rust/C throughput geomean = 0.52x (min 0.25x, max 3.18x); Rust/C CPU-per-request geomean = 1.99x

### HTTP/1.1

| Scenario | C req/s | Rust req/s | **Rust/C** | C p50 / p99 ms | Rust p50 / p99 ms | C CPU µs/req | Rust CPU µs/req | C peak PSS MB | Rust peak PSS MB |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| `h1-return` — `return 200` (12 B body, no file I/O), keep-alive | 245,537 | 84,848 | **0.35x** | 1.03 / 1.21 | 2.99 / 3.50 | 8.1 | 23.5 | 26.9 | 19.4 |
| `h1-static-1k` — static 1 KB file, keep-alive | 124,655 | 47,396 | **0.38x** | 2.03 / 2.48 | 5.42 / 6.26 | 16.0 | 42.1 | 27.2 | 19.8 |
| `h1-static-100k` — static 100 KB file (sendfile) | 86,967 | 41,041 | **0.47x** | 0.73 / 1.05 | 1.55 / 1.67 | 23.0 | 48.7 | 27.1 | 17.6 |
| `h1-static-1m` — static 1 MB file (sendfile) | 15,814 | 16,331 | **1.03x** | 1.24 / 2.04 | 1.20 / 2.31 | 65.9 | 94.1 | 27.0 | 17.0 |
| `h1-conn-close` — 1 KB, new TCP connection per request | 72,558 | 28,979 | **0.40x** | 0.82 / 1.06 | 2.16 / 2.33 | 27.3 | 68.8 | 27.0 | 16.9 |
| `h1-2k-conns` — 1 KB, 2000 concurrent keep-alive connections | 142,558 | 45,917 | **0.32x** | 13.40 / 16.92 | 44.39 / 50.01 | 14.0 | 43.4 | 27.9 | 40.6 |
| `h1-regex-rewrite` — regex location + map + set + if + rewrite last + add_header + vars | 204,836 | 61,836 | **0.30x** | 1.24 / 1.38 | 4.16 / 5.31 | 9.7 | 32.3 | 27.1 | 19.7 |
| `h1-access-log` — static 1 KB with buffered combined access_log | 119,174 | 43,031 | **0.36x** | 2.15 / 2.36 | 6.03 / 6.46 | 16.7 | 46.4 | 27.3 | 19.9 |
| `h1-gzip` — 100 KB HTML gzip-compressed on the fly (level 1) | 2,263 | 2,128 | **0.94x** | 28.00 / 52.72 | 29.91 / 121.97 | 884.6 | 940.6 | 27.7 | 19.0 |
| `h1-sub-filter` — 100 KB HTML through sub_filter (424 replacements), sendfile off | 7,624 | 4,762 | **0.62x** | 8.35 / 10.04 | 13.46 / 17.68 | 262.3 | 420.0 | 27.1 | 19.7 |
| `h1-sub-filter-sendfile` — 100 KB HTML through sub_filter (424 replacements), sendfile on (default) | 1,499 | 4,767 | **3.18x** | 42.99 / 49.86 | 13.53 / 16.92 | 1279.8 | 419.6 | 27.2 | 19.7 |
| `h1-limit-req` — static 1 KB through limit_req (shared-memory zone, never rejects) | 119,822 | 44,601 | **0.37x** | 2.13 / 2.30 | 5.76 / 6.34 | 16.7 | 44.7 | 27.1 | 19.8 |

Bandwidth view:

| Scenario | C Gbit/s | Rust Gbit/s | **Rust/C** | C CPU s/GB | Rust CPU s/GB | C peak PSS MB | Rust peak PSS MB |
|---|--:|--:|--:|--:|--:|--:|--:|
| `h1-static-100k` — static 100 KB file (sendfile) | 71.38 | 33.67 | **0.47x** | 0.22 | 0.48 | 27.1 | 17.6 |
| `h1-static-1m` — static 1 MB file (sendfile) | 132.71 | 137.01 | **1.03x** | 0.06 | 0.09 | 27.0 | 17.0 |

### HTTPS

| Scenario | C req/s | Rust req/s | **Rust/C** | C p50 / p99 ms | Rust p50 / p99 ms | C CPU µs/req | Rust CPU µs/req | C peak PSS MB | Rust peak PSS MB |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| `tls-h1-1k` — HTTPS 1 KB, keep-alive (ECDSA P-256, TLS 1.3) | 102,682 | 38,943 | **0.38x** | 2.46 / 2.98 | 6.63 / 8.01 | 19.4 | 51.2 | 37.6 | 28.5 |
| `tls-h1-1m` — HTTPS 1 MB, keep-alive (bulk encryption) | 2,299 | 1,909 | **0.83x** | 13.72 / 20.23 | 19.46 / 98.35 | 869.7 | 1048.0 | 29.6 | 19.4 |
| `tls-resume-ecdsa` — new TLS connection per request, TLS 1.3 session resumption | 6,578 | 5,438 | **0.83x** | 0.58 / 1.00 | 0.39 / 0.75 | 302.8 | 367.6 | 30.5 | 20.0 |
| `tls-handshake-ecdsa` — full TLS 1.3 handshake per request, ECDSA P-256 | 4,189 | 4,210 | **1.00x** | 2.81 / 12.18 | 2.62 / 12.28 | 332.5 | 380.5 | 31.6 | 20.8 |
| `tls-handshake-rsa` — full TLS 1.3 handshake per request, RSA 2048 | 3,266 | 2,990 | **0.92x** | 1.32 / 10.63 | 1.06 / 9.88 | 612.3 | 666.7 | 30.0 | 19.6 |

Bandwidth view:

| Scenario | C Gbit/s | Rust Gbit/s | **Rust/C** | C CPU s/GB | Rust CPU s/GB | C peak PSS MB | Rust peak PSS MB |
|---|--:|--:|--:|--:|--:|--:|--:|
| `tls-h1-1m` — HTTPS 1 MB, keep-alive (bulk encryption) | 19.33 | 15.98 | **0.83x** | 0.83 | 1.00 | 29.6 | 19.4 |

### HTTP/2

| Scenario | C req/s | Rust req/s | **Rust/C** | C p50 / p99 ms | Rust p50 / p99 ms | C CPU µs/req | Rust CPU µs/req | C peak PSS MB | Rust peak PSS MB |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| `h2-tls-1k` — h2 over TLS, 1 KB, 64 conns x 16 streams | 132,391 | 63,342 | **0.48x** | 7.84 / 9.65 | 16.20 / 18.66 | 15.1 | 31.6 | 31.0 | 52.4 |
| `h2-tls-100k` — h2 over TLS, 100 KB, 32 conns x 8 streams | 17,922 | 11,484 | **0.64x** | 14.46 / 16.67 | 21.74 / 32.34 | 111.6 | 174.2 | 29.9 | 42.2 |
| `h2c-1k` — h2c (cleartext, prior knowledge), 1 KB, 64 conns x 16 streams | 107,702 | 67,514 | **0.63x** | 9.47 / 12.55 | 15.12 / 17.23 | 18.6 | 29.7 | 27.7 | 53.1 |
| `h2-tls-return` — h2 over TLS, `return 200`, 16 conns x 100 streams | 269,817 | 114,550 | **0.42x** | 5.96 / 7.86 | 13.95 / 17.46 | 7.4 | 17.5 | 28.7 | 43.1 |

Bandwidth view:

| Scenario | C Gbit/s | Rust Gbit/s | **Rust/C** | C CPU s/GB | Rust CPU s/GB | C peak PSS MB | Rust peak PSS MB |
|---|--:|--:|--:|--:|--:|--:|--:|
| `h2-tls-100k` — h2 over TLS, 100 KB, 32 conns x 8 streams | 14.69 | 9.45 | **0.64x** | 1.09 | 1.69 | 29.9 | 42.2 |

### HTTP/3

| Scenario | C req/s | Rust req/s | **Rust/C** | C p50 / p99 ms | Rust p50 / p99 ms | C CPU µs/req | Rust CPU µs/req | C peak PSS MB | Rust peak PSS MB |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| `h3-1k` — HTTP/3 (QUIC) 1 KB, 32 conns | 87,314 | 27,393 | **0.31x** | 0.35 / 0.50 | 1.14 / 1.63 | 22.8 | 72.8 | 32.1 | 21.9 |
| `h3-100k` — HTTP/3 (QUIC) 100 KB, 32 conns | 5,102 | 3,124 | **0.61x** | 5.87 / 10.06 | 8.25 / 51.87 | 390.7 | 638.3 | 38.0 | 26.0 |

Bandwidth view:

| Scenario | C Gbit/s | Rust Gbit/s | **Rust/C** | C CPU s/GB | Rust CPU s/GB | C peak PSS MB | Rust peak PSS MB |
|---|--:|--:|--:|--:|--:|--:|--:|
| `h3-100k` — HTTP/3 (QUIC) 100 KB, 32 conns | 4.18 | 2.56 | **0.61x** | 3.82 | 6.23 | 38.0 | 26.0 |

### Proxy

| Scenario | C req/s | Rust req/s | **Rust/C** | C p50 / p99 ms | Rust p50 / p99 ms | C CPU µs/req | Rust CPU µs/req | C peak PSS MB | Rust peak PSS MB |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| `proxy-1k-keepalive` — proxy_pass, 1 KB, upstream keepalive | 103,689 | 30,880 | **0.30x** | 2.43 / 3.75 | 8.28 / 11.23 | 19.3 | 64.7 | 29.3 | 24.7 |
| `proxy-1k-no-keepalive` — proxy_pass, 1 KB, new upstream connection per request (keepalive 0, Connection: close) | 34,691 | 17,871 | **0.52x** | 7.29 / 8.26 | 14.36 / 19.43 | 57.5 | 111.5 | 29.3 | 24.0 |
| `proxy-100k` — proxy_pass, 100 KB, buffering on | 19,304 | 9,004 | **0.47x** | 3.30 / 3.79 | 7.23 / 8.51 | 103.6 | 222.1 | 27.6 | 18.9 |
| `proxy-1m` — proxy_pass, 1 MB, buffering on | 1,811 | 1,095 | **0.60x** | 16.72 / 28.38 | 24.80 / 50.49 | 1104.2 | 1827.0 | 28.5 | 18.2 |
| `proxy-post-10k` — POST 10 KB request body through proxy_pass | 84,858 | 21,419 | **0.25x** | 1.48 / 2.06 | 5.99 / 7.00 | 23.6 | 93.2 | 29.2 | 23.8 |
| `proxy-tls-terminate` — HTTPS in, HTTP keepalive upstream, 1 KB | 79,191 | 25,896 | **0.33x** | 3.19 / 3.78 | 9.80 / 12.40 | 25.2 | 77.0 | 38.7 | 29.7 |
| `proxy-to-tls-upstream` — HTTP in, HTTPS keepalive upstream (proxy_ssl), 1 KB | 79,161 | 27,259 | **0.34x** | 3.22 / 5.34 | 9.53 / 12.41 | 25.2 | 73.3 | 39.4 | 35.4 |
| `proxy-h2-frontend` — h2 over TLS in, HTTP/1.1 keepalive upstream, 1 KB | 74,737 | 28,872 | **0.39x** | 10.61 / 37.77 | 34.17 / 59.03 | 26.8 | 69.4 | 43.7 | 64.2 |
| `proxy-cache-hit` — proxy_cache HIT, 1 KB (served from cache file) | 102,903 | 33,651 | **0.33x** | 2.48 / 2.99 | 7.57 / 8.54 | 19.4 | 59.3 | 26.5 | 20.7 |
| `proxy-h2-upstream` — proxy_pass with proxy_http_version 2 to an HTTP/2 TLS upstream, keepalive, 1 KB | 76,937 | 26,420 | **0.34x** | 1.65 / 3.32 | 4.90 / 7.18 | 26.0 | 75.6 | 33.6 | 24.7 |
| `grpc-pass` — h2/TLS in (16 conns x 8 streams), grpc_pass to an HTTP/2 TLS upstream, keepalive, 1 KB | 67,524 | 25,211 | **0.37x** | 1.96 / 3.07 | 5.14 / 6.90 | 29.6 | 79.3 | 37.0 | 28.3 |
| `fastcgi-1k` — fastcgi_pass to Go FastCGI server, keepalive, 1 KB | 40,249 | 29,521 | **0.73x** | 3.12 / 11.69 | 4.32 / 6.51 | 30.6 | 67.6 | 27.7 | 20.1 |

Bandwidth view:

| Scenario | C Gbit/s | Rust Gbit/s | **Rust/C** | C CPU s/GB | Rust CPU s/GB | C peak PSS MB | Rust peak PSS MB |
|---|--:|--:|--:|--:|--:|--:|--:|
| `proxy-100k` — proxy_pass, 100 KB, buffering on | 15.89 | 7.39 | **0.46x** | 1.01 | 2.17 | 27.6 | 18.9 |
| `proxy-1m` — proxy_pass, 1 MB, buffering on | 15.20 | 9.19 | **0.60x** | 1.05 | 1.74 | 28.5 | 18.2 |

### Stream

| Scenario | C req/s | Rust req/s | **Rust/C** | C p50 / p99 ms | Rust p50 / p99 ms | C CPU µs/req | Rust CPU µs/req | C peak PSS MB | Rust peak PSS MB |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| `stream-tcp-proxy` — stream proxy_pass (TCP relay) to HTTP backend, 1 KB keep-alive | 147,992 | 118,504 | **0.80x** | 1.70 / 2.59 | 2.13 / 2.55 | 13.4 | 16.8 | 29.1 | 25.5 |
| `stream-tls-terminate` — stream ssl termination + TCP relay, 1 KB keep-alive | 116,784 | 87,792 | **0.75x** | 2.15 / 3.12 | 2.87 / 4.25 | 17.1 | 22.7 | 40.5 | 32.2 |

Bandwidth view:

| Scenario | C Gbit/s | Rust Gbit/s | **Rust/C** | C CPU s/GB | Rust CPU s/GB | C peak PSS MB | Rust peak PSS MB |
|---|--:|--:|--:|--:|--:|--:|--:|
| `stream-bulk-iperf` — iperf3 single TCP stream through stream proxy (bulk relay) | 12.68 | 12.06 | **0.95x** | 0.61 | 0.65 | 26.2 | 15.9 |

### Fixed rate

| Scenario | C CPU % | Rust CPU % | **Rust/C CPU** | C p50 / p90 / p99 ms | Rust p50 / p90 / p99 ms | C peak PSS MB | Rust peak PSS MB |
|---|--:|--:|--:|--:|--:|--:|--:|
| `rate-h1-static-1k` — 10k req/s fixed, static 1 KB, 50 conns (latency at equal load) | 18 | 48 | **2.70x** | 0.10 / 0.14 / 0.21 | 0.21 / 0.35 / 0.53 | 26.4 | 16.8 |
| `rate-tls-1k` — 10k req/s fixed, HTTPS 1 KB, 50 conns | 23 | 58 | **2.54x** | 0.12 / 0.19 / 0.31 | 0.27 / 0.48 / 0.74 | 28.6 | 18.7 |
| `rate-h2-1k` — 10k req/s fixed, h2 1 KB, 10 conns x 10 streams | 21 | 49 | **2.34x** | 0.15 / 0.24 / 0.38 | 0.46 / 0.66 / 0.92 | 28.0 | 19.7 |
| `rate-proxy-1k` — 10k req/s fixed, proxy_pass keepalive, 1 KB | 21 | 71 | **3.41x** | 0.15 / 0.22 / 0.44 | 0.38 / 0.60 / 0.97 | 26.9 | 18.1 |

### Memory

| Scenario | C PSS before → with 10k conns (MB) | Rust PSS before → with 10k conns (MB) | C KB/conn | Rust KB/conn | **Rust/C** | C after close (MB) | Rust after close (MB) |
|---|--:|--:|--:|--:|--:|--:|--:|
| `idle-10k-h1` — 10,000 idle HTTP/1.1 keep-alive connections | 25.9 → 31.3 | 15.6 → 129.9 | 0.56 | 11.71 | **20.9x** | 26.7 | 130.0 |
| `idle-10k-tls` — 10,000 idle HTTPS keep-alive connections | 25.9 → 172.1 | 15.6 → 269.5 | 14.97 | 26.00 | **1.7x** | 172.2 | 269.6 |
| `idle-10k-h2` — 10,000 idle HTTP/2 (TLS) connections | 25.9 → 176.7 | 15.7 → 259.0 | 15.45 | 24.91 | **1.6x** | 176.8 | 259.0 |

### Run health

| Scenario | Server | valid/runs | rps spread | invalid reasons | post-load CPU spin | forced stop | error.log (first distinct) |
|---|---|--:|--:|---|--:|---|---|
| `h1-2k-conns` | c | 3/3 | 13% |  | 0% |  |  |
| `grpc-pass` | c | 3/3 | 15% |  | 0% |  |  |
| `stream-bulk-iperf` | c | 3/3 | - |  | 0% |  | 119459#119459: *5 writev() failed (104: Connection reset by peer) while proxying and sending to upstream<br>119460#119460: *9 writev() failed (104: Connection reset by peer) while proxying and sending to upstream<br>119504#119504: *9 writev() failed (104: Connection reset by peer) while proxying and |
| `stream-bulk-iperf` | rust | 3/3 | - |  | 0% |  | 119472#119472: *9 writev() failed (104: Connection reset by peer) while proxying and sending to upstream<br>119473#119473: *5 writev() failed (104: Connection reset by peer) while proxying and sending to upstream<br>119491#119491: *9 writev() failed (104: Connection reset by peer) while proxying and |
