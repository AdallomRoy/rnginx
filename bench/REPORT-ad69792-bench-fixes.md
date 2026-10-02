# nginx C vs. Rust port (rnginx): benchmark report, after the fixes

Date: 2026-10-01.

**Compared:**
- nginx 1.31.7, C (`nginx-c/`);
- the Rust port on branch **`bench-fixes` @ `ad69792`**: `master` (`1196fa6`) plus 6 fix commits.

The first pass benchmarked `master` (report kept as `REPORT-before-fixes.md`); its numbers are the "before" column in [Before → after](#before--after).
Raw data is in `results/*.jsonl`. The harness is `bench.py`, with `report.py`, `compare.py`, `extra.py`, `churn.py`, `verify_fixes.py` and `profile2.py`.

## TL;DR

* **All four bugs the first pass found are fixed, plus the HTTP/2 memory growth**: 6 commits on `bench-fixes`, each checked against the C code.
  * The nginx-tests suite passes the **same 388 test files as `master`**. The one failure seen, `limit_req_delay.t`, is a known load flake and passes 5/5 on its own.
  * `cargo test --workspace` passes.
* **Throughput:** Rust/C goes from **0.50× to 0.54×** (geometric mean over the same 32 scenarios). CPU per request goes from **2.06× to 1.91× C's**. The worst scenario goes from 0.11× to 0.30×.
* **What changed:**
  * **Stream bulk relay:** stalled with the workers at 100% CPU, now **12.2 Gbit/s (0.97× C)**.
  * **`sub_filter`:** now actually works with the default `sendfile on`, where it is **3.0× faster than C**, because C splits that case into hundreds of small `sendfile()` calls. With `sendfile off` it is **5.8× faster than before** (0.11× → 0.63× C).
  * **10 KB POST through `proxy_pass`:** **+72%** (0.19× → 0.32× C). Bodies under 1.25 × `client_body_buffer_size` now stay in memory, as in C.
  * **HTTP/2 connection churn:** **3.2 GB → 268 MB** (C 181 MB). An idle HTTP/2 connection costs 33 → 25.5 KB.
  * **Upstream keepalive:** no longer leaks descriptors. After a single 10 s HTTP/2-proxy run the old build held **284,001 fds**; the fixed one holds ~600. The faster LTO/jemalloc builds now run with **0 errors** (before: up to 128k failed requests).
* **Unchanged:** the port's general overhead.
  * Small HTTP/1.1 requests: 0.32–0.38× C.
  * Proxying: 0.30–0.53×.
  * HTTP/2: 0.48–0.83×.
  * At equal load (10k req/s) Rust needs 2.3–3.1× the CPU, with p99 latency 2.0–2.4× C's.
  * An idle HTTP/1.1 connection costs 10.7 KB vs about 1 KB in C.
* **Not comparable:** HTTP/3 and gRPC are not ported. C serves about 88k req/s over HTTP/3.

## What was fixed

All six commits are on the `bench-fixes` branch.

| Commit | Symptom | Root cause | Fix (C reference) | Verified by |
|---|---|---|---|---|
| `b7e7fc1` upstream keepalive | ~0.6 descriptors leaked per proxied request; `connect() failed (24: Too many open files)` after a few hundred thousand requests | `spawn_close_handler` `dup()`ed the cached socket before spawning its watcher task and wrapped it in `OwnedFd` only inside the task. Reusing the connection aborted the task unpolled, leaking the raw fd | The descriptor is duplicated when the task first runs and is owned at once. A reused connection needs no watcher, as with `ngx_http_upstream_keepalive_close_handler` on the read event | Worker fds stay at or below ~600 after every proxy, proxy_ssl and FastCGI run (C: 150–300). Old build: 175k fds after 9 s, 284k after one run |
| `075b3a4` request body | Every 8–10 KB body went through a temp file (43k files in 3 s) | C's `rb->buf` sizing (the rest of the body if under 1.25 × `client_body_buffer_size`) was ported only for unbuffered bodies. The save filter wrote once the in-memory bytes reached `client_body_buffer_size` | Sizing applied to both paths. The save filter writes only when `rb->buf->last == rb->buf->end` with body remaining (`ngx_http_request_body_save_filter`); HTTP/2 uses its stream's `rb->buf` | Same spill pattern as C for 8 KB to 100 KB bodies. POST 10 KB: no temp files, +72% |
| `9780408` sub_filter | Nothing replaced with `sendfile on`; 9× C's CPU with `sendfile off` | The header filter didn't set `r->filter_need_in_memory`, so the file buffers passed through. The matcher allocated a lowercased copy at every byte position | Sets `filter_need_in_memory` (`ngx_http_sub_header_filter`). The comparison no longer allocates | 424/424 replacements with `sendfile on`. 5.8× faster with `sendfile off` |
| `3606c12` connection / stream relay | Bulk transfer through `stream { proxy_pass }` (TCP or TLS) stalled, with the workers spinning at 100% CPU and every other session starved | `Connection::try_recv` used tokio's budget-aware `poll_read_ready()` with a no-op waker. Once the coop budget was spent it reported a ready socket as `WouldBlock`, while `readable()` (not budgeted) kept returning at once: a syscall-free livelock | `try_recv` checks and clears readiness with `AsyncFd::try_io`. The relay takes one unit of coop budget per read, so a busy session yields as the C event loop moves on to other events | iperf3 12.2 Gbit/s with the worker idle afterwards. 10 MB downloads: 282 req/s (TCP) and 184 req/s (TLS) vs C's 285 and 188 (old build: 0). End-of-test control messages interleave as in C |
| `3646930` http2 | Memory grew with connection churn: 338 MB → 1.3 → 3.0 → 3.2 GB over 4 rounds of 10k connections | Each connection owned a 256 KB receive buffer; C has one per worker (`h2mcf->recv_buffer`). With glibc, after the first frees the buffers moved into the heap and `calloc()` zero-filled them | The driver waits for readiness without a buffer, then reads and processes with a pooled per-worker buffer until `EAGAIN` (`ngx_http_v2_read_handler`'s `do … while (rev->ready)`). TLS wanting a write retries on the write event (`ngx_ssl_write_handler`). The 64 KB output buffer is freed when idle (`ngx_http_v2_handle_connection`) | Flat 265–268 MB over 4 rounds; 25.5 KB per idle connection (was 33.2). All 45 h2 test files pass |
| `ad69792` http | The pooled-buffer driver made *every* HTTP/1.1 connection 3.5 KB bigger | The connection task awaited `v2::connection::init()` inline, so every task was sized to hold the HTTP/2 driver state | The HTTP/2 driver future is boxed once a connection turns out to be HTTP/2 | Idle HTTP/1.1 10.70 KB and TLS 24.88 KB per connection, slightly better than before. As a side effect, POST +19% |

Cost of the HTTP/2 change: cleartext `h2c` is about 1.7% slower (77.0k vs 78.4k req/s); h2 over TLS is unchanged (72.3k vs 72.5k in the same session).

## Setup

| | |
|---|---|
| Machine | AWS r6i.8xlarge, Xeon Platinum 8375C @ 2.9 GHz, Linux 7.0.0-1013-aws, Docker container limited to 8 physical cores (CPUs 0–7, no HT siblings) |
| C build | nginx 1.31.7, gcc 11.4 `-O2`, **same module list as the Rust binary** (`build-c.sh`), `--with-debug` kept: the Rust port always compiles its debug-log checks in, as does Ubuntu's nginx. A second build adds `--with-http_v3_module` for the h3 scenario only |
| Rust build | `bench-fixes` @ `ad69792`, rustc 1.96.1, release profile `opt-level=3`, no LTO, glibc malloc. "Before" is `master` @ `1196fa6` with the same profile |
| CPU layout | nginx under test: 2 workers pinned to CPUs 0 and 1. Backends: CPUs 2–3 (a C nginx as HTTP/HTTPS upstream, a Go FastCGI server, iperf3). Load generators: CPUs 4–7 |
| Tools | wrk 4.1.0, h2load 1.43, oha 1.16 (plus an HTTP/3 build), iperf3 3.9, `tools/idleconns` (Go) |
| Method | Fresh nginx per run, response checked with curl (status, size, body content), 3 s warm-up, 10 s measurement, 3 alternating reps, medians. Zero errors required. Afterwards: spin detection, error.log scan, worker fd count. For proxies, the backend's new-connection count is checked to confirm keepalive |

## Results (fixed build vs C)

wrk/h2load latency is closed-loop, so at saturation it mostly reflects queueing; see [Equal load](#equal-load-fixed-10000-reqs) for latency comparisons.
CPU is µs per request across all nginx processes. PSS is the peak for master plus workers during the run.

### HTTP/1.1

| Scenario | C req/s | Rust req/s | **Rust/C** | C p50 / p99 ms | Rust p50 / p99 ms | C CPU µs/req | Rust CPU µs/req | C peak PSS MB | Rust peak PSS MB |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| `return 200` (12 B, no file I/O) | 248,795 | 93,212 | **0.37×** | 1.02 / 1.12 | 2.75 / 3.01 | 8.0 | 21.4 | 26.1 | 17.6 |
| static 1 KB | 125,778 | 42,182 | **0.34×** | 2.02 / 2.17 | 6.06 / 6.51 | 15.9 | 47.3 | 26.5 | 18.9 |
| static 100 KB (sendfile) | 87,703 | 39,016 | **0.44×** | 0.72 / 0.89 | 1.65 / 1.86 | 22.7 | 51.3 | 26.5 | 16.3 |
| static 1 MB (sendfile) ¹ | 15,804 | 17,756 | **1.12×** | 1.25 / 2.05 | 1.10 / 2.28 | 64.5 | 97.8 | 26.5 | 15.7 |
| new TCP connection per request | 73,393 | 27,630 | **0.38×** | 0.82 / 1.00 | 2.25 / 2.57 | 27.0 | 72.3 | 26.4 | 15.8 |
| 2000 keep-alive connections ² | 123,600 | 40,452 | **0.33×** | 15.9 / 17.6 | 49.4 / 56.2 | 16.1 | 49.4 | 27.3 | 37.5 |
| regex location + map + set + if + rewrite + add_header | 210,316 | 68,313 | **0.32×** | 1.21 / 1.32 | 3.75 / 4.28 | 9.5 | 29.2 | 26.6 | 18.9 |
| static 1 KB + buffered access_log | 120,115 | 38,539 | **0.32×** | 2.12 / 2.62 | 6.65 / 7.58 | 16.6 | 51.8 | 26.8 | 19.0 |
| gzip 100 KB HTML (level 1) | 2,274 | 2,225 | **0.98×** | 28.0 / 57.7 | 28.7 / 97.9 | 880 | 900 | 27.2 | 32.8 |
| sub_filter 100 KB, 424 replacements, `sendfile off` | 7,561 | 4,784 | **0.63×** | 8.56 / 10.3 | 16.4 / 37.7 | 265 | 418 | 26.4 | 16.2 |
| sub_filter, same, `sendfile on` (default) ³ | 1,500 | 4,515 | **3.01×** | 43.0 / 52.0 | 17.5 / 37.2 | 1,278 | 443 | 26.6 | 16.3 |
| limit_req (shm zone, never rejects) | 121,936 | 40,862 | **0.34×** | 2.08 / 2.32 | 6.20 / 7.78 | 16.4 | 48.8 | 26.6 | 19.0 |

¹ Not CPU-bound for C: its workers were ~50% busy, Rust's ~88%. Rust spends 1.5× C's CPU per byte (0.09 vs 0.06 CPU-s/GB).
² In 1 of 3 reps both the old and the fixed Rust build showed a multi-second p99 (2.2–2.7 s); C never did.
³ With `sendfile on`, C's `sub_filter` sends the unchanged stretches between the 424 replacements (still file-backed buffers) as separate small `sendfile()` calls. Rust reads the body into memory and writes it out in a few large writes.

### HTTPS (TLS 1.3; ECDSA P-256 unless noted)

| Scenario | C req/s | Rust req/s | **Rust/C** | C CPU µs/req | Rust CPU µs/req | C peak PSS MB | Rust peak PSS MB |
|---|--:|--:|--:|--:|--:|--:|--:|
| 1 KB keep-alive | 103,245 | 42,898 | **0.42×** | 19.3 | 46.5 | 37.8 | 27.5 |
| 1 MB keep-alive (19.2 vs 16.4 Gbit/s) | 2,297 | 1,953 | **0.85×** | 871 | 1,024 | 29.3 | 18.4 |
| new connection per request, session resumption | 6,670 | 5,555 | **0.83×** | 300 | 359 | 30.5 | 18.6 |
| full handshake per request, ECDSA (not CPU-saturated) | 4,192 | 4,255 | **1.02×** | 332 | 381 | 31.1 | 20.0 |
| full handshake per request, RSA 2048 | 3,264 | 3,011 | **0.92×** | 612 | 663 | 29.7 | 18.3 |

### HTTP/2 and HTTP/3

| Scenario | C req/s | Rust req/s | **Rust/C** | C p50 / p99 ms | Rust p50 / p99 ms | C CPU µs/req | Rust CPU µs/req | C peak PSS MB | Rust peak PSS MB |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| h2/TLS 1 KB, 64 conns × 16 streams | 131,333 | 72,296 | **0.55×** | 7.88 / 10.6 | 14.1 / 16.6 | 15.2 | 27.7 | 30.5 | 50.6 |
| h2/TLS 100 KB, 32 × 8 | 17,908 | 14,789 | **0.83×** | 14.5 / 16.8 | 17.2 / 22.5 | 112 | 135 | 29.4 | 42.6 |
| h2c 1 KB (cleartext) | 109,694 | 76,987 | **0.70×** | 9.37 / 13.9 | 13.3 / 17.0 | 18.3 | 26.0 | 27.1 | 48.3 |
| h2/TLS `return 200`, 16 × 100 streams | 272,085 | 131,740 | **0.48×** | 5.93 / 7.44 | 12.5 / 19.8 | 7.4 | 15.2 | 28.3 | 39.7 |
| **HTTP/3** 1 KB, 32 conns | 88,325 | *not implemented* | – | 0.30 / 0.48 | – | 22.6 | – | 32.7 | – |

### Reverse proxy, FastCGI and stream

| Scenario | C req/s | Rust req/s | **Rust/C** | C p50 / p99 ms | Rust p50 / p99 ms | C CPU µs/req | Rust CPU µs/req | C peak PSS MB | Rust peak PSS MB |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| proxy 1 KB, upstream keepalive | 104,940 | 35,297 | **0.34×** | 2.51 / 2.76 | 7.24 / 9.12 | 19.0 | 56.6 | 28.7 | 22.5 |
| proxy 1 KB, new upstream connection per request | 34,818 | 17,484 | **0.50×** | 7.26 / 9.25 | 14.5 / 16.7 | 57.3 | 114.1 | 28.6 | 21.2 |
| proxy 100 KB | 19,318 | 11,954 | **0.62×** | 3.30 / 3.78 | 4.85 / 10.3 | 104 | 167 | 27.0 | 17.2 |
| proxy 1 MB | 1,827 | 2,009 | **1.10×** | 15.4 / 28.1 | 15.0 / 32.4 | 1,095 | 996 | 28.1 | 16.4 |
| POST 10 KB body through proxy | 85,807 | 27,455 | **0.32×** | 1.49 / 1.80 | 4.66 / 5.82 | 23.3 | 72.8 | 28.6 | 22.8 |
| HTTPS in → HTTP keepalive upstream | 79,256 | 29,359 | **0.37×** | 3.22 / 3.65 | 8.61 / 10.8 | 25.2 | 67.9 | 38.0 | 28.5 |
| HTTP in → HTTPS keepalive upstream | 79,765 | 29,490 | **0.37×** | 3.16 / 5.38 | 8.75 / 10.9 | 25.0 | 67.7 | 39.3 | 29.5 |
| h2/TLS in → HTTP/1.1 upstream ⁴ | 66,885 | 35,284 | **0.53×** | 12.9 / 44.0 | 27.2 / 51.8 | 29.9 | 56.8 | 43.7 | 65.9 |
| proxy_cache HIT 1 KB | 104,151 | 31,114 | **0.30×** | 2.45 / 2.87 | 7.61 / 9.54 | 19.2 | 64.2 | 25.9 | 19.6 |
| fastcgi_pass 1 KB (C limited by the Go backend) | 40,668 | 37,790 | **0.93×** | 3.10 / 11.8 | 3.31 / 6.90 | 30.5 | 52.8 | 27.1 | 19.2 |
| stream TCP relay, 1 KB keep-alive | 150,789 | 118,699 | **0.79×** | 1.68 / 2.64 | 2.14 / 2.70 | 13.2 | 16.8 | 28.6 | 24.2 |
| stream TLS termination + relay | 115,825 | 87,769 | **0.76×** | 2.19 / 2.58 | 2.91 / 3.47 | 17.2 | 22.7 | 39.7 | 30.7 |
| stream bulk relay (iperf3), Gbit/s | 12.57 | 12.21 | **0.97×** | | | 0.62 CPU-s/GB | 0.64 CPU-s/GB | 26.3 | 15.2 |

⁴ C's throughput in this scenario varies a lot (60–92k req/s across runs). Rust's is steady at about 35k.

### Equal load: fixed 10,000 req/s

| Scenario | C CPU | Rust CPU | **Rust/C** | C p50 / p90 / p99 ms | Rust p50 / p90 / p99 ms |
|---|--:|--:|--:|--:|--:|
| static 1 KB | 18% | 49% | **2.70×** | 0.10 / 0.15 / 0.24 | 0.22 / 0.37 / 0.57 |
| HTTPS 1 KB | 22% | 54% | **2.43×** | 0.11 / 0.19 / 0.34 | 0.25 / 0.42 / 0.74 |
| h2 1 KB, 10 conns × 10 streams | 19% | 44% | **2.32×** | 0.18 / 0.29 / 0.42 | 0.38 / 0.60 / 0.86 |
| proxy keepalive 1 KB | 20% | 62% | **3.07×** | 0.15 / 0.21 / 0.34 | 0.34 / 0.53 / 0.75 |

## Before → after

"Before" is `master` (first pass), "after" is `bench-fixes`. C is from the same session as "after".
Rows near 1.00× are unchanged within noise. `tls-h1-1k`'s 0.95× is first-pass variance: the old and new builds measured the same when run side by side (42.4k vs 42.9k req/s).

| Scenario | C req/s | Rust before | Rust after | **after/before** | Rust/C before | **Rust/C after** | Rust CPU µs/req before → after |
|---|--:|--:|--:|--:|--:|--:|--:|
| `h1-sub-filter` (sendfile off) | 7,561 | 826 | 4,784 | **5.79×** | 0.11× | **0.63×** | 2,426 → 418 |
| `h1-sub-filter-sendfile` (sendfile on) | 1,500 | *wrong output* | 4,515 | – | – | **3.01×** | – → 443 |
| `proxy-post-10k` | 85,807 | 16,009 | 27,455 | **1.72×** | 0.19× | **0.32×** | 123.8 → 72.8 |
| `stream-bulk-iperf` | 12.57 Gbit/s | **FAILED** | 12.21 Gbit/s | – | – | **0.97×** | – |
| `h2-tls-100k` | 17,908 | 14,510 | 14,789 | 1.02× | 0.81× | 0.83× | 137.9 → 135.3 |
| `h1-return` | 248,795 | 96,170 | 93,212 | 0.97× | 0.38× | 0.37× | 20.7 → 21.4 |
| `h1-static-1k` | 125,778 | 41,964 | 42,182 | 1.01× | 0.33× | 0.34× | 47.6 → 47.3 |
| `h1-regex-rewrite` | 210,316 | 68,660 | 68,313 | 0.99× | 0.33× | 0.32× | 29.1 → 29.2 |
| `h1-access-log` | 120,115 | 38,827 | 38,539 | 0.99× | 0.31× | 0.32× | 51.4 → 51.8 |
| `h1-2k-conns` | 123,600 | 40,896 | 40,452 | 0.99× | 0.34× | 0.33× | 48.9 → 49.4 |
| `tls-h1-1k` | 103,245 | 45,292 | 42,898 | 0.95× | 0.44× | 0.42× | 44.0 → 46.5 |
| `tls-handshake-ecdsa` | 4,192 | 4,273 | 4,255 | 1.00× | 1.01× | 1.02× | 372.8 → 380.6 |
| `h2-tls-1k` | 131,333 | 72,664 | 72,296 | 0.99× | 0.55× | 0.55× | 27.5 → 27.7 |
| `h2c-1k` | 109,694 | 78,712 | 76,987 | 0.98× | 0.72× | 0.70× | 25.5 → 26.0 |
| `h2-tls-return` | 272,085 | 132,970 | 131,740 | 0.99× | 0.49× | 0.48× | 15.0 → 15.2 |
| `proxy-1k-keepalive` | 104,940 | 35,774 ⁵ | 35,297 | 0.99× | 0.34× | 0.34× | 55.8 → 56.6 |
| `proxy-1k-no-keepalive` | 34,818 | 17,781 | 17,484 | 0.98× | 0.50× | 0.50× | 112.2 → 114.1 |
| `proxy-cache-hit` | 104,151 | 30,866 | 31,114 | 1.01× | 0.30× | 0.30× | 64.7 → 64.2 |
| `proxy-tls-terminate` | 79,256 | 29,586 | 29,359 | 0.99× | 0.37× | 0.37× | 67.4 → 67.9 |
| `stream-tcp-proxy` | 150,789 | 118,044 | 118,699 | 1.01× | 0.78× | 0.79× | 16.9 → 16.8 |
| `stream-tls-terminate` | 115,825 | 87,861 | 87,769 | 1.00× | 0.75× | 0.76× | 22.7 → 22.7 |
| `fastcgi-1k` | 40,668 | 37,262 | 37,790 | 1.01× | 0.94× | 0.93× | 53.0 → 52.8 |

⁵ Before the fix these runs were valid only because 13 s was too short to exhaust the 200k fd limit.
`compare.py` produces the full 38-row table (`results/before-after.md`). The rows not shown above (static 100 KB/1 MB, gzip, limit_req, TLS 1 MB and resumption, proxy 100 KB/1 MB, proxy_ssl, h2 frontend, fixed rate) are all within 0.98–1.02×.

## Memory

| | C | Rust before | Rust after |
|---|--:|--:|--:|
| Idle PSS 1 s after start, `worker_connections 20000` (C preallocates connection slots) | 28.8 MB | 16.8 MB | 16.9 MB |
| Per idle HTTP/1.1 keep-alive connection | 0.55 KB (+~0.39 KB preallocated) | 10.83 KB | 10.70 KB |
| Per idle HTTPS connection | 15.0 KB | 25.0 KB | 24.9 KB |
| Per idle HTTP/2 connection | 15.5 KB | 33.2 KB | **25.5 KB** |
| HTTP/2 churn: PSS after each of 4 rounds opening and closing 10k connections | 179 → 181 → 181 → 181 MB | 338 → 1,348 → 2,989 → **3,237 MB** | **265 → 268 → 268 → 268 MB** |
| HTTP/1.1 churn, same | 34 / 29 MB (open / closed) | 123 MB, flat | 122 MB, flat |

After closing HTTP/1.1 connections, the Rust worker keeps its peak (~120 MB) because glibc holds freed memory, but it is reused, not leaked.
The remaining per-connection difference is live state per connection: it is the same with jemalloc. C frees the request pool and header buffer when a connection goes idle.

## Where the Rust port spends its time

This profile is from the first pass. The fixes did not change these paths, except POST, whose temp-file I/O is gone.

| Scenario (CPU per request) | C user µs | C kernel µs | Rust user µs | Rust kernel µs |
|---|--:|--:|--:|--:|
| `return 200` | 1.6 | 6.4 | 10.6 | 10.0 |
| static 1 KB | 3.1 | 12.6 | 21.7 | 26.2 |
| HTTPS 1 KB | 7.3 | 12.0 | 27.8 | 16.2 |
| h2c 1 KB | 4.0 | 14.4 | 20.6 | 4.8 |
| proxy keepalive 1 KB | 4.9 | 14.2 | 32.8 | 23.0 |
| stream TCP relay | 0.9 | 12.3 | 2.7 | 14.2 |

* C spends 60–80% of its CPU in the kernel. Rust spends **3–10× more user-space time per request** and 1.2–2× more kernel time on HTTP/1.x.
* On HTTP/2, Rust's kernel time is lower than C's: it batches frames into fewer writes.
* perf: glibc takes 12% (static), 22% (proxy) and 33% (h2) of Rust's worker CPU, almost all of it malloc/free/memmove. C uses pool allocators and spends 4–7% in libc.
* The rest of Rust's overhead is spread thinly across its async state machines. There is no single hot spot.

### What-ifs on the fixed build: LTO and allocator (no code changes)

Each cell is median req/s / CPU µs per request.

| Scenario | C | Rust | + jemalloc | fat LTO | LTO + jemalloc | **LTO+je vs C** |
|---|--:|--:|--:|--:|--:|--:|
| `return 200` | 244,967 / 8.1 | 93,005 / 21.5 | 98,664 (+6%) | 106,965 (+15%) | 112,884 (+21%) / 17.7 | **0.46×** |
| static 1 KB | 126,010 / 15.8 | 42,653 / 46.8 | 43,542 (+2%) | 47,431 (+11%) | 49,239 (+15%) / 40.5 | **0.39×** |
| h2/TLS 1 KB | 133,351 / 15.0 | 71,345 / 28.1 | 82,699 (+16%) | 78,516 (+10%) | 91,926 (+29%) / 21.8 | **0.69×** |
| proxy keepalive 1 KB | 103,526 / 19.3 | 34,739 / 57.5 | 37,105 (+7%) | 39,129 (+13%) | 43,478 (+25%) / 45.9 | **0.42×** |
| POST 10 KB via proxy | 85,600 / 23.3 | 27,389 / 72.9 | 27,933 (+2%) | 24,772 (−10%) | 26,057 (−5%) / 76.7 | **0.30×** |

All of these runs had zero errors. Before the fd-leak fix, the LTO builds failed up to 128k requests in the proxy scenario.

## Other observations

* **Multi-second tail at 2000 connections.** One of three `h1-2k-conns` reps, in both the old and the fixed Rust build, had p99 = 2.2–2.7 s against ~55 ms otherwise. This was not investigated. C never showed it.
* **HTTP/3 and gRPC are not ported** (stubs only). C: 88k req/s over HTTP/3 at 22.6 CPU-µs per request.
* **Not CPU-bound for C:** static 1 MB (client/kernel bound), FastCGI (Go backend bound) and the ECDSA handshake test (C at ~70% of 2 cores). Compare CPU per request there, not req/s.

## Caveats

* Everything runs over loopback on one host with two workers. Absolute numbers are higher than over a NIC, but both servers run under identical conditions, and CPU per request is the comparable metric.
* The before/after rows come from two sessions about three hours apart. Rows within ±2% are noise; the same-session A/B runs mentioned above settle the borderline cases.

## Reproduce

```sh
cd /home/ubuntu/nginx-bench
./build-c.sh                                   # C -O2 builds (module list from bin/nginx-rust -V)
# Rust: build the bench-fixes branch (cd /home/ubuntu/rnginx-fixes && cargo build --release),
# then copy target/release/nginx to bin/nginx-rust; bin/nginx-rust-master-1196fa6 is "before"
python3 bench.py --list
python3 bench.py --reps 3                      # full suite, ~80 min
python3 bench.py --only proxy-post-10k,stream-bulk-iperf --servers c,rust,rust-old --reps 3
python3 report.py results/fixed-*.jsonl results/final-*.jsonl results/final2-*.jsonl       # tables
python3 compare.py results/full-*.jsonl,results/rerun-*.jsonl,results/rerun2-*.jsonl \
                   results/fixed-*.jsonl,results/final-*.jsonl,results/final2-*.jsonl    # before/after
python3 churn.py c=bin/nginx-c-O2 rust=bin/nginx-rust                              # h2 churn memory
python3 verify_fixes.py leak c=bin/nginx-c-O2 old=bin/nginx-rust-master-1196fa6 new=bin/nginx-rust
```

## Addendum: `master` after merging the `fixes` branch (`7f01d41`)

After this report, `master` also merged the `fixes` integration branch of 2026-09-30, which had not been merged before.
It brings the ngx_http_upstream.c core, gRPC, proxying over HTTP/2, HTTP/3 and QUIC, the tunnel and control API modules,
and the finished slice module. nginx-tests passes 447 files with it (388 before).

The fixes above carry over. The descriptor leak, the stream relay livelock and the HTTP/2 buffer growth were still present
on that branch, and were re-verified fixed after the merge.

Sanity run (2 reps, 10 s each, same harness):

| Scenario | C req/s | previous master (ad69792) | merged master (7f01d41) | merged vs previous | merged / C | merged CPU µs/req |
|---|--:|--:|--:|--:|--:|--:|
| `h1-return` | 251,795 | 93,089 | 84,771 | -9% | 0.34× | 23.5 |
| `h1-static-1k` | 126,627 | 42,418 | 47,177 | +11% | 0.37× | 42.3 |
| `tls-h1-1k` | 104,456 | 42,401 | 39,045 | -8% | 0.37× | 51.0 |
| `h2-tls-1k` | 134,427 | 71,246 | 63,462 | -11% | 0.47× | 31.6 |
| `h2c-1k` | 108,066 | 76,479 | 67,594 | -12% | 0.63× | 29.6 |
| `h3-1k` | 86,290 | – | 27,641 | – (no HTTP/3 before) | 0.32× | 72.1 |
| `proxy-1k-keepalive` | 111,764 | 36,566 | 31,065 | -15% | 0.28× | 64.3 |
| `proxy-100k` | 19,882 | 11,945 | 9,116 | -24% | 0.46× | 219.4 |
| `proxy-post-10k` | 85,820 | 27,651 | 21,482 | -22% | 0.25× | 93.0 |
| `fastcgi-1k` | 40,361 | 38,054 | 29,386 | -23% | 0.73× | 68.0 |
| `stream-tcp-proxy` | 151,136 | 118,423 | 118,224 | -0% | 0.78× | 16.9 |

* **HTTP/3 can now be compared:** Rust reaches 0.32× C's throughput over QUIC, at 72 vs 22 CPU-µs per request.
* **Static 1 KB is 11% faster** than on the previous `master`. Most other HTTP paths are 8–12% slower, and proxying /
  FastCGI is 15–24% slower: the faithful port of the upstream core and event pipe costs throughput in this port.
* **These differences come from the `fixes` code, not from the merge.** A same-session A/B against the branch built as it was
  matched within 1%, except h2 at −2–3% from the pooled receive buffers. That build also leaked 243k–287k descriptors per
  proxy run, where the merged `master` held ~550.
* Per idle connection: HTTP/1.1 11.7 KB and TLS 26.0 KB (about +1 KB, from the branch), HTTP/2 24.9 KB. HTTP/2 churn stays
  flat (262–264 MB).
* A full rerun of all 42 scenarios on the merged `master` has not been done; the tables above describe `ad69792`.
