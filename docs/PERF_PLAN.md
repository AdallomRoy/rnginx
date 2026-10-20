# Plan: the user-space CPU per request

Date: 2026-10-20, master `bee4068`. This plan follows `docs/IO_URING_PLAN.md`
(done) and replaces Phases 2 and 3 of `bench/PLAN.md`, which were written on
2026-10-02, before io_uring changed where the time goes.

Goal, as in `bench/PLAN.md` §2: at least 0.95× C's requests per second and at
most 1.05× its CPU per request on every saturation scenario; the fixed-rate
scenarios at equal CPU; idle memory per connection within 2× C (HTTP/1) and
1.2× (TLS, HTTP/2). Then faster than C.

Data: `bench/results/plan2/` (benchmarks) and `bench/results/analysis/`
(`profile-1792504702.json`, `allocs-1792505668.json`,
`allocsites-1792509600.json`); the scripts are in `bench/local/` (`plan2.sh`,
`pgo.sh`, `ab.sh`).

## 1. Where we are

### 1.1 Throughput
The full run of 2026-10-19 (`bench/PLAN.md` §1.7, master `6a3128d`, io_uring
the default) puts the geometric mean of the 35 saturation scenarios at
**0.95×** C, with CPU per request at 1.06×. Ten scenarios are above C:

- static files up to 16 KB;
- HTTP/2 with small responses;
- the 1 MB file;
- ECDSA handshakes;
- `fastcgi-1k`;
- `h1-sub-filter-sendfile`, where C is unusually slow.

These are below 0.9×:

| Scenario | ÷ C | Scenario | ÷ C |
|---|--:|---|--:|
| `h3-1k` | 0.63× | `h1-conn-close` | 0.81× |
| `proxy-post-10k` | 0.66× | `proxy-100k` | 0.82× |
| `proxy-tls-terminate` | 0.68× | `h1-regex-rewrite` | 0.85× |
| `proxy-1k-keepalive` | 0.69× | `proxy-1m`, `proxy-1k-no-keepalive` | 0.87× |
| `proxy-to-tls-upstream` | 0.75× | `h1-static-100k`, `h2-tls-100k` | 0.89× |
| `grpc-pass` | 0.76× | `h2c-100k` | 0.90× |
| `h1-sub-filter` | 0.77× | `stream-bulk-iperf` | unstable, §2.3 |

At a fixed 10k req/s, rnginx uses 1.10–1.60× C's CPU (`rate-proxy-1k`
1.60×, `rate-h2-1k` 1.43×). An idle HTTP/1.1 connection holds 2.52 KB, against
C's 0.56.

### 1.2 The kernel is done; the gap is user time
These are profiles of `bee4068` and C on 12 scenarios, with 2 workers
saturated (frame-pointer build). CPU per request is in µs, split at the
kernel boundary; user time includes OpenSSL and libc.

| Scenario | C total | rnginx total | C user | rnginx user | C kernel | rnginx kernel |
|---|--:|--:|--:|--:|--:|--:|
| `h1-return` | 8.5 | 9.2 | 1.7 | **3.7** | 6.8 | 5.5 |
| `h1-regex-rewrite` | 10.0 | 11.9 | 2.9 | **5.7** | 7.1 | 6.2 |
| `h1-conn-close` | 29.1 | 36.1 | 5.2 | **11.4** | 23.9 | 24.7 |
| `tls-h1-1k` | 20.2 | 21.1 | 7.6 | **11.9** | 12.6 | 9.3 |
| `proxy-1k-keepalive` | 20.7 | 29.7 | 5.3 | **13.3** | 15.5 | 16.4 |
| `proxy-post-10k` | 25.0 | 37.2 | 5.8 | **15.7** | 19.1 | 21.5 |
| `proxy-to-tls-upstream` | 27.5 | 32.8 | 11.1 | **17.8** | 16.4 | 15.1 |
| `grpc-pass` | 31.6 | 40.6 | 14.0 | **25.3** | 17.5 | 15.3 |
| `h3-1k` | 23.4 | 37.9 | 10.0 | **21.8** | 13.4 | 16.1 |
| `h1-sub-filter` | 275.5 | 359.2 | 146.9 | **218.1** | 128.7 | 141.2 |
| `proxy-100k` | 111.9 | 135.7 | 12.8 | **35.2** | 99.1 | 100.6 |
| `h2c-100k` | 54.8 | 61.6 | 7.6 | **23.6** | 47.2 | 37.9 |

- **Kernel:** rnginx's kernel time is below C's, or within 1.5 µs of it,
  everywhere except:
  - HTTP/3 (+2.7 µs), whose UDP sockets are not on the ring;
  - `proxy-post-10k` (+2.4), which receives and forwards a 10 KB body;
  - `h1-sub-filter` (+12.5 of 129).
- **User:** rnginx's user time is **2–3× C's in every scenario**. That is the
  whole gap.

System calls per request (`analyze.py uringstat`) confirm it:

| Scenario | C | rnginx |
|---|--:|--:|
| `h1-return` | 2.01 | 0.07 (one `io_uring_enter` per ~30 requests) |
| `tls-h1-1k` | 7.03 | 4.08 |
| `proxy-1k-keepalive` | 5.03 | 2.08, plus 3 ring operations |
| `proxy-to-tls-upstream` | 6.04 | 4.09 |

Upstream TLS is still on epoll, so it still makes C's four calls: two reads,
a write and an EAGAIN.

### 1.3 Allocations per request
Counted by `analyze.py allocs` on the glibc build. C's counts are mostly
its pools: one `malloc` for a pool, then `ngx_palloc` inside it.

| Scenario | C | rnginx | Scenario | C | rnginx |
|---|--:|--:|---|--:|--:|
| `h1-return` | 3.0 | 19.6 | `h3-1k` | 3.2 | 70.3 |
| `h1-static-1k` | 3.0 | 29.1 | `proxy-1k-keepalive` | 5.0 | 78.3 |
| `h1-regex-rewrite` | 3.0 | 35.5 | `proxy-post-10k` | 7.0 | 80.0 |
| `h1-conn-close` | 4.0 | 36.0 | `proxy-to-tls-upstream` | 12.9 | 89.1 |
| `tls-h1-1k` | 11.4 | 44.5 | `grpc-pass` | 22.6 | 105.7 |
| `h2c-1k` | 3.1 | 39.4 | `proxy-100k` | 13.0 | 130.7 |
| `h2-tls-1k` | 9.1 | 47.2 | | | |

`h1-return` was at 14.0 after Phase 1 of `bench/PLAN.md`. io_uring added
about 5: the boxed write continuation and the operation payloads.

**Where they come from** (`analyze.py allocsites`):
- **Headers.** Header copies are the largest source.
  - `proxy-1k-keepalive`: the upstream response's header lines account for
    ~24 of 78 (`proxy::process_header`, three per line). Request and
    response header entries add ~18 (`TableElt::owned` and `::generated`,
    `push_copy`), and the request line, URI and host ~7.
  - `h1-return`: 11 of 19 come from the request line and the header lines.
  - `h3-1k` and `grpc-pass`: the same, plus HPACK and QPACK fields.
- **One per request each:** the request object, the boxed filter steps
  (`Step::boxed`, 1–3), the ring's send payload, and per-module contexts and
  closures (`set_ctx`, closures made at configuration time that allocate
  per call).
- **Inside OpenSSL:** ~12 per request on upstream TLS (`SSL_read` and
  `SSL_write` with `SSL_MODE_RELEASE_BUFFERS`, as in C).

## 2. Where the user time goes

### 2.1 Spread thin
No function of `proxy-1k-keepalive` takes more than 1.7% of the CPU. Its
13.3 µs of user time, by what costs it:

| Cost | µs/req | Detail |
|---|--:|---|
| The state machines' own code | ~2.6 | Self time of the `async fn` bodies: `send_request` 0.49, `run_request` 0.31, `proxy_handler` 0.29, `Phases::poll` 0.28, `init_request` 0.27, `connection_task` 0.23, `write_loop` 0.21, `send_response` 0.20. Part of it is work inlined into them. |
| tokio | 1.07 | `Notify` 0.25 (a thread-safe primitive with a mutex, used on one thread); timers 0.3 (`Sleep::new_timeout`, a timer entry registered and dropped for each wait); tasks and wakers 0.4. |
| The allocator | ~0.75 | jemalloc's malloc 0.38, free 0.26, cache flushes 0.1. |
| Freeing the request | 0.55 | `Rc::drop_slow` and frees under `connection_task`: the request object and what it holds, dropped field by field. |
| Copies | 0.55 | Provided buffers copied out 0.17; futures moved into boxes ~0.25. |
| Parsing, PCRE | 0.68 | As in C (0.67). |

The futures are large:
- `proxy_handler()` is 8,152 bytes, and the content handler boxes it for
  every request (`Box::pin(proxy_handler(r))`). Most of it is state for paths
  a 1 KB keepalive request never takes: cache, upgrade, non-buffered and
  duplex modes.
- `upstream_rt::init()` is 5,632 bytes and `init_request()` 3,480.
- `write_loop()` is 1,480, boxed for each ring send.

Elsewhere the pattern is the same. tokio costs:

| Scenario | µs/req | Note |
|---|--:|---|
| `h1-return` | 0.57 | 6% of its CPU |
| `h1-conn-close` | 1.26 | |
| `grpc-pass` | 2.56 | `Notify` 0.67 |
| `h3-1k` | 2.16 | `Notify` 0.48 |

### 2.2 Specific waste
The profiles found these, and each is a local fix.

| Where | Cost | Cause |
|---|--:|---|
| `h2c-100k`, `v2/filter.rs` `take_from` | 2.05 µs (3.3%) | DATA payloads are read from the file into zero-filled memory (`resize(n, 0)` before `pread`). `copy_filter.rs` reads into spare capacity instead. |
| `h2c-100k`, `v2/connection.rs` `start_output` | 3.73 µs (6%) | Every frame is copied into the write buffer before the send. C sends the frames' own buffers, and file pages by sendfile. |
| `proxy-100k`, `event_pipe.rs` `RawBuf::unfilled_mut` | 1.03 µs | The pipe's raw buffers are zero-filled on their first read. They belong to the request, so this happens once per response. C does not initialize them. |
| `proxy-100k`, upstream reads | 1.2 µs (0.17 on 1 KB) | Every received byte is copied out of the provided buffer (`read_stash`, `poll_pipe_recv_conn`). `IO_URING_PLAN.md` §7 estimated 0.9 µs. |
| `h1-sub-filter`, the send path | ~38 µs of 359 | Per-buffer costs over the ~850 buffers of a response: `plain_send_chain_pass` 17, `chunked_body_filter` 9.7, `update_sent` 7.0, `loc_conf` lookups 4.1. |
| `h1-sub-filter`, the buffers | ~10 µs | Each piece is an owned `Vec`, so an allocation and a copy. C's buffers point into the input and the replacement string. |
| `h1-sub-filter`, the matcher | 143 µs against 111 | `sub_body_filter` itself is 1.3× C's `ngx_http_sub_body_filter` plus `ngx_http_sub_match`. |
| `h3-1k`, `v3/request.rs` `init_request_stream` | 1.29 µs self | Not yet explained. |
| `proxy-*`, `upstream_rt.rs` | 0.07 µs | `u.resp.buf` is zero-filled for every request (`resize(len + room, 0)`). |

### 2.3 The stream relay since `bee4068`
`stream-bulk-iperf`, 5 reps (`results/plan2/stream-bulk.jsonl`), in Gbit/s,
with the worker's CPU use:

| Build | Runs | Median |
|---|---|--:|
| C | 13.9, 12.5, 14.0, 11.8, 12.0 | 12.5 |
| master (io_uring) | 12.4, 11.3, **6.2 (50% CPU)**, **6.5 (50% CPU)**, 11.1 | 11.1 |
| master, `RNGINX_URING_WRITES=sync` | 12.1, 12.7, 11.0, 11.0, 10.8 | 11.0 |
| master on epoll | 11.4, 11.4, 11.3, 13.3, 11.4 | 11.4 |

**What happens.** Once a write at once finds the socket full, the rest goes
to the ring as a copy. The writes after it then queue behind that send:
`uring_writev` makes no write at once while a send is in flight. From then
on, every write waits for a ring send and a run of the tasks, and the worker
idles at 50%.

**Fix.** With `sync` (`writev()`, then a wait for room and another
`writev()`, as C does) the runs are stable.

## 3. Approach
Three kinds of work, in order of cost:
1. **The build.** PGO (§4) gives +8 to +32%, measured, with no code change.
2. **Local waste** (§2.2, §2.3). Each fix takes days, and its savings are
   already measured.
3. **Per-request structure.** This covers the runtime's per-wait costs, the
   request and connection objects, header copies and other allocations, the
   size and depth of the futures, and the layers of proxying and HTTP/3. Most
   of the gap is here; the work is mechanical but broad.

The rules stay those of `bench/PLAN.md` §2:
- nginx-tests pass the same 455 files, with io_uring and with epoll;
- `cargo test --workspace` passes;
- the crates stay `forbid(unsafe_code)`;
- behaviour stays C's: responses, log lines, timeouts and the order of
  observable system calls.

## 4. Phase 0: PGO (days)
These are the same code built with a profile, against C and the usual
build (`results/plan2/pgo-ab.jsonl`). The three servers alternate in each
rep, 3 reps, with no errors. Ratios are medians of per-rep ratios:

| Scenario | master ÷ C | **master + PGO ÷ C** | PGO ÷ master |
|---|--:|--:|--:|
| `h1-return` | 0.93× | **1.01×** | 1.105 |
| `h1-static-1k` | 1.12× | **1.27×** | 1.159 |
| `h1-conn-close` | 0.78× | **0.98×** | 1.250 |
| `h1-regex-rewrite` | 0.89× | **1.00×** | 1.123 |
| `tls-h1-1k` | 0.95× | **1.10×** | 1.143 |
| `h2c-1k` | 1.48× | **1.75×** | 1.179 |
| `h3-1k` | 0.67× | **0.89×** | 1.321 |
| `proxy-1k-keepalive` | 0.69× | **0.86×** | 1.235 |
| `proxy-post-10k` | 0.68× | **0.81×** | 1.211 |
| `grpc-pass` | 0.78× | **0.91×** | 1.179 |
| `proxy-100k` | 0.82× | **0.88×** | 1.077 |
| geometric mean | | | **1.178** |

CPU per request, user / kernel µs:

| Scenario | C | master | master + PGO |
|---|--:|--:|--:|
| `h1-return` | 1.55 / 6.71 | 3.60 / 5.32 | 2.88 / 5.24 |
| `h1-conn-close` | 4.87 / 22.95 | 11.47 / 23.68 | 6.94 / 21.33 |
| `h3-1k` | 10.02 / 13.00 | 21.24 / 15.02 | 13.38 / 12.62 |
| `proxy-1k-keepalive` | 4.89 / 14.90 | 12.87 / 15.80 | 8.91 / 14.37 |
| `grpc-pass` | 13.89 / 17.10 | 25.33 / 14.65 | 20.35 / 13.58 |

- **User time** drops by 20–40%. The 40 MB binary carries every module,
  and the profile lays out the hot code together.
- **Kernel time** drops by 1.1–2.4 µs where the footprint is largest
  (`h1-conn-close`, `h3-1k`, `proxy-*`). This fits `bench/PLAN.md` §1.2's
  attribution of the extra kernel time to cache and TLB pollution from the
  user-space footprint.
- **After PGO, user time is still 1.2–2.1× C's.** The rest of this plan is
  still needed, but it starts from a smaller base.

**The build.**
- Four steps: a `-Cprofile-generate` build, a training run, `llvm-profdata
  merge` (from the rustup component `llvm-tools`), and a `-Cprofile-use`
  build.
- The training load is a broad mix of `bench.py` scenarios, so that no
  protocol is left cold: 27 of them here, 3 s each (`bench/local/pgo.sh`).
- To do:
  - a script in `scripts/` that does all four steps;
  - the benchmark and released binaries built with it;
  - CI building the profile once per release.
- Day-to-day builds stay as they are.

**Before adopting:**
- nginx-tests on the PGO binary, in both event modes;
- a full `bench.py` run, to check the scenarios outside the training mix:
  `h1-2k-conns`, `h1-static-1m`, `tls-h1-1m`, the handshakes,
  `h2-tls-100k`, `h3-100k`, `proxy-1m`, `proxy-h2-frontend`, the fixed-rate
  and memory scenarios.

**Then BOLT.** Post-link layout attacks the same misses; it is not measured
yet.

## 5. Phase A: local waste (1–2 weeks)

| # | Change | Files | Saving (µs per request, before PGO) |
|---|---|---|---|
| A1 | Read HTTP/2 DATA from a file into spare capacity (`rustix::buffer::spare_capacity`, as `copy_filter.rs` does) | `v2/filter.rs` | `h2c-100k` −2.0; `h2-tls-100k` likewise |
| A2 | Send HTTP/2 frames from their own buffers, with no `wbuf` copy on plain connections. The ring's send takes the queued frames as an owned list, with iovecs over each `OutFrame`, which returns to `FRAME_BUFS` at completion; the write at once is a `writev()` of the same. | `v2/connection.rs`, `ngx-core/connection.rs` | `h2c-100k` −3.7 |
| A3 | Take the event pipe's raw buffers and `u.resp.buf` from a per-worker free list of initialized buffers (as `FRAME_BUFS` and the copy filter do), returned when the pipe is dropped | `event_pipe.rs`, `upstream_rt.rs` | `proxy-100k` −1.0; `proxy-1k` −0.07 |
| A4 | Read upstream responses without the copy. While the last read filled its length, `recv()` straight into the pipe's buffer, as C reads while `rev->ready` (the "bulk exception" of `IO_URING_PLAN.md` §2.3); use the ring only when the read would block. | `upstream_rt.rs`, `ngx-core/connection.rs` | `proxy-100k` −1.2; `proxy-1k` −0.17 |
| A5 | Write the stream relay's bulk data as C does (§2.3): `writev()`, and when the socket is full, wait for room and write again, not a ring send of a copy | `ngx-core/connection.rs` | `stream-bulk-iperf` stable, 0.88–0.91× → then the relay's copies |
| A6 | Add a single-threaded `Notify` to ngx-core with the subset of tokio's API in use (`notified()`, `notify_one()` with its stored permit, `notify_waiters()`), built on `Cell`s and a slab of wakers. The ~70 uses switch by import. | `ngx-core/sync.rs` (new), users | `proxy-1k` −0.25; `grpc-pass` −0.67; `h3-1k` −0.48 |
| A7 | Cut the per-buffer costs of the send path (for `sub_filter`): read the location conf once per call, not once per buffer; run `update_sent` and the chunk framing over runs of small buffers | `output.rs`, `chunked_filter.rs`, `write_filter.rs` | `h1-sub-filter` −20 to −30 |
| A8 | Make `analyze.py` count jemalloc's symbols (`_rjem_*`) as allocation, not as "other (binary)" | `bench/analyze.py` | tooling |

## 6. Phase B: per-request objects and the runtime's costs (4–6 weeks)
These items are independent enough for parallel workstreams, as Phase 1 of
`bench/PLAN.md` was run: B1+B6, B2+B3, B4+B5, B7, B8+B9.

| # | Change | Saving |
|---|---|---|
| B1 | **Reuse request objects** (`bench/PLAN.md` 2c). A per-worker pool of request states, reset by an exhaustive struct literal (so a new field cannot be forgotten), with the vectors' capacities kept. Subrequests and HTTP/2 and HTTP/3 streams take theirs from the same pool. | −0.4 to −0.6 µs per request; −5 to −10 allocations |
| B2 | **Wait with persistent timers.** Each of the connection's read, keepalive and send waits gets one `EventTimer`, reset and never re-registered, instead of a `tokio::time::timeout` per wait. There are ~90 sites; the request and upstream paths go first. | −0.2 to −0.4 µs per request |
| B3 | **Shrink the proxy's future.** Keep the common path small, boxing the cache, upgrade, non-buffered and duplex modes only when they are taken. Keep the handler's future in a slot of the connection, reused for each request (`Pin<Box<Option<F>>>` with `Pin::set`, as `pipe_out_slot` does), instead of an 8 KB box each time. | −0.3 to −0.5 µs per proxied request |
| B4 | **Zero-copy headers** (`bench/PLAN.md` 2a, moved up: §1.3 makes it the largest source of allocations). Header lines become slices of a shared buffer: the request's header buffer and `u->buffer` of upstream responses. HPACK and QPACK fields go into one buffer per header block. | proxy −40 to −45 allocations; `h1-return` −8 to −10; `h3-1k` −20 |
| B5 | **Cut the other allocations** down to the milestones of `bench/PLAN.md` §9: 8 on `h1-return`, 30 on proxy, 25 on `h3-1k`. Sources: `Step::boxed`, the ring's send payload, per-module contexts and closures. | ~25 ns per allocation and its free |
| B6 | **Reuse connections.** Take the connection object, its HTTP state and its log context from a per-worker free list (C's `ngx_get_connection`). | `h1-conn-close` −0.5 to −1 µs |
| B7 | **Make `sub_filter` copy nothing.** A shared variant of `BufData` (`Rc<[u8]>` and a range, `bench/PLAN.md` 2e) for the unchanged input and the replacement strings; then compare the matcher with C's. | `h1-sub-filter` → ~0.9× |
| B8 | **Run upstream TLS through the ring BIO**, as client TLS does (`IO_URING_PLAN.md` §2.9) | −4 system calls per request on `proxy-to-tls-upstream`, `proxy-h2-upstream`, `grpc-pass` |
| B9 | **Run UDP through the ring:** RECVMSG and SENDMSG (with GSO) for QUIC | `h3-1k` kernel −1.5 to −2.5 µs |

## 7. Phase C: structure (8–12 weeks)
What Phase B leaves on proxying and HTTP/3 is the cost of running each
request through nested futures, tasks and `Rc<RefCell>` objects at all.
These are the items of `bench/PLAN.md` Phases 2 and 3 that remain:

| # | Change | For |
|---|---|---|
| C1 | **Synchronous first.** A request whose header is in the buffer runs the phases, filters and write in the read's poll, with no per-request future. Only the first real wait (a body, an upstream, a full socket) goes async, as C's handlers return NGX_AGAIN (`bench/PLAN.md` Phase 3). | all small requests |
| C2 | **The upstream's keepalive path as a state machine** of C's handlers (`ngx_http_upstream.c`): connect or reuse, send, read the header, pass the body. It replaces the nested `async fn`s. | proxy, FastCGI, uwsgi, SCGI, gRPC |
| C3 | **HTTP/2 and HTTP/3 streams without a tokio task each** (`bench/PLAN.md` 2d). The connection's driver polls its streams from slots. | h2, h3 |
| C4 | **Own executor** (`bench/PLAN.md` 2b, the executor half; the reactor half went with io_uring). Done only if tokio's task costs still show after A6, B1 and B2. | all |

Each of these changes the shape of the port, so each starts with a prototype
on one scenario and a measurement, before the migration.

## 8. Projection
The table adds the savings estimated above to the PGO build's CPU per
request (`results/plan2/pgo-ab.jsonl`), scaled by 0.75: PGO makes all code
cheaper, so a saving measured before PGO counts for less after it. Ratios
are req/s ÷ C.

| Scenario | now | + PGO | + Phase A | + Phase B |
|---|--:|--:|--:|--:|
| `h1-return` | 0.93× | 1.01× | 1.02× | ~1.08× |
| `h1-conn-close` | 0.78× | 0.98× | 0.98× | ~1.02× |
| `h1-regex-rewrite` | 0.89× | 1.00× | 1.00× | ~1.07× |
| `tls-h1-1k` | 0.95× | 1.10× | 1.10× | ~1.15× |
| `h3-1k` | 0.67× | 0.89× | 0.90× | 0.95–1.0× |
| `proxy-1k-keepalive` | 0.69× | 0.86× | 0.87× | 0.92–0.97× |
| `proxy-post-10k` | 0.68× | 0.81× | 0.82× | 0.87–0.92× |
| `grpc-pass` | 0.78× | 0.91× | 0.93× | 0.97–1.0× |
| `proxy-100k` | 0.82× | 0.88× | 0.89× | 0.90–0.93× |
| `h2c-100k` | 0.90× | not measured | +9% | |
| `h1-sub-filter` | 0.77× | not measured | +8% | ~0.9× before PGO |
| `stream-bulk-iperf` | unstable | | 0.88–0.91× | |

These are additive estimates; each step is measured before the next. Phase
C is what takes proxying and HTTP/3 past C.

## 9. Measuring
- **Leading indicators, per change:**
  - user µs per request (`analyze.py profile`);
  - allocations per request (`analyze.py allocs`, glibc build);
  - system calls and ring operations (`analyze.py uringstat`).
- **Throughput:**
  - compare builds in one run, alternating, 3 reps or more, with medians of
    per-rep ratios;
  - compare PGO builds with PGO builds, since the profile shifts every
    build's numbers.
- **After each phase:** the full run of `bench.py`, the fixed-rate and
  memory scenarios included.
- **Symbolizer:** `analyze.py allocsites` now uses `llvm-addr2line` when
  present (apt: `llvm-14`). Binutils' `addr2line` took more than 8 minutes
  per run on the 40 MB binary, holding the benchmark lock all the while.
- **Before any benchmark in a fresh container:** the environment loses
  packages between sessions (`bench/PLAN.md` §2). Also needed: `llvm-14`,
  and `rustup component add llvm-tools` for PGO.

## 10. Risks
- **Request and connection reuse.** State left over from one request is a
  security bug: a header, a variable, a user's credentials. Mitigations:
  - the reset is an exhaustive struct literal;
  - debug builds poison freed states;
  - a test runs two different requests through one state and compares
    every field.
- **Timers (B2).** `send_timeout`, `keepalive_timeout`, `lingering_*` and
  `worker_shutdown_timeout` are the gates, in both event modes.
- **The single-threaded `Notify` (A6)** must keep tokio's semantics where the
  port relies on them:
  - `notify_one()` stores a permit when nobody waits;
  - `notify_waiters()` wakes only those waiting.
- **PGO.**
  - A profile from a narrow load would make the rest slower. The training
    mix covers every protocol, and the full run checks the scenarios outside
    it.
  - A stale profile still applies to the functions that did not change,
    since LLVM matches them by hash. It is regenerated for each benchmark
    and release build.
- **Zero-copy headers (B4)** touch ~230 field accesses and every module that
  reads headers. They go in behind golden-output tests of the header and log
  formatting.
- **Phase C** changes the structure of the request and upstream paths that
  every module uses. It lands one path at a time, behind the same tests.
