# Plan: rnginx at performance parity with nginx C

Date: 2026-10-02.

Inputs to this plan:
- the benchmark analysis `REPORT.md` (master `7f01d41`);
- the run of branch `perf-fixes` (`results/perf-fixes-20261001.jsonl`);
- a re-run of C / master / perf-fixes / safe (`results/safe-check-20261002.jsonl`);
- six code reviews of the hot paths, run on perf-fixes: request lifecycle, filters and output, I/O and runtime, proxy, h2/h3/TLS, and config/variables/build.

Unless stated otherwise:
- file references are to `/home/ubuntu/rnginx-perf` (perf-fixes);
- all savings are estimates from reading the code, priced at the report's measured ~50 ns per allocation and freeing, and its profiles;
- every step must be validated with the benchmark before it counts.

## 1. Where we are

| | C | master | perf-fixes | safe |
|---|--:|--:|--:|--:|
| geomean, 35 scenarios | 1 | 0.52× | not run on all | = master (§1.3) |
| `h1-return` req/s | 247k | 85.6k (0.35×) | 120k (0.48×) | = master |
| `h1-return` user / kernel µs per request | 1.6 / 6.4 | 12.8 / 10.6 | 7.9 / 8.8 | 13.7 / 10.5 |
| `h1-static-1k` | 125k | 0.38× | 0.52× | = master |
| `h1-regex-rewrite` | 208k | 0.30× | 0.42× | |
| `tls-h1-1k` | 101k | 0.39× | 0.53× | = master |
| `h2-tls-1k` | 129k | 0.49× | 0.64× | = master |
| `proxy-1k-keepalive` | 104k | 0.30× | 0.38× | = master |

The C, master and perf-fixes figures are from the 2026-10-01 runs. §1.3 has the 2026-10-02 re-run, where all four were measured together.

### 1.1 What `perf-fixes` already did (9 commits, not on master)
- request body forwarded without the per-byte copy;
- read readiness cleared after a short read, as C does;
- dup-free client-close and keepalive watchers;
- TLS and upstream reads only once the socket is read-ready;
- no per-request clones of the cached time, rewrite codes or log handlers;
- filters and phase handlers that have nothing to do for a request are skipped without a boxed future.

### 1.2 What is left
**Syscalls are no longer the problem.** After perf-fixes the counts per request equal C's:

| Scenario | Rust | C |
|---|--:|--:|
| `h1-return` | 2.02 | 2.01 |
| `tls-h1-1k` | 7.06 | 7.03 |
| `stream-tcp-proxy` | 4.04 | 4.02 |
| `proxy-1k-keepalive` | 4.08 | 5.03 |

**What remains** is user CPU, 2.5–5× C's, plus kernel time 1.2–1.4× C's for the *same* syscalls:

**Allocations.** C does 3–22 per request.

| Scenario | Allocations per request |
|---|--:|
| `return 200` | 37 |
| static 1 KB | 70 |
| proxy 1 KB | 159 |
| h2 | ~175 |
| h3 | ~250 |

Where they come from:
- 7–8 copies per header line;
- copies of the request line;
- the request object (2.6 KB) and `r.ctx` (1.2 KB), both on glibc's slow path;
- owned copies of every variable value;
- per-call regex match data;
- per-response header Strings;
- iovec Vecs;
- keepalive buffers zero-filled on every cycle.

**Async layers.**
- 4–7 boxed futures per request remain (rewrite and static handlers, header, copy and write filters, the proxy content handler).
- Every layer is polled.

**tokio, about 1.1 µs per request on HTTP/1 and 3.3–4.2 µs on proxy/h2/h3.**
- About 12 mutex pairs and 15 atomic operations per request.
- A timer registered and cancelled per keepalive cycle.
- Two `Notify` waiters per request.
- A worker-cycle wakeup on every connection drop.

**Smaller items:**
- a clock read on every cached-time access;
- an `Rc` clone and a downcast on each of the ~50 config lookups per request;
- linear scans in `map`.

**Kernel.** The extra kernel time per syscall is attributed to cache and TLB pollution from Rust's larger user-space footprint. It should shrink as user CPU drops, and is measured, not assumed, at each phase.

### 1.3 The `safe` branch
`safe` is master plus the unsafe removal; it does not include perf-fixes. Re-run on 2026-10-02 (`results/safe-check-20261002.jsonl`, medians of 3, ratios to C):

| Scenario | C req/s | master | perf-fixes | safe |
|---|--:|--:|--:|--:|
| `h1-return` | 251k | 0.33× | 0.48× | 0.33× |
| `h1-static-1k` | 117k | 0.40× | 0.50× | 0.36× ¹ |
| `h1-limit-req` | 116k | 0.39× | 0.51× | 0.38× |
| `tls-h1-1k` | 103k | 0.38× | 0.53× | 0.38× |
| `h2-tls-1k` | 130k | 0.47× | 0.59× | 0.37× ¹ |
| `h3-1k` | 83k | 0.33× | 0.40× | 0.32× |
| `proxy-1k-keepalive` | 97k | 0.28× | 0.38× | 0.27× |
| `proxy-cache-hit` | 93k | 0.34× | 0.44× | 0.34× |

¹ This day's runs drifted ±10–20% between reps, for every server alike: slow and fast windows came and went during the run. A paired re-run, master and safe alternating with 5 reps each (`results/safe-ab-20261002.jsonl`), gives safe/master per-rep medians of **1.04 on `h1-static-1k`** and **1.01 on `h2-tls-1k`**. Allocations per request are equal or lower on safe (`results/analysis/allocs-1790944683.json`):

| Scenario | master | safe |
|---|--:|--:|
| `h1-return` | 81.2 | 81.2 |
| `h1-static-1k` | 124.3 | 120.3 |
| `h2-tls-1k` | 175.6 | 171.6 |

**Conclusion: removing `unsafe` cost no measurable throughput.**

The reviews still found three hot-path costs on safe that Phase 0 removes. Each is too small to show at this noise level:
- the descriptor table (`fd.rs`: a global Mutex plus an `Arc` clone per `fd::get`, about 30–60 ns, 1–8 calls per request);
- per-datagram allocations in nix's UDP `cmsg` helpers;
- `getpid()` in the zone mutex, which the old `ShmTx` did as well.

No added costs were found in the TLS/QUIC crypto or shared-memory accessors.

### 1.4 After Phase 1 (master `85adcd1`)
Master `85adcd1` is safe + perf-fixes (`8dcf1ef`, "before" below) plus the six Phase 1 workstreams. The build profile and allocator (Phase 0 item 3) are not applied yet. Run on 2026-10-02 (`results/phase1-20261002.jsonl`): medians of 3, the three servers interleaved in each rep, spread between reps ≤ 5%, no errors. Ratios to C:

| Scenario | C req/s | before | after | after/before ¹ | user µs per request, C / before / after | kernel µs, C / before / after |
|---|--:|--:|--:|--:|--:|--:|
| `h1-return` | 246k | 0.49× | 0.58× | 1.19 | 1.6 / 7.9 / 5.9 | 6.5 / 8.8 / 8.2 |
| `h1-static-1k` | 126k | 0.51× | 0.61× | 1.20 | 3.2 / 14.5 / 10.2 | 12.6 / 16.4 / 15.6 |
| `h1-regex-rewrite` | 210k | 0.40× | 0.52× | 1.27 | 2.7 / 13.5 / 9.4 | 6.8 / 10.0 / 9.0 |
| `h1-access-log` | 117k | 0.51× | 0.62× | 1.22 | 3.9 / 16.4 / 11.6 | 13.2 / 17.1 / 15.9 |
| `tls-h1-1k` | 101k | 0.53× | 0.65× | 1.21 | 7.4 / 21.3 / 15.4 | 12.1 / 15.5 / 14.7 |
| `h2-tls-1k` | 133k | 0.63× | 0.81× | 1.28 | 6.2 / 18.5 / 13.7 | 8.9 / 5.3 / 5.1 |
| `h2c-1k` | 110k | 0.83× | 1.11× | 1.33 | 4.0 / 16.9 / 11.7 | 14.3 / 4.9 / 4.7 |
| `h3-1k` | 84k | 0.39× | 0.50× | 1.27 | 10.1 / 42.9 / 31.2 | 13.4 / 17.2 / 16.3 |
| `proxy-1k-keepalive` | 102k | 0.41× | 0.51× | 1.25 | 5.0 / 28.5 / 19.8 | 14.5 / 19.2 / 18.3 |
| `proxy-post-10k` | 85k | 0.43× | 0.52× | 1.20 | 5.7 / 31.0 / 22.6 | 17.8 / 23.2 / 22.4 |
| `proxy-cache-hit` | 105k | 0.41× | 0.53× | 1.29 | 5.2 / 26.2 / 18.1 | 14.1 / 20.2 / 18.1 |
| `grpc-pass` | 67k | 0.49× | 0.58× | 1.17 | 13.7 / 44.4 / 36.0 | 16.2 / 16.0 / 15.7 |
| **geomean** | | **0.49×** | **0.61×** | **1.24** | | |

¹ Median of the per-rep ratios.

- Phase 1 cut user CPU per request by 19–31% and kernel CPU by 2–10%.
- Allocations per request: `return 200` 37.2 → 14.0 (milestone ≤ 16: met), proxy 1 KB 160.4 → 74.4 (≤ 70: not quite). An idle HTTP/1.1 connection holds 2.5 KB (was 11.4; C 0.5).
- What is left is user space: 2.1–4.0× C's user CPU per request (geomean 3.1×; `return 200` 5.9 µs against the ~4.5 projected in §4). Kernel CPU is 1.2–1.3× C's on HTTP/1.1, h3 and proxy, with the same syscalls per request as C (`analyze.py syscalls` at 2000 req/s: `h1-return` 2.90 against 2.95, `proxy-1k-keepalive` 6.74 against 6.82): the extra kernel time is not extra calls. HTTP/2 stays below C's kernel time because the driver batches frames (REPORT.md); that alone puts `h2c-1k` ahead of C.
- These 12 are the small-request scenarios, where the gap is widest, so 0.61× is not the milestones' 35-scenario geomean. The build gain measured on master (+14–29%, report §10) would put them at about 0.70–0.79×; to be measured.

## 2. Target and how progress is measured

**Target:**
- at least 0.95× C req/s and at most 1.05× C CPU per request on every saturation scenario of `bench.py`;
- the fixed-rate scenarios at equal CPU;
- per idle HTTP/1.1 connection at most 2× C (C: 0.5 KB; Rust today: 11.4 KB);
- TLS and h2 idle connections at most 1.2× C.

**Rules for every change:**
- nginx-tests keep passing the same 455 files as today: `scripts/run-tests.sh`. The 15 `mail_*.t` failures are the unported mail module.
- `cargo test --workspace` passes.
- The crates remain `#![forbid(unsafe_code)]`; anything that really needs `unsafe` goes into `ngx-sys` as a small safe function.

**Leading indicators**, cheaper than full runs and recorded per change in a budget table:
- allocations per request (`analyze.py` / `tools/mcount`);
- syscalls per request (`perf stat` on the `raw_syscalls` tracepoints);
- user µs per request.

**Comparing two builds:** run them alternating with at least 5 reps each and compare per-rep ratios. The machine can drift ±10–20% between reps (§1.3), so separate runs of each build mislead.

**Cadence:**
- `bench.py --only h1-return,h1-static-1k,tls-h1-1k,h2-tls-1k,proxy-1k-keepalive,h3-1k` (about 20 minutes) after each merged step;
- the full 35-scenario run (about 2 hours) at the end of each phase;
- profiles from a frame-pointer build (`-C force-frame-pointers=yes`; perf 5.15 cannot unwind Rust's DWARF), as in the report.

**Prerequisite in a fresh container:**
`sudo apt-get install -y wrk nghttp2-client iperf3 libjemalloc2 libmimalloc2.0 linux-tools-generic`

## 3. Phase 0: one base branch, cheap wins (about 1 week)

**1. Merge perf-fixes into safe.**
- `git merge-tree` shows two conflicts: `upstream_rt.rs` and `upstream_keepalive.rs`, both the dup-based watchers that perf-fixes removes. Port its versions (4320200, 47f27f4) onto rustix.
- Check that the merged TLS read path keeps perf-fixes' `recv_drained`/`read_drained` in `ssl.rs` and `event_openssl.rs`. Without it HTTPS goes back to 9 syscalls per request.
- Rebuild under `forbid(unsafe_code)`.

**2. Remove the safe-branch hot-path costs:**
- **Descriptor table:**
  - make the table a thread-local `RefCell<Vec<Option<Rc<OwnedFd>>>>` (no process starts threads);
  - give `AsyncFd` the connection's own handle (`AsyncFd<fd::Fd>`) so `writev`/`sendfile`/`setsockopt` borrow it without a lookup;
  - make `os::close_fd` do a single lookup.
  - Saves 0.05–0.5 µs per request; as a side benefit, a late `AsyncFd` drop can no longer `EPOLL_CTL_DEL` a reused number.
- **UDP control messages:** stack buffers for `recvmsg`, and an `ngx_sys::os::sendmsg_udp` (source address and GSO) instead of nix's allocating `sendmsg`.
- **Zone mutex:** the cached pid instead of `getpid()` (`shmem/lock.rs`; −2 to −6 syscalls per request on limit_req, limit_conn and the cache).

**3. Build profile and allocator** (`Cargo.toml`, `crates/nginx/src/main.rs`):
- `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`; nothing relies on unwinding, and a panicking worker then exits like a crashed C worker.
- `#[global_allocator]`: mimalloc or jemalloc via the safe crates, chosen by measurement.
- Measured on master: +14 to +29% from LTO plus jemalloc (report §10).

**4. Re-baseline:** the full benchmark of the merged branch against C.

**Expected:** about 0.65–0.72× geomean. perf-fixes' +32–40% applies to the ~25 small-request scenarios, the build gain of +14–29% was measured on those too, and bulk/handshake scenarios gain little. `h1-return` is about 0.58×.

## 4. Phase 1: remove per-request allocations, copies and layers (3–4 weeks, six parallel workstreams)

Items are in each workstream's own order. Savings are per request; S/M/L is the effort.

### W1. Request lifecycle (`request_rt.rs`, `request.rs`, `request_headers.rs`)

| # | Change | Saving | Effort |
|---|---|---|---|
| 1 | Remove needless copies:<br>• borrow `hc.buffer` instead of copying it (`:768`);<br>• move lowcase instead of cloning it (`:714`);<br>• `TableElt::with_hash` takes owned Vecs;<br>• borrow header values in the handlers (`request_headers.rs:96,117,134`);<br>• create `r.variables` lazily;<br>• build the close-connection string only with debug on (`:260`). | −6 allocations (−3 per extra header line), 0.3 µs | S |
| 2 | Keepalive as C does it:<br>• drop the request *before* the keepalive wait (`connection_task` holds `r` across it, `:193–205`);<br>• no buffer while idle; take one from a per-worker pool when the socket is readable, `try_recv` straight into it, and return it on EAGAIN, as `ngx_http_keepalive_handler` / `ngx_pfree` do. | −2 zero-filled 1 KB allocations, 0.2 µs; idle connection 11.4 → ~3.5 KB | S/M |
| 3 | `r.ctx` as a small inline map (`SmallVec<[(u16, Rc<dyn Any>); 4]>` behind the existing accessors) | −1 slow-path 1.2 KB allocation, 0.1 µs | S |
| 4 | Shrink the connection-task future: box the cold awaits (special response, post_action, subrequests, discard body, TLS handshake, lingering close) | −1 to −1.5 KB per idle connection | S |
| 5 | O(1) reusable-connection queue: drop the `BTreeMap` plus SipHash `HashMap` per keepalive cycle in `set_reusable` (`connection.rs:576–600`); keep the connection's own `Weak` | 0.1 µs | S |

### W2. Filters, phases and the output path (`lib.rs`, `core_rt.rs`, `header_filter.rs`, `write_filter.rs`, `output.rs`)

| # | Change | Saving | Effort |
|---|---|---|---|
| 1 | **Synchronous-unless-waiting filter chains.** `enum Step { Ready(i64), Pending(BoxFut) }`, which implements `Future` and is Unpin, so no `unsafe`. Header filters and the chunked/trailers/range/copy-short-path/write body filters become plain functions that call `next`. The write filter makes one non-blocking attempt and returns `Pending`, with today's loop, only when the socket is full. Filters that really wait (postpone with subrequests, ssi, sub, gzip, gunzip, charset, addition, slice) stay async and are boxed only while active. The ~36 callers of `send_header`/`output_filter` are unchanged because they await a `Step`. | 3, 4 and 6 boxes and their poll layers on return/static/proxy, about 0.4–0.8 µs; 4 fewer syscalls per blocked write (TestReading without `dup`) | M (~700 LOC) |
| 2 | **Phase engine as a synchronous loop.** Handlers return a `Step`; the checkers process results synchronously; only real waits are awaited (auth subrequests, limit_req delay, body reads, content handlers). Then make the `return` and static handlers synchronous-first. | 0.1–0.65 µs | S–M |
| 3 | **Response header in one buffer sized up front**, as `ngx_http_header_filter` does. Integer, hex and HTTP-time writers instead of `format!`/Strings for status, Content-Length, Last-Modified, ETag and Keep-Alive. Shared `Rc<[u8]>` Content-Type. Static keys for generated headers. | −1 allocation on return, −6 to −10 on static, 0.1–0.6 µs | S–M |
| 4 | `writev` from a stack `[IoSlice; 64]` (`output.rs:54`, `connection.rs:1183`); a `Chain` holding two buffers inline; `BufData::Static` for constant bytes | −2 allocations per write, −3 per response, 0.2–0.35 µs | S/M |
| 5 | `return`/`send_response` without copies (`script.rs:131`, `core_rt.rs:722`, `rewrite.rs:1028`) | −3 allocations, 0.15 µs | S |
| 6 | Copy-filter buffers reused from a free list as in C (today a zero-filled `vec![0; n]` per read, `copy_filter.rs:368/378`) | ~1 µs per 32 KB of in-memory output (TLS without kTLS, gzip, sub, ssi, h2/h3 bodies) | M |
| 7 | Internal redirects and named locations as a loop instead of recursion; `if` blocks flattened into one code list | −2 boxes per redirect, −1 per taken `if` | M |

### W3. Config, variables, regex, logging (`variables.rs`, `script.rs`, `regex.rs`, `log.rs`, `conf.rs`)

| # | Change | Saving | Effort |
|---|---|---|---|
| 1 | **Variable values as cheap shared bytes:** `VarBytes` with `Empty`, `Static`, `Inline([u8; 22])` and `Shared(Rc<[u8]>)` variants, 24 bytes like a Vec. Cache hits return a refcount bump instead of a Vec clone. Header and prefix variables borrow; the variable table is cached on the request. | −15 to −20 allocations on regex-rewrite, −10 to −16 on fastcgi, −6 with access_log | M (~500 LOC, mechanical) |
| 2 | **Regex without per-call allocation:** reuse `CaptureLocations` (taken and put back from a `RefCell`); write captures into reused per-request storage; borrow the subject instead of cloning it (`rewrite.rs:1120`, `core_rt.rs:356–364`) | −5 allocations per match, −2 per miss; −12 on regex-rewrite | S–M |
| 3 | **Complex values and config without per-request clones.** Constants return their stored bytes; a single-variable value returns that variable. `add_header` lists become `Rc<[HeaderVal]>`; `return` borrows its value; the log module's `logs` becomes `Rc<[_]>`. | −20 to −25 allocations on regex-rewrite, −4 with add_header | M |
| 4 | **Access log formatted straight into its buffer**, with integer writers and the time read once. Output must stay byte-identical. | −10 to −12 allocations and 1.5–2.5 µs per logged request | S–M |
| 5 | **Typed config access:** cache `CoreMainConf`/`clcf`/`cscf` on the request; a borrow-based `with_loc_conf` for idle checks; no `Rc` clone plus downcast per lookup | 0.15–0.4 µs | M |
| 6 | limit_req and limit_conn: no downcasts or `Rc` clones per request; the binary-address key inline | −4 allocations, 0.2–0.3 µs | S |
| 7 | `map` on `HashCombined`, as C uses `ngx_hash_find_combined` (today a linear scan; no effect on the benchmark) | O(1) big maps | M |

### W4. Event loop quick wins (`connection.rs`, `event.rs`, `times.rs`)

| # | Change | Saving | Effort |
|---|---|---|---|
| 1 | Don't wake the worker cycle on every `Connection` drop; only while exiting, as C checks `ngx_exiting` once per iteration | 0.3–0.5 µs per closed connection or h3 stream | S |
| 2 | `read_ready()` via `try_io` instead of a `recv(MSG_PEEK)`, which is exactly `c->read->ready` | −1 syscall per non-keepalive request | S |
| 3 | Clear write readiness after a short `writev`/`send` (`ngx_writev_chain` sets `wev->ready = 0`) | −1 EAGAIN per partial write | S |
| 4 | **Persistent per-connection timers.**<br>• One pinned `Sleep` per connection task, `reset()`; resetting to a later deadline is lock-free in tokio.<br>• A close-waker slot instead of the two per-request `Notified`s.<br>• The send timer only after the first `Pending`, which is also what C does.<br>• Same pattern in the upstream, h2 and QUIC drivers, behind an nginx-shaped `EventTimer` API (add/del with `NGX_TIMER_LAZY_DELAY`) that Phase 2's runtime reuses. | h1 0.3–0.4 µs, proxy ~1 µs, h2/h3 0.5–1 µs | M (~350 LOC) |

### W5. Proxy and upstream (`upstream_rt.rs`, `proxy.rs`, `event_pipe.rs`, `upstream_keepalive.rs`; peers in the safe tree)

| # | Change | Saving | Effort |
|---|---|---|---|
| 1 | **Per-request clones in setup and send:**<br>• `ProxyVars` as `Rc`;<br>• schema and URI shared;<br>• `create_request` computes the length first, as `ngx_http_proxy_create_request` does;<br>• send from a cursor over `u.request_bufs` instead of cloning them, rewound for the next upstream as C rewinds `buf->pos`;<br>• link the request body instead of copying it;<br>• `EventPipe` as one Vec of structs. | −25 allocations, 1.5–2 µs; POST-10k −20 KB memcpy, another 2–3 µs | S–M |
| 2 | Interim step of the header redesign: `with_hash` takes owned Vecs | −16 allocations | S |
| 3 | **Peer selection:** an inline `tried` bitmap for up to 64 peers (C does exactly this); per-peer cached `SockAddr` and name, invalidated by the zone's config counter; no `UpstreamState` clones | −8 allocations, 0.5–0.7 µs | S–M |
| 4 | Cache hit: move `c.buf` into `u->buffer` instead of copying it, as C does `u->buffer = *c->buf` | −6 allocations, −8 KB memcpy | S |
| 5 | Keepalive cache: one reaper task per pool instead of a spawned task per returned connection | ~1–1.5 µs | M |
| 6 | One timer and one client-close watch per phase instead of per await (with W4.4) | 0.5–1 µs | M |
| 7 | Event pipe: read straight into raw buffers that are zeroed once; `readv` across all free raw buffers, as `ngx_event_pipe_read_upstream` does | proxy-100k −15 to −25 of 222 µs; proxy-1m about 10× that | M |
| 8 | Restore `ngx_http_upstream_test_connect`'s `getsockopt(SO_ERROR)` on cached connections | fidelity fix, not speed (Rust currently skips it) | S |

### W6. HTTP/2, HTTP/3, TLS (`v2/`, `v3/`, `quic/`, `event_openssl.rs`)

| # | Change | Saving | Effort |
|---|---|---|---|
| 1 | **HPACK without copies:** decoding fills caller buffers; Huffman-encode into one scratch buffer per header block | −29 allocations, ~1.8 µs (~8% of h2) | S |
| 2 | **QPACK / HTTP/3 headers in place:** no per-field-line clone of the 1 KB header buffer; static-table lookups as `&'static` slices | −50 allocations, ~3.3 µs on h3-1k | S–M |
| 3 | **h2 framing:** one buffer per frame (header reserved, payload written behind it); recycled frame buffers (`free_frames`); `last_out` as a `VecDeque` | −8 allocations, 0.6–1.5 µs | S–M |
| 4 | **QUIC packet buffers like C's static arrays:** a thread-local scratch set; inline `Copy` connection IDs; lookups by slice | h3-1k ~1.3 µs; h3-100k ~50 µs (−700 to −900 allocations) | M |
| 5 | QUIC frame and buffer free lists (C's `free_frames`/`free_bufs`, blocks never zeroed) | h3-1k 0.8 µs; h3-100k ~20 µs | M |
| 6 | TLS record buffer from a per-worker pool (today 16 KB zero-filled per keepalive request, `event_openssl.rs:2378`); SSL chain list on the stack | 0.7–1 µs on tls-h1-1k | S |

### Expected after Phase 1
- `return 200` at ~10–16 allocations (from 37); user CPU ~7.9 → ~4.5 µs before the build gains.
- Proxy at ~60–70 allocations (from 159).
- Per-request savings: h2 −3.5 µs, h3 −7 µs.
- Kernel time should drop with the smaller footprint; to be measured.
- **Projected:** `h1-return` ~0.65×, `h1-static-1k` ~0.7×; geomean about 0.72–0.8×.
- How the projection is made: the item savings are added up, then the build gain is applied. That is likely conservative, because fewer allocations also mean fewer cache misses, less future memmove and less refcount traffic, which the per-item estimates do not count.

## 5. Phase 2: structural changes (6–10 weeks)

The reviews agree that Phase 1 alone leaves `return 200` near 0.65×: user ~4 µs against C's 1.6, on top of kernel ~8 against 6.4. Closing more of the small-request gap needs the following.

**2a. Zero-copy request and response headers** (W1/W5 follow-up; M–L, ~1,200 LOC)
- The header buffer becomes a `BytesMut`.
- Each parsed request line and header line is frozen, with:
  - `request_line`, `uri`, `args`, `exten` and host as `Bytes` slices;
  - `TableElt { key: Bytes, value: Bytes, lowcase_key }`;
  - lowcase keys for known headers from the hash table's static names;
  - static keys for response headers.
- `large_client_header_buffers` keeps parsed lines alive and copies only the incomplete line, as C keeps `hc->busy`. Pipelined requests continue in the same buffer, as C does; today the port compacts.
- The proxy, FastCGI, SCGI, uwsgi and grpc parsers slice `u->buffer` the same way, and `push_copy` shares bytes. That alone is about −53 allocations per proxied request.
- `$uri`, `$args`, `$http_*` and captures become refcount bumps (`VarBytes` gets a `Bytes` variant).
- ~229 field accesses; most compile unchanged through `Deref<[u8]>`.
- Fidelity fix to make on the way: re-read `cscf` per header line as C does, so that after a Host header switches server, the new server's header settings apply.

**2b. Own single-threaded runtime in ngx-core** (L, ~1,800 LOC). It replaces tokio's reactor, timer wheel and executor; `tokio::sync` and `select!` stay.
- **Reactor:** a rustix epoll reactor with nginx's model:
  - edge-triggered, registered once, no `EPOLL_CTL_DEL` (close does it);
  - `ready`/`available`/`pending_eof` flags;
  - listen sockets level-triggered with `EPOLLEXCLUSIVE` natively. This deletes the `/proc/self/fdinfo` plus `dup` workaround in `listen_event.rs`.
- **Timers:** an rbtree/`BTreeMap` timer tree with `ngx_event_add_timer` semantics, expired after events, plus posted and next queues.
- **Time:** `ngx_time_update` once per loop iteration, not a clock read per access.
- **Executor:** wakers from `Waker::from(Arc<impl Wake>)`, so no `unsafe`.
- **Migration:**
  - First add `ngx_core::rt` as a pure re-export of tokio and move every call site to it, with tests green: 73 `tokio::time` sites, 24 spawns, 10 `yield_now`, 23 `AsyncFd` sites.
  - Then swap the implementation and A/B it against tokio.
- **Saves** about 0.8 µs per request on HTTP/1 and 2.5–3 µs on proxy/gRPC/h3, plus one syscall per closed connection.

**2c. Request objects reused:**
- `Request { connection, http_connection, log_ctx, st: Option<Box<RequestState>> }`;
- `Drop` resets the state with an exhaustive struct literal and returns it to a bounded per-worker pool;
- the same mechanism covers subrequests and h2/h3 streams;
- reuses the 2.6 KB slow-path block and the Vec capacities between requests.

**2d. HTTP/2 and HTTP/3 streams without a tokio task each:**
- an ngx-core `SubTasks` pool (slots `Pin<Box<Option<F>>>` reused through `Pin::set`, all safe);
- the connection driver polls ready streams inline, as C runs the request inline;
- fake connections and logs are reused, as `ngx_http_v2_close_stream` does.
- Saves ~1 µs per stream.

**2e. Shared buffers in chains** (`BufData` with an `Rc<Vec<u8>>` variant), so event-pipe shadow buffers, chunked framing and FastCGI records stop copying, as C's shadow buffers do.

**Projected after Phase 2** (same additive method, so likely conservative):

| | Projection |
|---|---|
| h1 | 0.75–0.85× |
| TLS | 0.8–0.9× |
| h2 | 0.9–1.0× (Rust already batches writes better than C) |
| proxy | 0.65–0.75× |
| h3 | 0.6–0.7× |
| bulk transfers, handshakes, gzip | ~1.0× (they are already 0.8–1.03×) |
| geomean | 0.8–0.9× |

On the smallest requests (`return 200`, static 1 KB, proxy 1 KB) the remaining gap is the cost of running every request through futures, tasks and `Rc<RefCell>` objects at all. C runs such a request to completion inside one event handler. That is what Phase 3 addresses.

## 6. Phase 3: the last 10–20% on small requests

- **Synchronous fast path:** when the request header is complete in the buffer and the response fits the socket's send buffer, the read handler runs the phase engine, filters and write to completion without creating any per-request future. Only the first `Pending` (EAGAIN, a subrequest, a body read, an upstream) moves the request onto the async path. This is exactly C's model: event handlers run to completion and register for an event only on `NGX_AGAIN`. It builds on W2.1/W2.2 (`Step` chains) and 2b (the runtime).
- **Upstream as an explicit state machine** for the common keepalive/1 KB path, mirroring `ngx_http_upstream.c`'s handlers, instead of nested async layers.
- **PGO** (`cargo-pgo` with the benchmark as training load): typically +5–15%. Not used now because `llvm-tools` is not installed.
- **Per-request arena for request-scoped buffers**, if allocation still shows up in the profiles: an arena handed out as owned `Vec` slabs from a pool, not borrowed references, because arena references inside an `Rc<Request>` would be self-referential.

## 7. Not planned, and why

- **io_uring:** Docker's default seccomp profile blocks it, submitting buffers safely needs `unsafe`, and its completion model departs from nginx's readiness pattern.
- **`unsafe` arenas or pointer-based zero-copy:** the crates stay `forbid(unsafe_code)`. Every design above uses safe tools: `Bytes`, `Rc<[u8]>`, `Pin::set`, `Waker::from(Arc)`, `SmallVec`.
- **`target-cpu=native`:** 2% or less, and it costs portability.

## 8. Risks

**Faithfulness.**
- Every step keeps nginx-tests green and log lines byte-identical.
- The timer changes (W4.4, 2b) carry the most risk: the timeout tests and `worker_shutdown_timeout*` are their gates.
- Header and log formatting changes get golden-output unit tests comparing old and new bytes.

**Estimates.** They come from code reading and the report's costs. Each workstream measures its own steps and re-ranks; the leading indicators (allocations and syscalls per request) catch a step that does not deliver.

**The runtime swap (2b)** is the largest single change. The re-export shim lets it land in two reviewable halves, and tokio stays available as a fallback build until the A/B is conclusive.

## 9. Execution

| Week | Work |
|---|---|
| 1 | Phase 0 (one engineer or agent). Merged base branch, re-baseline. |
| 2–5 | Phase 1: W1–W6 in parallel, each in its own worktree, merged into an integration branch weekly. Order inside each: the S items first, then M. W2.1 (`Step` chains) and W4.4 (timers) gate Phase 2. |
| 6–15 | Phase 2: 2a and 2b in parallel (different files); 2c/2d/2e after 2b. Full benchmark at each merge. |
| then | Phase 3, chosen by the post-Phase-2 profiles. |

**Milestones:**

| End of | Geomean | Allocations per request (`return 200` / proxy 1 KB) |
|---|---|---|
| Phase 0 | 0.65× or more | |
| Phase 1 | 0.72× or more | ≤ 16 / ≤ 70 |
| Phase 2 | 0.8× or more | ≤ 8 / ≤ 30 |
| Phase 3 | parity target as in §2 | ≤ 4 / ≤ 15 |
