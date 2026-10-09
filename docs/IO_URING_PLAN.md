# Plan: socket reads and writes through io_uring

Date: 2026-10-09. Supersedes "io_uring: not planned" in `bench/PLAN.md` §7.

Goal: rnginx faster than C nginx. Today `return 200` costs rnginx 11.5 µs of
server CPU per request against C's 8.5 (0.74×): 3.95 µs user (C 1.57) and
7.55 µs kernel (C 6.95). `bench/PLAN.md` Phase 2/3 works on the user time.
This plan works on the kernel time, which C cannot go below with epoll: both
reads and writes of the hot sockets move to io_uring.

## 1. Where this comes from

### 1.1 Arc
github.com/shuakami/Arc claims 2.3× nginx on HTTP/1.1 proxying. It is a Rust
proxy with a hand-written state machine per worker thread, each with its own
io_uring ring (fixed buffers, fixed files, multishot accept), a 10 ms timeout
wheel, and byte pass-through proxying.
- The claim does not hold up. It was measured on 2 vCPUs (WSL2) against a
  Python `ThreadingHTTPServer` backend, with 1 Arc worker against nginx's
  `auto`, and wrk on the same CPUs.
- Its hot path still builds several Strings per request.
- Its upstream keepalive costs 3 epoll syscalls per request.
- It does not rebuild headers, so it does less work than nginx; a faithful
  port cannot take that.

What is worth taking is its I/O: reads and writes as ring operations, with
the read of the next request submitted only after the response went out.
Some of its other features are not needed here:
- fixed files only pay off in multi-threaded processes; rnginx workers have
  1 thread each (checked), so fdget() already takes its light path;
- SQPOLL burns a core;
- the GCRA limiter and pass-through change nginx semantics.

### 1.2 Measurements
`bench/uring-proto/` is one HTTP/1.1 server answering `return 200` with C
nginx's 160 bytes, built with each I/O model. It runs as 2 forked
single-threaded workers on CPUs 0-1, with wrk on the other CPUs, and the
cost is counted as the server CPUs' busy time per request
(`bench/uring-proto/README.md`).

| Server | req/s | µs/req |
|---|--:|--:|
| C nginx | 233.6k | 8.51 |
| rnginx master | 173.3k | 11.49 |
| tokio + epoll (rnginx's I/O model) | 291.4k | 6.84 |
| tokio + own ring: recv via ring, send() syscall | 348.5k | 5.72 |
| **tokio + own ring: recv and send via ring** | **389.8k** | **5.12** |
| tokio-uring 0.5 | 389.1k | 5.13 |
| raw io_uring loop, no tokio | 415.0k | 4.80 |

- Within rnginx's runtime structure, io_uring saves **1.7 µs per request
  (−25%)**. Of that, 0.6 µs comes from the writes.
- Client CPU per request drops too (8.1 → 6.7 µs): epoll's wakeup callback
  no longer runs for every arriving segment.
- The arming matters more than anything else. The recv of the next request
  should be submitted when the code next wants data, i.e. after the response
  went out, and not together with the send or multishot. Then the request is
  usually already there and the recv completes inline at submit:
  - raw loop, armed late: 4.71 µs (per-connection buffer) or 4.80 µs
    (provided buffer);
  - armed with the send: 6.17 and 6.25 µs;
  - multishot: 5.75 µs.
- Provided buffers cost nothing extra when armed late. Neither buffer counts
  nor setup flags (DEFER_TASKRUN, COOP_TASKRUN) matter at saturation.
- Syscalls are dear here: a null syscall costs 147 ns (eIBRS, BHI loop,
  VERW on return to user). This is a common cloud VM setup, and it is why
  the savings exceed the textbook ones.

### 1.3 tokio-uring: its architecture, not the crate
tokio-uring runs a ring inside a tokio current-thread runtime:
- the ring's fd is registered in tokio's reactor;
- operations are futures over a slab of lifecycles;
- an operation dropped in flight leaves its buffers with the driver until
  its completion arrives.

That is the model rnginx needs: tokio, the LocalSet, timers and `select!`
stay. We take the architecture, not the crate, for these reasons:
- **Not maintained.** The last release is 0.5.0 (May 2024), the last commit
  a clippy fix (July 2025), and 98 issues and PRs are open. It pins
  io-uring 0.6.
- **Submits only when the thread parks.** Its `on_thread_park` hook flushes,
  but tokio's busy path (`park_yield`, every 61 tasks) never runs that hook.
  With one task that stays runnable it served **0 requests** (tokio-epoll
  290k, our per-tick flush 392k, p99 0.74 ms).
- **Owns the runtime.** It builds the tokio runtime itself, and rnginx needs
  its own park/unpark hooks: the time update, signals, `events_park`.
- **No cancel on drop.** An abandoned read keeps the socket open until data
  arrives, so `keepalive_timeout` and `client_header_timeout` would not close
  anything.
- **Missing operations.** It has no readiness operation, no peek, and no
  provided-buffer recv (its pool is dead code), so every waiting read holds
  an owned buffer.

## 2. Design

### 2.1 Layers
- **`ngx_sys::uring`**, the only `unsafe`, with a sound safe API. The ring
  owns everything the kernel may touch until the completion of the
  operation that references it. This keeps SAFETY.md's rule that no raw
  pointer crosses the API.
  - Every push takes its payload by value:
    - a descriptor keeper `K: AsFd + 'static` (rnginx passes `fd::Fd`
      handles, which keep the number open);
    - send sources and receive targets as boxed objects;
    - nothing for polls and cancels.
  - The iovecs come from a boxed object through
    `fn iovecs<'a>(&'a self, out: &mut Vec<IoSlice<'a>>)` (`IoSliceMut`
    for receives), called once after boxing. Safe code can only lend memory
    that lives as long as the object; the object is not touched again until
    the completion returns it.
  - The provided-buffer rings belong to the `Ring`.
  - Built on the `io-uring` crate (0.7, maintained by tokio-rs).
- **`ngx_core::uring`**, the driver (safe). It holds the per-worker ring
  plus:
  - the waiting side: operation states and wakers;
  - futures for recv, send, poll and cancel;
  - the flush points;
  - the wakeup of a parked thread.
- **Connections in io_uring mode.** `Connection`'s I/O methods get an
  io_uring implementation behind the same signatures, so the ported code
  keeps nginx's structure.

### 2.2 The driver
- **Ring.** One per worker process, created when its event loop starts
  (`event.rs::run_event_loop`). Setup flags: `SINGLE_ISSUER`,
  `COOP_TASKRUN` and `TASKRUN_FLAG` (the flag lets a flush skip the enter
  when no work is pending; DEFER_TASKRUN measured the same, and is tried in
  Phase 5). The master, cache processes and helpers keep epoll only.
- **Operations.** A slab indexed by `user_data`, which packs index and
  generation as Arc packs connection keys, so a stale completion cannot
  reach a reused slot. States, as tokio-uring's lifecycle:
  - `Waiting(waker)`;
  - `Done(res, flags, payload)`;
  - `Ignored(payload)`: the future went away, and the completion frees the
    payload.
- **Flush:** submit what is queued, then reap completions and wake their
  tasks. It runs:
  - at the end of every LocalSet tick (`block_on_events`, next to the time
    update);
  - in `events_park` before the thread blocks;
  - whenever the SQ is full.

  A flush with nothing queued and no taskrun flag makes no syscall. Under
  load this is one `io_uring_enter` per tick of up to 61 tasks.
- **Wakeup while parked.** The ring's fd is registered once in tokio's
  reactor, and a driver task flushes when it becomes readable. An epoll_wait
  interrupted to run io_uring task work returns EINTR. That case is covered
  by the flush in `events_park`, and `events_unparked` must not take it for
  a signal (verify).
- **Cancel on drop.** A future dropped in flight (a timeout's `select!`, a
  closed request) pushes `ASYNC_CANCEL` for its `user_data` and leaves its
  payload in `Ignored`.
- **Close.** Each operation holds an `fd::Fd` handle of its socket.
  `fd::close(n)` already closes only when the last handle drops, so:
  - the number cannot be reused while an operation that names it is queued;
  - the socket really closes once the cancelled operations complete, in the
    same flush.

  `Connection::close` cancels the connection's operations. It never waits.
- **Worker exit.** The driver cancels everything and reaps the completions
  (bounded wait) before dropping the ring and its buffers.

### 2.3 Reads
- **RECV with buffer select** from provided-buffer rings: 2 KB buffers for
  request heads and frames, 16 KB for bodies; sizes to be measured. An idle
  connection holds no buffer, as in C. The `len` of the operation caps the
  read.
- **Armed late, never multishot.** A RECV is submitted only when the code
  waits for data and nothing is stashed. That is the arming measured in
  §1.2, and it is what nginx's structure already does: try the read, then
  wait.
- **Stash.** A completion's bytes are copied into the caller's buffer at the
  next `try_recv`. A remainder moves to a pooled heap buffer, and the ring
  buffer is recycled at once, so ring buffers never stay held.
- **Readiness flags**, as `rev->ready`, `rev->pending_eof` and
  `rev->error`:
  - ready: data is stashed, or the last read filled its length;
  - pending EOF: a RECV returned 0;
  - error: from the completion's errno.

  Reads stay exact: a short read clears ready, and EOF and errors come back
  in the order C sees them.
- **Bulk exception, to evaluate.** When the last read filled its length,
  `try_recv` may call recv() directly, as C does with `rev->ready`: one
  syscall per 16 KB instead of a tick of latency.
- **Upstream and stream reads** go into their own buffers by moving them
  into the operation (READV into the event pipe's `RawBuf` Vecs, the stream
  proxy's buffer), with no copy. A busy upstream connection has no idle
  memory to save.

### 2.4 Writes
- **Completion is awaited.** A write is a SEND or SENDMSG operation. The
  caller gets the same byte count or errno the syscall would have given, one
  tick later. These stay exactly as in C:
  - `c->sent` and `$bytes_sent`;
  - partial writes and the rest of the chain;
  - `send_timeout`;
  - `limit_rate`;
  - errors logged with C's names and levels ("writev() failed",
    "sendfile() failed").

  Rejected: completing writes optimistically (write-behind). It would move
  `c->sent` ahead of the kernel, report errors after the request is logged,
  and change `send_timeout`.
- **Ownership.** The output chain's buffers (`BufData::Memory(Vec<u8>)`) go
  into the operation with the chain, and come back with the completion:
  - `update_sent(chain, n)` runs as today;
  - output queued meanwhile is appended behind what comes back;
  - small cold-path sends (100-continue and the like) copy into a pooled
    buffer.

  MSG_NOSIGNAL is set on every send.
- **One send in flight per connection.** That keeps the order without links.
  Synchronous syscalls on the socket, namely `sendfile`, TCP_CORK and
  TCP_NODELAY, and `shutdown`, run only when no send is queued or in flight
  on it (checked by debug assertions). File buffers keep a synchronous
  sendfile after the memory part's send completed. Phase 5 replaces it by a
  linked READ→SENDMSG for small files.
- **Write filter** (`write_filter.rs`): `iteration()` submits, and a new
  `Pass` result maps to `Resume::Send`. Timers and watches follow C's
  NGX_AGAIN rule:
  - an operation that completes in the flush that submitted it creates no
    `send_timeout` timer and no client watch;
  - one still in flight after that flush gets both.
- **Boxing.** Phase 1 boxes `write_loop` for every response (one allocation
  each). Phase 1b gives `Step` a variant holding the write continuation, so
  the common case allocates nothing.

### 2.5 Readiness without epoll
Sockets in io_uring mode are never registered in epoll, so `afd()` is not
called for them. The few waits that do not read become POLL_ADD operations:
- `writable()`: POLLOUT;
- `read_event()`, TestReading and ClientWatch: POLLIN|POLLRDHUP, then a
  peek, as now. The wait for the end of the stream becomes POLLRDHUP alone
  on the socket itself, replacing today's `dup()` and second registration;
- the keepalive cache's close handler (`poll_peek_close`):
  POLLIN|POLLRDHUP;
- the TLS handshake and non-kTLS TLS I/O (Phase 4): POLLIN/POLLOUT driving
  OpenSSL's retries (`drive_io`).

### 2.6 What stays on epoll
These stay on epoll, each until its phase:
- listening sockets (Phase 5);
- TLS connections (Phase 4);
- UDP and QUIC;
- pipes, eventfds and signals;
- the resolver;
- the control socket;
- mail.

Each connection gets its mode when accepted or connected. A plain HTTP/1
connection that becomes HTTP/2 or a WebSocket tunnel switches to epoll, with
nothing in flight and the stash handed over as preread, until its phase
converts that path.

### 2.7 Selection and fallback
- **Selection.** `use io_uring;` in `events {}`, nginx's event-method
  directive (today `set_use` accepts `epoll` only).
  `RNGINX_EVENTS=io_uring|epoll` overrides it, for nginx-tests and for
  bench.py, whose configuration C shares.
- **Probe** at worker start:
  - `io_uring_setup` succeeds;
  - IORING_REGISTER_PROBE reports RECV, SEND, SENDMSG, READV, POLL_ADD and
    ASYNC_CANCEL;
  - a provided-buffer ring registers (5.19+);
  - SINGLE_ISSUER is accepted (6.0+).
- **Fallback.** If the probe fails, the worker falls back to epoll and logs
  one notice with the reason. Typical reasons:
  - Docker's default seccomp profile;
  - `kernel.io_uring_disabled`;
  - an old kernel;
  - RLIMIT_MEMLOCK.

  The pinned memory is small (ring entries, not buffers), but it is
  accounted per user across workers.

### 2.8 Fidelity rules
Each of these is a test gate in its phase:
1. `rev->ready` and `wev->ready` keep C's rules: a short read clears read
   readiness, a partial write clears write readiness, and the next wait
   blocks.
2. `pending_eof` and errors reach the same handlers in the same order. A
   client closing during a blocked write is detected by the watch first, as
   epoll reports the read event first.
3. Timeouts keep closing on time: a timed-out operation is cancelled, and
   its socket closes in the same flush. This covers `client_header_timeout`,
   `client_body_timeout`, `send_timeout`, `keepalive_timeout`,
   `lingering_timeout`, `lingering_time`, `reset_timedout_connection` and
   the proxy timeouts.
4. `c->sent`, `$bytes_sent` and `$request_time` are counted at completion.
5. Error log lines keep C's syscall names, levels and contexts.
6. Pipelined data stays in the header buffer as in C. The stash holds only
   bytes not yet returned by a `try_recv`.
7. Lingering close keeps its order: `shutdown(SHUT_WR)` after the last send
   completed, then reads until the timeout.
8. Graceful shutdown (QUIT, `worker_shutdown_timeout`) closes idle
   connections and cancels their reads, and the worker exits once the ring
   is drained.

## 3. Phases
Each phase is on a branch, gated by nginx-tests with `RNGINX_EVENTS=io_uring`
(455 files, as with epoll), the epoll suite unchanged, and
`cargo test --workspace`.

| Phase | Scope | Main files | Size | Expected |
|---|---|---|---|---|
| 0 | `ngx_sys::uring`: ring, provided buffers, owned payloads, probe. `ngx_core::uring`: slab, futures, flush points, wakeup, cancel, exit. `use io_uring` and `RNGINX_EVENTS`. Unit tests. | ngx-sys `uring.rs`; ngx-core `uring.rs`, `event.rs`, `process.rs` | ~800 LOC, 3 days | no change with epoll |
| 1 | HTTP/1 plain client connections: header and body reads, discard body, lingering close; output chain writes; watches as POLL_ADD | `connection.rs`, `output.rs`, `write_filter.rs`, `request_rt.rs`, `request_body.rs`, `upstream_rt.rs` (ClientWatch) | ~900 LOC, 1 week | `h1-return` 11.5 → ~9.8 µs/req (0.74× → ~0.86× C); HTTP/1 small requests +12-17% |
| 1b | `Step` variant for the write continuation; timers only after the first flush | `lib.rs`, `write_filter.rs` | ~250 LOC, 2 days | −0.1-0.2 µs/req |
| 2 | HTTP/2 over plain TCP: the driver's reads from the stash, its writes as owned SENDs of `wbuf` | `v2/connection.rs` | ~300 LOC, 2 days | `h2c-1k` (already 1.46× C) |
| 3 | Upstreams over plain TCP (proxy, FastCGI, uwsgi, SCGI, gRPC, memcached): request sends, event pipe reads, header reads, keepalive cache watch, connect completion via POLLOUT (synchronous `connect()`, as C logs it). Stream TCP proxy relay. | `upstream_rt.rs`, `upstream.rs`, `upstream_keepalive.rs`, `event_pipe.rs`, `ngx-stream/proxy.rs` | ~1000 LOC, 1-1.5 weeks | `proxy-1k-keepalive` 30.8 → ~27.5 µs/req; `stream-tcp-proxy` |
| 4 | TLS: the handshake with POLL_ADD readiness. With kTLS (TX+RX), ring RECVMSG (record type cmsg) and SENDMSG on the socket. Without it, a memory BIO between OpenSSL and the ring, errno and error queue as C reports them. | `event_openssl.rs`, `ngx-sys/ssl.rs`, `ssl_module.rs`, `output.rs` | ~1200 LOC, 2 weeks | `tls-h1-1k`, `h2-tls-*`, `proxy-tls-terminate`, `stream-tls-terminate` |
| 5 | Multishot ACCEPT per worker (with `accept_mutex`, `multi_accept` and the worker_connections throttle). Small files as linked READ→SENDMSG. Close through the ring. DEFER_TASKRUN. io_uring as the default where the probe passes. | `event.rs`, `listen_event.rs`, `output.rs` | ~700 LOC, 1 week | `h1-conn-close`, `proxy-1k-no-keepalive`, `h1-static-1k` |

io_uring alone does not make rnginx faster than C on small requests: after
Phase 1, `return 200` is projected at ~9.8 µs (C 8.5). But it takes
rnginx's kernel time below C's (~6.0 against 6.95 µs). With `bench/PLAN.md`
Phase 2/3 bringing user time from 3.95 to ~2 µs, `return 200` lands at
~8.0 µs, about 1.06× C; proxy and TLS gain more, since each request has two
sockets or more bytes per syscall. `bench/PLAN.md` 2b (own runtime) loses
its reactor half once the hot sockets leave epoll; its timer and executor
items stay.

## 4. Testing
- **Driver unit tests**, skipped where io_uring is unavailable:
  - a drop in flight;
  - cancel, then close: the socket closes, and the number is not reused
    while queued;
  - ENOBUFS, then retry;
  - short reads and partial sends;
  - EOF and errors;
  - flush with nothing queued (no syscall);
  - wakeup while parked;
  - exit with operations in flight.
- **nginx-tests** under both modes for every phase. Watch in particular:
  - `http_keepalive*`, `body*`, `http_request_body*`, `lingering*`,
    `limit_rate*`, `proxy_ignore_client_abort*`, `http_disable_symlinks*`;
  - `h2_*` (Phase 2);
  - `proxy*`, `fastcgi*`, `uwsgi*`, `grpc*`, `stream_proxy*` (Phase 3);
  - `ssl*`, `h2_ssl*`, `stream_ssl*` (Phase 4).
- **Stress.** wrk with connection churn and abrupt resets mid-response, idle
  floods, slow readers that fill the send buffer. After each run:
  - the worker's open descriptors return to the baseline (`/proc/PID/fd`);
  - stub_status reading, writing and waiting return to 0;
  - QUIT completes with operations in flight.

## 5. Measuring
- **Benchmarks.** `bench.py` gets a `rust-uring` server: the same binary
  with `ENVS = {RNGINX_EVENTS: io_uring}`, alternated with `rust` and `c`,
  5 reps (`bench/PLAN.md` §2).
- **After each phase,** the subset of `bench/PLAN.md` §2 plus:
  - `idle-10k-h1`: io_uring mode must not hold more per idle connection
    than epoll mode;
  - the fixed-rate scenarios: at 10k req/s, wakeups dominate; CPU must not
    exceed epoll mode's by more than 5%, and p99 is watched.
- **Leading indicators:**
  - server CPU µs/req (per-CPU, as `bench/uring-proto/ab.py`);
  - syscalls per request;
  - enters per request and completions per enter;
  - SQ-full, ENOBUFS and CQ overflow counts (debug counters, logged at
    worker exit).

## 6. Risks
- **Semantics.** Timeouts, close timing and error attribution are where a
  completion model can drift. Mitigations: the rules of §2.8, the full suite
  under both modes, and write completions awaited, never assumed.
- **TLS (Phase 4)** is the riskiest. kTLS comes first; the memory BIO
  changes how OpenSSL sees errors, and must reproduce C's log lines.
- **The wakeup path.** EINTR from io_uring task work while tokio sleeps in
  epoll_wait must not look like a signal to `events_unparked`.
  DEFER_TASKRUN avoids the case if it shows up.
- **Latency.** Each write completes a tick later. Under load, ticks batch;
  at low load, the park flush submits at once. Fixed-rate p99 is the gate.
- **Availability.** Containers and older kernels are handled by the probe
  and the epoll fallback. nginx-tests and the benchmarks run on this VM's
  7.0 kernel.
