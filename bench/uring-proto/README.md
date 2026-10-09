# io_uring vs epoll: the I/O model alone

The prototype behind `docs/IO_URING_PLAN.md`: one HTTP/1.1 server answering
`return 200` with C nginx's 160 response bytes, built several ways, so that
the I/O model is the only difference. It is not part of the workspace.

- `src/main.rs`: worker processes forked as nginx's (one per CPU, single
  threaded, `SO_REUSEPORT` listeners), with a raw event loop: `epoll`
  (edge-triggered, one recv per event, a short read means drained, as nginx),
  `uring` (multishot recv from a provided-buffer ring), `uring-arc` (recv
  into a per-connection buffer, armed again once the send completed, as
  github.com/shuakami/Arc does).
- `src/tok.rs`: the same inside tokio, shaped like rnginx (current-thread
  runtime, LocalSet, a task per connection): `tokio-epoll` (AsyncFd
  readiness, readiness cleared after a short read, sync-first send), the
  `tokio-uring` crate as designed, and `tokio-ring`, a minimal ring driver
  of our own flushed at the end of every LocalSet tick (the design of the
  plan).
- `ab.py`: runs C nginx (`../bin/nginx-c-O2`), rnginx
  (`../../target/release/nginx`) and prototype modes alternately on CPUs
  0-1 with wrk on CPUs 4-7 (or `CLIENT_CPUS`), and reports the server
  CPUs' busy time per request from `/proc/stat`, which also counts work the
  kernel does outside the server processes.

```
cargo build --release
CLIENT_CPUS=2-7 CLIENT_THREADS=6 CLIENT_LIST=2,3,4,5,6,7 \
    python3 ab.py 3 8 c rust proto-epoll proto-tokio-epoll "proto-tokio-ring@NBUF=256"
```

`proto-MODE@K=V,...` passes knobs (see `src/main.rs`).

## Results (2026-10-09, `results/`)

Xeon Platinum 8375C, 8 dedicated CPUs, kernel 7.0.0-1014-aws, wrk -t6 -c256.
A null syscall costs 147 ns here (eIBRS, BHI loop, VERW on return).

| Server | req/s | server CPU µs/req |
|---|--:|--:|
| C nginx 1.31.7 | 233.6k | 8.51 |
| rnginx master `869dd8a` | 173.3k | 11.49 |
| epoll, raw loop | 301.5k | 6.60 |
| io_uring, raw loop, Arc's arming | 415.0k | 4.80 |
| tokio + epoll (rnginx's model) | 291.4k | 6.84 |
| tokio + own ring, recv via ring, send() syscall | 348.5k | 5.72 |
| **tokio + own ring, recv and send via ring** | **389.8k** | **5.12** |
| tokio + own ring, DEFER_TASKRUN | 382.6k | 5.21 |
| tokio-uring 0.5 | 389.1k | 5.13 |

When the recv is armed matters more than how (raw loop, µs/req): armed when
the code next wants data, after the response went out, it usually finds the
request there and completes inline: 4.71 with a per-connection buffer, 4.80
with a provided buffer. Armed together with the send it costs 6.17 and 6.25;
multishot (always armed) 5.75. Buffer counts and setup flags change nothing
at saturation.

With one task that stays runnable (`SPIN=1`, a response produced in chunks
with yields): tokio-epoll 290k req/s (p99 0.97 ms), tokio-ring 392k (p99
0.74 ms), tokio-uring **0**: it submits only when the thread parks, which a
busy runtime never does.
