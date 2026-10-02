# Phase 1 of the performance plan: rules for the workstream agents

Read this fully, then:
- bench/PLAN.md: the plan, especially §1–§4. Your workstream's items are in §4.
- bench/REPORT.md: the benchmark analysis.
- CONVENTIONS.md and docs/SAFETY.md.

You are one of six agents. Each works in its own git worktree (your cwd), on a branch made from master. The orchestrator merges the branches.

## Goal
Cut what each request costs in user space: heap allocations, copies, boxed futures and poll layers, and needless clones and clock reads. Behaviour must stay as it is.

**Behaviour that must not change:**
- the same responses, byte for byte;
- the same log lines;
- the same timeouts and the same order of observable syscalls.

**Hard constraints:**
- nginx-tests keep passing the same files. Baseline: 455 pass; the 15 `mail_*.t` failures are expected (no mail module).
- `cargo test --workspace` passes.
- The crates stay `#![forbid(unsafe_code)]`. Anything that really needs `unsafe` goes into crates/ngx-sys as a small safe function with a `// SAFETY:` comment (docs/SAFETY.md).
- Don't "improve" nginx behaviour. The C source is in /home/ubuntu/rnginx/nginx-c/src.

## Measuring

**Allocations per request.** The main indicator: deterministic, and cheap to measure.
- Build release: `cargo build --release`.
- Then run, from /home/ubuntu/rnginx/bench (the main checkout: a worktree's bench/ has no binaries or data):
  `NGX_BENCH_BIN=$PWD_OF_YOUR_WORKTREE/target/release/nginx flock /tmp/nginx-bench.lock python3 analyze.py allocs <scenarios> custom`
  - Scenarios are names from `python3 bench.py --list`, comma-separated.
  - `flock` is required: the harness uses fixed ports and pinned CPUs, and all agents share them.
- Call sites of the remaining allocations: `analyze.py allocsites` (same form, also under flock).

**Throughput.** Do NOT run throughput benchmarks (`bench.py`): with six agents compiling, the numbers are meaningless. The orchestrator measures throughput at integration.

**Baseline on master** (`analyze.py allocs`, master 8dcf1ef). C does 3–22 per request.

| Scenario | allocs/req | Scenario | allocs/req |
|---|--:|---|--:|
| h1-return | 37.2 | h2-tls-1k | 119.1 |
| h1-static-1k | 66.2 | h2c-1k | 112.0 |
| h1-regex-rewrite | 95.2 | h3-1k | 192.5 |
| h1-access-log | 77.2 | proxy-1k-keepalive | 160.4 |
| h1-limit-req | 71.2 | proxy-post-10k | 160.3 |
| tls-h1-1k | 80.1 | proxy-cache-hit | 154.4 |
| fastcgi-1k | 157.3 | grpc-pass | 214.3 |
| stream-tcp-proxy | 8.0 | | |

## File ownership

Edit only your files, plus the exceptions listed for you. A file listed for another workstream belongs to it. A file nobody owns may be edited minimally when your change needs it; say so in your report.

**Don't change shared APIs** (signatures of public functions or types used outside your files). If needed, add a new function or variant next to the old one and convert only your own call sites; the rest converts after the merge. Don't reformat, and don't rename or remove items others call.

| | Workstream | Files |
|---|---|---|
| **W1** | request lifecycle | ngx-http `request_rt.rs`, `request.rs`, `request_headers.rs`, `parse.rs` |
| **W2** | filters, phases, output | ngx-http `lib.rs` (filter and phase sections), `core_rt.rs`, `core.rs` (phase-handler registration), `header_filter.rs`, `write_filter.rs`, `output.rs`, `copy_filter.rs`, `chunked_filter.rs`, `range_filter.rs`, `not_modified_filter.rs`, `headers_filter.rs`, `postpone_filter.rs`, `static_module.rs`, `special_response.rs`, `index.rs`, `access.rs`, `auth_basic.rs`, `realip.rs`, `try_files.rs`, the body-filter modules (`addition_filter.rs`, `charset_filter.rs`, `gzip_filter.rs`, `gunzip.rs`, `ssi_filter.rs`, `sub_filter.rs`, `slice.rs`, `userid.rs`) |
| **W3** | config, variables, regex, logging | ngx-http `variables.rs`, `script.rs`, `rewrite.rs`, `map.rs`, `log.rs`, `limit_req.rs`, `limit_conn.rs`, `split_clients.rs`; ngx-core `regex.rs`, `shmem/lock.rs`; ngx-stream `variables.rs`, `map.rs`, `limit_conn.rs` |
| **W4** | event loop and I/O | ngx-core `connection.rs`, `event.rs`, `listen_event.rs`, `times.rs`, `fd.rs`, `os.rs`; in ngx-http `request_rt.rs`, only the functions `read_ready` / `socket_has_data` (the MSG_PEEK test) |
| **W5** | proxy and upstream | ngx-http `upstream_rt.rs`, `upstream.rs`, `proxy.rs`, `event_pipe.rs`, `upstream_keepalive.rs`, `upstream_round_robin.rs`, `upstream_cache.rs`, `file_cache.rs`, `fastcgi.rs`, `scgi.rs`, `uwsgi.rs`, `grpc.rs`, `upstream_h2.rs`, `proxy_v2.rs`; ngx-stream `upstream_round_robin.rs` |
| **W6** | HTTP/2, HTTP/3, QUIC, TLS | ngx-http `v2/*`, `v3/*`; ngx-core `quic/*`, `event_openssl.rs`, `ssl.rs`, `event_udp.rs`; `crates/ngx-sys/src/os.rs` (append only) |

## Work style
- Do the items of your workstream (given in your prompt) in order, one commit per item, each building and passing its tests.
- After each item:
  - measure allocs/req on the scenarios it should change;
  - run the nginx-tests that cover it: `cd /home/ubuntu/rnginx/nginx-tests && env TMPDIR=/tmp/<you> TEST_NGINX_BINARY=<worktree>/target/release/nginx prove <files>`.
- At the end, run the whole suite once with `-j4` and compare with /home/ubuntu/rnginx-unsafe-work/base-pass.txt:
  - `/home/ubuntu/rnginx-unsafe-work/suite.sh <binary> <your-name> 4` prints the regressions.
  - It runs under `env -i`; give it your binary's path.
  - It uses /tmp/<name>.
- A step that doesn't deliver what you expected: measure why, then fix it or drop it, and say so in your report.
- Large budget, no time limit: do the items, not a plan.

## Report (your final message)
1. Per item: done or not; commit; allocs/req before → after on the measured scenarios.
2. Tests: the files you ran; the full-suite result.
3. Changes outside your files, and any shared API you added.
4. Behaviour differences, if any, and why.
5. What you'd do next.
