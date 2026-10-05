# Benchmark harness: nginx C vs rnginx

Throughput, latency, CPU per request and memory of C nginx against Rust builds. C nginx is built at -O2 with the Rust binary's module list. The harness also has the measurements that explain the differences: heap allocations per request, syscalls, idle memory per connection, and profiles.

- `REPORT.md`: the analysis of master `7f01d41` against C (2026-10-01). It names the two earlier reports, kept here.
- `PLAN.md`: the plan to reach parity with C. §1 has the results so far.

## Layout

| | |
|---|---|
| `bench.py` | the scenarios (`--list`) and the runner. Each run: a fresh nginx, a response check, warm-up, load, CPU and memory sampling. One JSONL record per run |
| `report.py`, `compare.py` | Markdown tables from results; before/after tables |
| `analyze.py` | what explains a difference: `allocs`, `allocsites`, `idle`, `syscalls`, `sysstat`, `profile` |
| `extra.py`, `churn.py`, `verify_fixes.py`, `profile2.py` | the follow-up experiments of the reports |
| `smoke.py`, `smoke2.py`, `repro-stream-spin.py` | quick checks from writing the harness, and a bug reproducer |
| `tools/` | a Go FastCGI backend, a Go idle-connection client, and `mcount`, an LD_PRELOAD malloc counter |
| `setup.sh`, `build-c.sh` | make what is not in git (below) |

**Not in git** (`.gitignore`). These are made by `setup.sh` or written by the runs:
- `bin/`: nginx builds, oha, the tools;
- `src/`: the copy of the C source, the oha builds;
- `certs/`, `www/`, `www-extra/`;
- `run/`: server prefixes;
- `logs/`, `results/`;
- `local/`: machine-local leftovers.

The data lives next to the scripts, so run the harness from the main checkout; a worktree's `bench/` has the scripts only. Don't `git clean -x` the checkout: it deletes all of the above.

## Setup

The harness expects a machine with 8 dedicated CPUs (0–7). The nginx under test is pinned to CPUs 0–1, the backends to 2–3, the load generators to 4–7.

Packages (Ubuntu 22.04):
- `wrk nghttp2-client iperf3 strace linux-tools-generic libjemalloc2 libmimalloc2.0`;
- Go, on the PATH or in `/usr/local/go`;
- what C nginx needs to build: `build-essential libpcre2-dev libssl-dev zlib1g-dev libxslt1-dev libgd-dev libgeoip-dev libperl-dev`.

Then run `./setup.sh`. It makes, skipping each step whose output exists:
- the certificates and the files served;
- the tools;
- oha 1.16, in two builds, one with HTTP/3;
- `bin/nginx-rust`, from `cargo build --release`;
- `bin/nginx-c-O2`, with `build-c.sh`.

## Running

```sh
python3 bench.py --list
python3 bench.py --only h1-return,proxy-1k-keepalive --servers c,rust --reps 3 --out results/x.jsonl
python3 report.py results/x.jsonl
python3 analyze.py allocs h1-return,h2-tls-1k c,rust      # -> results/analysis/allocs-*.json
```

A build under test is a `BINS` entry in `bench.py`, as a copy in `bin/`. Any other path works with `NGX_BENCH_BIN=/path/to/nginx python3 bench.py ... --servers custom`.

**Rules that keep the numbers meaningful:**
- **One measurement at a time.** The harness uses fixed ports and pinned CPUs. When others share the machine, run under `flock /tmp/nginx-bench.lock`, and not while something compiles.
- **Compare builds within one run.** The machine drifts by 10–20% between reps on some days. Pass both builds in one run (`--servers a,b`): the servers alternate within each rep. Take the median of the per-rep ratios, from 3 reps or more.
- **Check allocations first.** Allocations per request (`analyze.py allocs`) are deterministic, so they are the first check of any change. They count calls to glibc's malloc through `bin/libmcount.so`, so they need a binary that allocates through glibc: `cargo build --release --no-default-features`, as the default build links jemalloc. `analyze.py` refuses other binaries for `allocs`, `allocsites` and `idle`.
