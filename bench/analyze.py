#!/usr/bin/env python3
"""Measurements that explain the C vs Rust differences.

    analyze.py allocs   SCENARIOS SERVERS   heap allocations per request (LD_PRELOAD bin/libmcount.so)
    analyze.py allocsites SCENARIOS SERVERS where the allocations of a request come from (sampled stacks)
    analyze.py idle     SCENARIOS SERVERS   heap blocks/bytes held per idle connection (idle-10k-* scenarios)
    analyze.py syscalls SCENARIOS SERVERS   syscalls per request (strace -f -c, nginx run as its child)
    analyze.py sysstat  SCENARIOS SERVERS   syscalls per request at full load (perf stat, syscall tracepoints)
    analyze.py profile  SCENARIOS SERVERS   perf profile with call graphs (frame-pointer builds),
                                            CPU time broken down into components

SCENARIOS and SERVERS are comma-separated (scenario names of bench.py, keys of
bench.BINS). Results go to results/analysis/<what>.json and are printed.
"""
import collections
import glob
import json
import os
import re
import signal
import struct
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bench import (B, BINS, CLIENT_CPUS, SCENARIOS, SERVER_CONF, SERVER_CPUS, Backends, Nginx,  # noqa: E402
                   client_run, h2load_cmd, oha_cmd, parse_h2load, parse_oha, parse_wrk, port_open, render,
                   reset_prefix, run_load, wait_ports_free, wrk_cmd, POST_LUA)

SCN = {s["name"]: s for s in SCENARIOS}
OUT = f"{B}/results/analysis"
os.makedirs(OUT, exist_ok=True)
MCOUNT = f"{B}/bin/libmcount.so"
MCOUNT_DIR = f"{B}/run/mcount"   # /dev/shm is only 64 MB here
PERF = (sorted(glob.glob("/usr/lib/linux-tools/*/perf")) or ["perf"])[-1]   # the /usr/bin/perf wrapper wants tools for the running kernel


# --------------------------------------------------------------------------
# allocations per request
# --------------------------------------------------------------------------

def conf_for(srv, s, prefix):
    """The server conf; builds before the upstream core port (rust-ad69792,
    rust-old) lack proxy_http_version 2 and gRPC, so those locations go."""
    conf = render(SERVER_CONF, prefix, quic=s.get("quic", False))
    if srv in ("rust-ad69792", "rust-old"):
        conf = conf.replace("proxy_http_version 2;", "proxy_http_version 1.1;")
        conf = re.sub(r"grpc_pass [^;]*;", "return 404;", conf)
    return conf



def mcount_read(pid):
    """malloc, calloc, realloc, free, memalign, bytes requested, live blocks, live bytes"""
    try:
        with open(f"/dev/shm/mcount.{pid}", "rb") as f:
            return struct.unpack("6Q2q", f.read(64))
    except (OSError, struct.error):
        return (0,) * 8


def allocs(scenarios, servers, duration=5):
    res = {}
    for name in scenarios:
        s = SCN[name]
        for srv in servers:
            prefix = f"{B}/run/{srv}"
            ngx = Nginx(BINS[srv], conf_for(srv, s, prefix), prefix,
                        SERVER_CPUS, ports=(18080, 18443), env={"LD_PRELOAD": MCOUNT})
            ngx.start()
            try:
                workers = ngx.pids[1:3]
                run_load(dict(s), 2, 0)
                before = [mcount_read(p) for p in workers]
                metrics, _, raw = run_load(s, duration, 0)
                after = [mcount_read(p) for p in workers]
            finally:
                ngx.stop()
                wait_ports_free([18080, 18443])
                for p in ngx.pids:
                    try:
                        os.unlink(f"/dev/shm/mcount.{p}")
                    except OSError:
                        pass
            if not metrics or not metrics.get("requests"):
                print(f"{name:22} {srv:6} no result {raw[-200:]!r}", flush=True)
                continue
            n = metrics["requests"]
            d = [sum(a[i] - b[i] for a, b in zip(after, before)) for i in range(6)]
            allocs_n = d[0] + d[1] + d[2] + d[4]
            r = {"requests": n, "allocs_per_req": allocs_n / n, "frees_per_req": d[3] / n,
                 "bytes_per_req": d[5] / n, "malloc": d[0] / n, "calloc": d[1] / n, "realloc": d[2] / n,
                 "memalign": d[4] / n}
            res[f"{name}/{srv}"] = r
            print(f"{name:22} {srv:6} allocations/req {r['allocs_per_req']:8.1f}  (malloc {r['malloc']:.1f} "
                  f"calloc {r['calloc']:.1f} realloc {r['realloc']:.1f} aligned {r['memalign']:.1f})  "
                  f"frees/req {r['frees_per_req']:8.1f}  bytes/req {r['bytes_per_req']:10.0f}", flush=True)
    return res


def bt_read(pid, start=0):
    """Sampled allocation stacks of a process (libmcount with MCOUNT_SAMPLE):
    a list of (size, [return addresses])."""
    out = []
    try:
        with open(f"{MCOUNT_DIR}/mcount-bt.{pid}", "rb") as f:
            used = struct.unpack("Q", f.read(8))[0]
            f.seek(8 + start)
            data = f.read(used - start)
    except (OSError, struct.error):
        return out, 0
    i = 0
    while i + 8 <= len(data):
        k, size = struct.unpack_from("II", data, i)
        if k == 0 or k > 64:
            break
        frames = struct.unpack_from(f"{k}Q", data, i + 8)
        out.append((size, list(frames)))
        i += 8 + 8 * k
    return out, used


def bt_used(pid):
    try:
        with open(f"{MCOUNT_DIR}/mcount-bt.{pid}", "rb") as f:
            return struct.unpack("Q", f.read(8))[0]
    except (OSError, struct.error):
        return 0


def read_maps(pid):
    maps = []
    with open(f"/proc/{pid}/maps") as f:
        for line in f:
            p = line.split()
            if len(p) >= 6 and "x" in p[1]:
                lo, hi = (int(x, 16) for x in p[0].split("-"))
                maps.append((lo, hi, int(p[2], 16), p[5]))
    return maps


_LOADS = {}


@__import__("functools").lru_cache(None)
def _realpath(path):
    return os.path.realpath(path)


def elf_vaddr(path, off):
    """File offset -> link-time virtual address (PT_LOAD of the offset)."""
    if path not in _LOADS:
        out = subprocess.run(["readelf", "-lW", path], capture_output=True, text=True).stdout
        segs = []
        for line in out.splitlines():
            q = line.split()
            if q and q[0] == "LOAD":
                segs.append((int(q[1], 16), int(q[2], 16), int(q[4], 16)))
        _LOADS[path] = segs
    for o, v, sz in _LOADS[path]:
        if o <= off < o + sz:
            return v + (off - o)
    return off


def symbolize(path, addrs):
    """{vaddr: [(function, file:line) innermost inline first]} via addr2line -i;
    -a prints each address before its chain."""
    addrs = sorted(set(addrs))
    if not addrs:
        return {}
    out = subprocess.run(["addr2line", "-a", "-f", "-C", "-i", "-e", path],
                         input="\n".join(f"{a:x}" for a in addrs) + "\n",
                         capture_output=True, text=True).stdout.splitlines()
    res, cur, j = {}, None, 0
    while j < len(out):
        line = out[j]
        if line.startswith("0x") and (j + 1 >= len(out) or not out[j + 1].startswith("0x")):
            cur = int(line, 16)
            res[cur] = []
            j += 1
            continue
        if cur is not None and j + 1 < len(out):
            res[cur].append((line, out[j + 1]))
        j += 2
    return res


PLUMBING = re.compile(r"^(alloc::|core::|std::|hashbrown::|__rust|__rdl|smallvec::|bytes::|"
                      r"ngx_alloc|ngx_palloc|ngx_pnalloc|ngx_pcalloc|ngx_create_pool|ngx_array_|ngx_list_|"
                      r"ngx_calloc|ngx_memalign|CRYPTO_|OPENSSL_)")


def plumbing(fn):
    """Allocator and container plumbing: the site is its caller. A trait
    impl (<T as Trait>::f) counts as plumbing unless T is one of ours."""
    if fn.startswith("<"):
        m = re.match(r"<&?(?:mut )?(.+?) as ", fn)
        return not (m and m.group(1).startswith(("ngx_", "nginx")))
    return bool(PLUMBING.match(fn))


def allocsites(scenarios, servers, duration=5, every=397):
    """Where the allocations of a request come from: the first frame (after
    allocator plumbing) of sampled allocation stacks, per request."""
    recorded = []
    for name in scenarios:
        s = SCN[name]
        for srv in servers:
            prefix = f"{B}/run/{srv}"
            ngx = Nginx(BINS[srv], conf_for(srv, s, prefix), prefix, SERVER_CPUS, ports=(18080, 18443),
                        env={"LD_PRELOAD": MCOUNT, "MCOUNT_SAMPLE": str(every), "MCOUNT_DIR": MCOUNT_DIR})
            ngx.start()
            try:
                workers = ngx.pids[1:3]
                run_load(dict(s), 2, 0)
                start = {p: bt_used(p) for p in workers}
                metrics, _, raw = run_load(s, duration, 0)
                maps = {p: read_maps(p) for p in workers}
                samples = []
                for p in workers:
                    got, _ = bt_read(p, start[p])
                    samples += [(p, sz, fr) for sz, fr in got]
            finally:
                ngx.stop()
                wait_ports_free([18080, 18443])
                for q in ngx.pids:
                    for f in (f"/dev/shm/mcount.{q}", f"{MCOUNT_DIR}/mcount-bt.{q}"):
                        try:
                            os.unlink(f)
                        except OSError:
                            pass
            n = (metrics or {}).get("requests")
            if not n or not samples:
                print(f"{name:22} {srv:6} no samples", flush=True)
                continue
            # return addresses -> (object, link-time address of the call)
            resolved = []
            memo = {}
            for p, sz, fr in samples:
                rf = []
                for a in fr:
                    r = memo.get((p, a))
                    if r is None:
                        for lo, hi, off, path in maps[p]:
                            if lo <= a < hi:
                                r = (path, elf_vaddr(path, a - lo + off) - 1)
                                break
                        else:
                            r = (None, a)
                        memo[(p, a)] = r
                    rf.append(r)
                resolved.append((sz, rf))
            recorded.append((name, srv, n, len(samples), os.path.realpath(BINS[srv]), resolved))
            print(f"recorded {name} {srv}: {len(samples)} samples, {n} requests", flush=True)

    per_bin = collections.defaultdict(set)
    for name, srv, n, ns, binary, resolved in recorded:
        for sz, rf in resolved:
            for path, va in rf:
                if path and _realpath(path) == binary:
                    per_bin[binary].add(va)
    syms = {}
    for binary, addrs in per_bin.items():
        for a, ch in symbolize(binary, addrs).items():
            syms[(binary, a)] = ch

    res = {}
    for name, srv, n, ns, binary, resolved in recorded:
        sites = collections.Counter()
        stacks = collections.Counter()
        for sz, rf in resolved:
            site, chain = None, []
            for path, va in rf:
                if path is None or _realpath(path) != binary:
                    continue
                for fn, loc in syms.get((binary, va), [("??", "??")]):
                    if fn == "??" or plumbing(fn):
                        continue
                    chain.append(fn)
                    if site is None:
                        loc = loc.split(" (discriminator")[0]
                        loc = re.sub(r"^.*/(crates/[^/]+/src|src)/", "", loc)
                        site = f"{fn} @ {loc}"
            sites[site or "(unresolved)"] += 1
            stacks[" <- ".join(list(dict.fromkeys(chain))[:6])[:400] or "(unresolved)"] += 1
        scale = every / n
        top = [(k, round(v * scale, 2)) for k, v in sites.most_common(60)]
        topst = [(k, round(v * scale, 2)) for k, v in stacks.most_common(40)]
        res[f"{name}/{srv}"] = {"requests": n, "samples": ns, "allocs_per_req": round(ns * scale, 1),
                                "sites": top, "stacks": topst}
        print(f"== {name} {srv}: {ns * scale:.1f} allocations/req sampled ({ns} samples)")
        for k, v in top[:30]:
            print(f"   {v:6.2f}  {k[:200]}")
    return res


def idle(scenarios, servers, n=5000):
    """Heap blocks and bytes held per idle connection (live counters of
    libmcount), with PSS for comparison. SCENARIOS: idle-10k-h1 etc."""
    import bench
    res = {}
    for name in scenarios:
        s = SCN[name]
        for srv in servers:
            prefix = f"{B}/run/{srv}"
            ngx = Nginx(BINS[srv], conf_for(srv, s, prefix), prefix, SERVER_CPUS, ports=(18080, 18443),
                        env={"LD_PRELOAD": MCOUNT})
            ngx.start()
            try:
                workers = ngx.pids[1:3]
                time.sleep(1)
                before = [mcount_read(p) for p in workers]
                pss0 = bench.mem_snapshot(ngx.pids)["total"].get("Pss", 0)
                p = subprocess.Popen(["taskset", "-c", CLIENT_CPUS, f"{B}/bin/idleconns", "-mode", s["mode"],
                                      "-addr", s["addr"], "-n", str(n)],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                line = p.stdout.readline().split()
                ok = int(line[1]) if len(line) == 3 else 0
                time.sleep(2)
                after = [mcount_read(p) for p in workers]
                pss1 = bench.mem_snapshot(ngx.pids)["total"].get("Pss", 0)
                p.stdin.close()
                p.wait()
                time.sleep(1)
                closed = [mcount_read(p) for p in workers]
            finally:
                ngx.stop()
                wait_ports_free([18080, 18443])
                for q in ngx.pids:
                    try:
                        os.unlink(f"/dev/shm/mcount.{q}")
                    except OSError:
                        pass
            if not ok:
                print(f"{name:22} {srv:6} no connections", flush=True)
                continue
            d = lambda a, b, i: sum(x[i] - y[i] for x, y in zip(a, b))  # noqa: E731
            r = {"connections": ok, "live_blocks_per_conn": d(after, before, 6) / ok,
                 "live_bytes_per_conn": d(after, before, 7) / ok, "pss_kb_per_conn": (pss1 - pss0) / ok,
                 "allocs_per_conn": (d(after, before, 0) + d(after, before, 1) + d(after, before, 4)) / ok,
                 "live_bytes_left_after_close_per_conn": d(closed, before, 7) / ok}
            res[f"{name}/{srv}"] = r
            print(f"{name:22} {srv:6} heap/conn {r['live_bytes_per_conn'] / 1024:6.2f} KB in "
                  f"{r['live_blocks_per_conn']:5.1f} blocks; PSS/conn {r['pss_kb_per_conn']:6.2f} KB; "
                  f"allocations while opening {r['allocs_per_conn']:.1f}/conn; "
                  f"left after close {r['live_bytes_left_after_close_per_conn']:.0f} B/conn", flush=True)
    return res


# --------------------------------------------------------------------------
# syscalls per request: strace as the parent of nginx (ptrace of a descendant)
# --------------------------------------------------------------------------

def strace_session(srv, s, prefix, load_seconds, rate):
    """Run nginx under strace -f -c; with rate > 0 load it at `rate` req/s.
    Returns ({syscall: calls}, requests)."""
    binary = BINS[srv]
    conf = conf_for(srv, s, prefix)
    reset_prefix(prefix)
    with open(f"{prefix}/conf/nginx.conf", "w") as f:
        f.write(conf)
    out = f"{prefix}/logs/strace.txt"
    p = subprocess.Popen(["strace", "-f", "-c", "-o", out, "--", "taskset", "-c", SERVER_CPUS, binary,
                          "-p", prefix + "/", "-c", f"{prefix}/conf/nginx.conf"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    end = time.time() + 20
    while time.time() < end and not (port_open(18080) and port_open(18443)):
        time.sleep(0.1)
    time.sleep(1.0)
    requests = 0
    if rate:
        ls = dict(s, tool="oha", conns=s.get("conns", 50) if s["tool"] == "oha" else 20)
        if s["tool"] == "h2load":
            ls.update(http_version="2", conns=4, parallel=5)
        if s.get("script"):
            ls["oha_extra"] = ["-m", "POST", "-D", f"{B}/www-extra/post10k.bin",
                               "-H", "Content-Type: application/octet-stream"]
        o, _, _ = client_run(oha_cmd(ls, s["url"], load_seconds, rate), load_seconds + 60)
        m = parse_oha(o, load_seconds) or {}
        requests = m.get("requests", 0)
    else:
        time.sleep(load_seconds)
    try:
        pid = int(open(f"{prefix}/logs/nginx.pid").read())
        os.kill(pid, signal.SIGTERM)
    except (OSError, ValueError):
        pass
    p.wait(timeout=60)
    calls = {}
    for line in open(out):
        m = re.match(r"\s*[\d.]+\s+[\d.]+\s+\d+\s+(\d+)\s+(?:(\d+)\s+)?(\w+)\s*$", line)
        if m and m.group(3) != "total":
            calls[m.group(3)] = int(m.group(1))
            if m.group(2):
                calls[m.group(3) + " (failed)"] = int(m.group(2))
    return calls, requests


def syscalls(scenarios, servers, seconds=6, rate=2000):
    res = {}
    for name in scenarios:
        s = SCN[name]
        for srv in servers:
            prefix = f"{B}/run/{srv}"
            base, _ = strace_session(srv, s, prefix, seconds, 0)
            wait_ports_free([18080, 18443])
            load, n = strace_session(srv, s, prefix, seconds, rate)
            wait_ports_free([18080, 18443])
            if not n:
                print(f"{name:22} {srv:6} no requests counted", flush=True)
                continue
            per = {k: (load.get(k, 0) - base.get(k, 0)) / n for k in set(load) | set(base)}
            per = {k: round(v, 2) for k, v in sorted(per.items(), key=lambda kv: -kv[1]) if v >= 0.05}
            total = round(sum(v for k, v in per.items() if not k.endswith("(failed)")), 2)
            res[f"{name}/{srv}"] = {"requests": n, "per_request": per, "total": total}
            top = ", ".join(f"{k} {v}" for k, v in list(per.items())[:8])
            print(f"{name:22} {srv:6} syscalls/req {total:6.2f}: {top}", flush=True)
    return res


# --------------------------------------------------------------------------
# syscalls per request under full load: perf stat on the syscall tracepoints
# (tracefs must be mounted; perf runs under sudo, nginx as this user)
# --------------------------------------------------------------------------

# x86_64 syscall numbers: counted through raw_syscalls with an id filter, as
# some per-syscall tracepoints (syscalls:sys_enter_recvfrom) never fire on
# this kernel
SYSCALLS = {"read": 0, "write": 1, "close": 3, "fstat": 5, "lseek": 8, "mmap": 9, "mprotect": 10, "munmap": 11,
            "brk": 12, "ioctl": 16, "pread64": 17, "readv": 19, "writev": 20, "sched_yield": 24, "mremap": 25,
            "madvise": 28, "sendfile": 40, "socket": 41, "connect": 42, "sendto": 44, "recvfrom": 45,
            "sendmsg": 46, "recvmsg": 47, "shutdown": 48, "getsockname": 51, "setsockopt": 54, "getsockopt": 55,
            "fcntl": 72, "futex": 202, "epoll_wait": 232, "epoll_ctl": 233, "openat": 257, "newfstatat": 262,
            "epoll_pwait": 281, "accept4": 288, "eventfd2": 290, "recvmmsg": 299, "sendmmsg": 307,
            "getrandom": 318, "statx": 332, "dup": 32, "dup2": 33, "dup3": 292, "accept": 43}
EAGAIN_OF = ["read", "recvfrom", "recvmsg", "readv", "writev", "sendto", "sendmsg", "write", "accept4"]


def perfstat_session(srv, s, prefix, seconds, load):
    """nginx under perf stat counting syscalls; with load, run the scenario's
    client at full load. Returns ({event: count}, requests)."""
    binary = BINS[srv]
    conf = conf_for(srv, s, prefix)
    reset_prefix(prefix)
    with open(f"{prefix}/conf/nginx.conf", "w") as f:
        f.write(conf)
    out = f"{prefix}/logs/perfstat.csv"
    ev = ["-e", "raw_syscalls:sys_enter"]
    names = ["sys_enter"]
    for sc, nr in SYSCALLS.items():
        ev += ["-e", "raw_syscalls:sys_enter", "--filter", f"id == {nr}"]
        names.append(sc)
    for sc in EAGAIN_OF:
        ev += ["-e", "raw_syscalls:sys_exit", "--filter", f"id == {SYSCALLS[sc]} && ret == -11"]
        names.append(sc + " EAGAIN")
    # setpriv, not sudo, drops back to this user: sudo takes 10 s here
    # (the host name does not resolve)
    p = subprocess.Popen(["sudo", PERF, "stat", "-x", ",", "-o", out] + ev +
                         ["--", "setpriv", f"--reuid={os.getuid()}", f"--regid={os.getgid()}", "--init-groups",
                          "taskset", "-c", SERVER_CPUS, binary, "-p", prefix + "/", "-c", f"{prefix}/conf/nginx.conf"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    end = time.time() + 60
    while time.time() < end and not (port_open(18080) and port_open(18443)):
        time.sleep(0.1)
    if not (port_open(18080) and port_open(18443)):
        raise RuntimeError("nginx under perf stat did not start")
    time.sleep(1.0)
    requests = 0
    if load:
        metrics, _, _ = run_load(s, seconds, 0)
        requests = (metrics or {}).get("requests") or 0
    else:
        time.sleep(seconds)
    try:
        os.kill(int(open(f"{prefix}/logs/nginx.pid").read()), signal.SIGTERM)
    except (OSError, ValueError):
        pass
    p.wait(timeout=60)
    # the events are printed in the order given; the filters don't show
    counts = {}
    rows = [line.strip().split(",") for line in open(out)]
    rows = [f for f in rows if len(f) >= 3 and f[2].startswith("raw_syscalls:")]
    for name, f in zip(names, rows):
        counts[name] = float(f[0]) if f[0].replace(".", "").isdigit() else 0.0
    return counts, requests


def sysstat(scenarios, servers, seconds=5):
    res = {}
    for name in scenarios:
        s = SCN[name]
        for srv in servers:
            prefix = f"{B}/run/{srv}"
            base, _ = perfstat_session(srv, s, prefix, seconds, False)
            wait_ports_free([18080, 18443])
            load, n = perfstat_session(srv, s, prefix, seconds, True)
            wait_ports_free([18080, 18443])
            if not n:
                print(f"{name:22} {srv:6} no requests counted", flush=True)
                continue
            per = {k: (load.get(k, 0) - base.get(k, 0)) / n for k in set(load) | set(base)}
            per = {k: round(v, 3) for k, v in sorted(per.items(), key=lambda kv: -kv[1]) if v >= 0.005}
            total = per.pop("sys_enter", None)
            res[f"{name}/{srv}"] = {"requests": n, "rps": n / seconds, "total": total, "per_request": per}
            top = ", ".join(f"{k} {v:.2f}" for k, v in list(per.items())[:10])
            print(f"{name:22} {srv:6} rps={n / seconds:9,.0f} syscalls/req {total or 0:6.2f}: {top}", flush=True)
    return res


# --------------------------------------------------------------------------
# profiles with call graphs, classified into components
# --------------------------------------------------------------------------

def component(sym, dso):
    """The component a sampled frame belongs to."""
    d = dso or ""
    if "kernel" in d or d.startswith("["):
        return "kernel"
    if "libcrypto" in d or "libssl" in d:
        return "OpenSSL"
    if "libz" in d:
        return "zlib"
    if "pcre" in d:
        return "PCRE"
    if "libc" in d or "ld-linux" in d:
        if re.search(r"malloc|free|calloc|realloc|memalign|unlink_chunk|tcache|consolidate|sysmalloc|arena", sym):
            return "malloc/free"
        if re.search(r"mem(cpy|move|set|cmp)|str(len|cmp|chr|ncmp)", sym):
            return "memcpy/memset/str"
        return "libc other"
    # the server binaries
    s = sym
    if re.search(r"__rust_alloc|__rust_dealloc|__rdl_|alloc::alloc::|<alloc::alloc::Global|drop_in_place|RawVec|raw_vec|Vec<.*>::(reserve|push|extend)|do_reserve|finish_grow|ngx_palloc|ngx_pnalloc|ngx_pcalloc|ngx_create_pool|ngx_destroy_pool|ngx_reset_pool|ngx_alloc|ngx_calloc|ngx_pfree", s):
        return "allocation (in binary)"
    if s.startswith("tokio::") or "<tokio::" in s or "tokio::runtime" in s:
        return "tokio runtime"
    if re.search(r"core::fmt|alloc::fmt|ngx_vslprintf|ngx_sprintf|ngx_snprintf|ngx_slprintf", s):
        return "formatting"
    if re.search(r"ngx_epoll|ngx_process_events|ngx_event_|ngx_handle_(read|write)_event|ngx_add_timer|ngx_event_find_timer|ngx_rbtree", s):
        return "event loop"
    if re.search(r"v3::|quic::|ngx_quic|ngx_http_v3", s):
        return "QUIC/HTTP3"
    if re.search(r"v2::|ngx_http_v2|huff|hpack", s):
        return "HTTP/2"
    if re.search(r"upstream|event_pipe|proxy|fastcgi|grpc|uwsgi|ngx_http_upstream|ngx_event_pipe", s):
        return "upstream/proxy"
    if re.search(r"ssl|openssl|SslConnection", s, re.I):
        return "TLS glue"
    if re.search(r"parse|ngx_http_parse|header_line|request_line", s):
        return "HTTP parsing"
    if re.search(r"filter|ngx_http_.*_filter|output_chain|write_filter|copy_filter|send_chain|writev|sendfile|chain", s):
        return "output/filters"
    if re.search(r"variable|script|complex_value|ngx_http_variable|ngx_http_script", s):
        return "variables/script"
    if re.search(r"log|ngx_http_log", s):
        return "logging"
    if re.search(r"RefCell|Rc<|core::cell|BorrowRef|alloc::rc", s):
        return "Rc/RefCell"
    if re.search(r"hash|HashMap|hashbrown|ngx_hash", s):
        return "hashing"
    if re.search(r"stream::|ngx_stream", s):
        return "stream module"
    if re.search(r"request|ngx_http_(process|handler|core|finalize|run_posted|init_request|wait_request|set_keepalive|keepalive)|phase|connection_task|location", s):
        return "request lifecycle"
    if s.startswith("core::") or s.startswith("alloc::") or s.startswith("std::") or s.startswith("<core::") or s.startswith("<alloc::") or s.startswith("<std::"):
        return "Rust std/core"
    return "other (binary)"


# Call graphs: perf 5.15 unwinds the C binary with DWARF, but not the Rust one
# (no frame past the first), so Rust is profiled in frame-pointer builds of
# the same commits (-C force-frame-pointers=yes)
PROFILE_BINS = {"rust": f"{B}/bin/nginx-rust-fp", "rust-ad69792": f"{B}/bin/nginx-rust-ad69792-fp"}


def profile_run(srv, s, label, seconds=6):
    binary = PROFILE_BINS.get(srv, BINS[srv])
    callgraph = "fp" if srv in PROFILE_BINS else "dwarf,32768"
    prefix = f"{B}/run/prof-{label}"
    conf = conf_for(srv, s, prefix)
    reset_prefix(prefix)
    with open(f"{prefix}/conf/nginx.conf", "w") as f:
        f.write(conf)
    data = f"{OUT}/perf-{s['name']}-{label}.data"
    p = subprocess.Popen([PERF, "record", "-e", "cpu-clock", "-F", "999", "--call-graph", callgraph, "-o", data, "--",
                          "taskset", "-c", SERVER_CPUS, binary, "-p", prefix + "/", "-c", f"{prefix}/conf/nginx.conf"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    end = time.time() + 20
    while time.time() < end and not (port_open(18080) and port_open(18443)):
        time.sleep(0.1)
    time.sleep(0.5)
    run_load(dict(s), 2, 0)
    metrics, _, _ = run_load(s, seconds, 0)
    try:
        os.kill(int(open(f"{prefix}/logs/nginx.pid").read()), signal.SIGTERM)
    except (OSError, ValueError):
        pass
    p.wait(timeout=120)
    return data, metrics


def summarize_profile(data):
    """Self and inclusive time per component and per function from perf script."""
    proc = subprocess.Popen([PERF, "script", "-i", data, "-F", "comm,ip,sym,dso", "--no-inline"],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors="replace")
    self_comp = collections.Counter()
    kern_sys = collections.Counter()
    attr_comp = collections.Counter()
    attr_sym = collections.Counter()
    incl_comp = collections.Counter()
    self_sym = collections.Counter()
    incl_sym = collections.Counter()
    samples = 0
    frames = []

    def flush():
        nonlocal samples, frames
        if not frames:
            return
        samples += 1
        leaf_sym, leaf_dso = frames[0]
        c = component(leaf_sym, leaf_dso)
        self_comp[c] += 1
        self_sym[(c, leaf_sym)] += 1
        # user time charged to the nearest frame of the server's own code: the
        # malloc/memcpy/Rust-std time a function causes is charged to it
        if c != "kernel":
            owner = None
            for sym, dso in frames:
                cc = component(sym, dso)
                if cc in ("malloc/free", "memcpy/memset/str", "libc other", "Rust std/core", "allocation (in binary)",
                          "Rc/RefCell", "hashing", "formatting", "kernel"):
                    continue
                owner = (cc, sym)
                break
            if owner is None:
                owner = (c, leaf_sym)
            attr_comp[owner[0]] += 1
            attr_sym[owner] += 1
        if c == "kernel":
            sc = "no syscall (irq/fault/other)"
            for sym, dso in reversed(frames):
                m = re.match(r"__(?:x64|se|do)_sys_(\w+)", sym)
                if m:
                    sc = m.group(1)
                    break
            kern_sys[sc] += 1
        seen_c, seen_s = set(), set()
        for sym, dso in frames:
            cc = component(sym, dso)
            if cc not in seen_c:
                incl_comp[cc] += 1
                seen_c.add(cc)
            if sym not in seen_s:
                incl_sym[sym] += 1
                seen_s.add(sym)
        frames = []

    for line in proc.stdout:
        if not line.strip():
            flush()
            continue
        if not line.startswith((" ", "\t")):
            flush()
            # header line: comm (only server processes are wanted)
            continue
        m = re.match(r"\s+[0-9a-f]+\s+(.*?)\s+\((.*)\)\s*$", line)
        if m:
            sym = re.sub(r"\+0x[0-9a-f]+$", "", m.group(1))
            frames.append((sym, m.group(2)))
    flush()
    proc.wait()
    pct = lambda c: {k: round(100.0 * v / samples, 1) for k, v in c.most_common()}  # noqa: E731
    return {"samples": samples, "self_components": pct(self_comp), "incl_components": pct(incl_comp),
            "kernel_by_syscall": pct(kern_sys), "user_attributed": pct(attr_comp),
            "top_attributed": [(c, s, round(100.0 * v / samples, 2)) for (c, s), v in attr_sym.most_common(40)],
            "top_self": [(c, s, round(100.0 * v / samples, 2)) for (c, s), v in self_sym.most_common(25)],
            "top_incl": [(s, round(100.0 * v / samples, 1)) for s, v in incl_sym.most_common(40)]}


def profile(scenarios, servers, seconds=6):
    # record one after the other (the machine must be otherwise idle), then
    # unwind and summarize in parallel
    runs = []
    for name in scenarios:
        s = SCN[name]
        for srv in servers:
            data, metrics = profile_run(srv, s, srv, seconds)
            runs.append((name, srv, data, (metrics or {}).get("rps")))
            print(f"recorded {name} {srv} rps={(metrics or {}).get('rps') or 0:,.0f}", flush=True)
            wait_ports_free([18080, 18443])
    import multiprocessing
    with multiprocessing.Pool(min(8, len(runs))) as pool:
        summs = pool.map(summarize_profile, [r[2] for r in runs])
    res = {}
    for (name, srv, data, rps), summ in zip(runs, summs):
        summ["rps"] = rps
        res[f"{name}/{srv}"] = summ
        comps = ", ".join(f"{k} {v}%" for k, v in list(summ["self_components"].items())[:9])
        print(f"{name:22} {srv:6} rps={rps or 0:,.0f} samples={summ['samples']}  self: {comps}", flush=True)
    return res


def glibc_malloc(binary):
    """libmcount counts calls to glibc's malloc: a binary with its own allocator
    (jemalloc, the default build since PLAN.md Phase 0, or mimalloc) would show
    next to no allocations."""
    syms = subprocess.run(["nm", binary], capture_output=True, text=True).stdout
    return not re.search(r" [Tt] (malloc|_rjem_malloc|mi_malloc\w*)$", syms, re.M)


def main():
    what, scen, servers = sys.argv[1], sys.argv[2].split(","), sys.argv[3].split(",")
    if what in ("allocs", "allocsites", "idle"):
        own = [s for s in servers if not glibc_malloc(BINS[s])]
        if own:
            sys.exit(f"{', '.join(own)}: not on glibc's malloc, which libmcount counts; "
                     "build with cargo build --release --no-default-features")
    with open(f"{B}/run/post10k.lua", "w") as f:
        f.write(POST_LUA)
    be = Backends()
    be.start()
    try:
        r = {"allocs": allocs, "allocsites": allocsites, "idle": idle, "syscalls": syscalls, "sysstat": sysstat,
             "profile": profile}[what](scen, servers)
    finally:
        be.stop()
    path = f"{OUT}/{what}-{int(time.time())}.json"
    with open(path, "w") as f:
        json.dump(r, f, indent=1)
    print("->", path)


if __name__ == "__main__":
    main()
