#!/usr/bin/env python3
"""Follow-up experiments that explain the main results.

    extra.py balance     per-worker CPU split (does one worker do all the work?)
    extra.py syscalls    syscalls per request (strace -c on both workers, fixed low rate)
    extra.py baseline    idle memory vs worker_connections (C preallocates connections)
    extra.py accesslog   access_log lines written vs requests served
    extra.py profile     perf profile of the workers under saturation (needs perf)
"""
import json
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bench import (B, BINS, CLIENT_CPUS, H, SCENARIOS, SERVER_CONF, SERVER_CPUS, Backends, Nginx,  # noqa: E402
                   client_run, cpu_snapshot, mem_snapshot, oha_cmd, parse_oha, parse_wrk, render,
                   wait_ports_free, wrk_cmd)

SCN = {s["name"]: s for s in SCENARIOS}
OUT = f"{B}/results/extra"
os.makedirs(OUT, exist_ok=True)


def server(srv, conf_text=None):
    prefix = f"{B}/run/{srv}"
    ngx = Nginx(BINS[srv], conf_text or render(SERVER_CONF, prefix), prefix, SERVER_CPUS, ports=(18080, 18443))
    ngx.start()
    return ngx


def stop(ngx):
    ngx.stop()
    wait_ports_free([18080, 18443])


def balance(servers):
    res = {}
    for name in ("h1-static-1m", "h1-static-1k", "proxy-1m"):
        s = SCN[name]
        for srv in servers:
            ngx = server(srv)
            try:
                workers = ngx.pids[1:3]
                c0 = cpu_snapshot(workers)
                out, _, _ = client_run(wrk_cmd(s, s["url"], 8), 70)
                c1 = cpu_snapshot(workers)
                split = [round((c1[p][2] - c0[p][2]) / 1e9 / 8 * 100) for p in workers]
                m = parse_wrk(out) or {}
                res[f"{name}/{srv}"] = {"worker_cpu_pct": split, "rps": m.get("rps")}
                print(f"{name:14} {srv:5} per-worker CPU % = {split}  rps={m.get('rps')}", flush=True)
            finally:
                stop(ngx)
    return res


def syscalls(servers, rate=1000, secs=5):
    """strace -c both workers while oha sends `rate` req/s; normalise per request."""
    res = {}
    for name in ("h1-return", "h1-static-1k", "proxy-1k-keepalive", "proxy-post-10k", "tls-h1-1k", "h2-tls-1k"):
        base = SCN[name]
        s = dict(base, tool="oha", conns=20)
        if name == "proxy-post-10k":
            s["oha_extra"] = ["-m", "POST", "-D", f"{B}/www-extra/post10k.bin",
                              "-H", "Content-Type: application/octet-stream"]
        if base["tool"] == "h2load":
            s.update(http_version="2", conns=4, parallel=5)
        for srv in servers:
            ngx = server(srv)
            try:
                load = subprocess.Popen(oha_cmd(s, s["url"], secs + 3, rate), stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, text=True)
                time.sleep(1.5)
                cmd = ["sudo", "timeout", "-s", "INT", str(secs), "strace", "-c", "-S", "calls"]
                for p in ngx.pids[1:3]:
                    cmd += ["-p", str(p)]
                tr = subprocess.run(cmd, capture_output=True, text=True)
                load.communicate()
                calls = {}
                for line in tr.stderr.splitlines():
                    m = re.match(r"\s*[\d.]+\s+[\d.]+\s+\d+\s+(\d+)\s+(?:(\d+)\s+)?(\w+)\s*$", line)
                    if m and m.group(3) != "total":
                        calls[m.group(3)] = int(m.group(1))
                reqs = rate * secs
                per = {k: round(v / reqs, 2) for k, v in sorted(calls.items(), key=lambda kv: -kv[1]) if v / reqs >= 0.05}
                res[f"{name}/{srv}"] = {"per_request": per, "total_per_request": round(sum(calls.values()) / reqs, 2)}
                print(f"{name:20} {srv:5} syscalls/req={sum(calls.values()) / reqs:.2f}  {per}", flush=True)
            finally:
                stop(ngx)
    return res


def baseline(servers):
    res = {}
    for wc in (1024, 20000):
        for srv in servers:
            prefix = f"{B}/run/{srv}"
            conf = render(SERVER_CONF, prefix).replace("worker_connections 20000;", f"worker_connections {wc};")
            ngx = server(srv, conf)
            try:
                time.sleep(1)
                m = mem_snapshot(ngx.pids)
                per = {pid: round(d.get("Pss", 0) / 1024, 1) for pid, d in m["per_pid"].items()}
                res[f"wc{wc}/{srv}"] = {"pss_total_mb": round(m["total"]["Pss"] / 1024, 1), "per_pid_mb": per,
                                        "rss_total_mb": round(m["total"]["VmRSS"] / 1024, 1)}
                print(f"worker_connections={wc:6} {srv:5} PSS total={m['total']['Pss'] / 1024:.1f} MB "
                      f"(per process {list(per.values())})", flush=True)
            finally:
                stop(ngx)
    return res


def accesslog(servers):
    res = {}
    s = SCN["h1-access-log"]
    for srv in servers:
        ngx = server(srv)
        try:
            out, _, _ = client_run(wrk_cmd(s, s["url"], 5), 60)
            m = parse_wrk(out)
        finally:
            stop(ngx)   # flushes the buffered log
        path = f"{B}/run/{srv}/logs/access.log"
        lines = sum(1 for _ in open(path)) if os.path.exists(path) else 0
        with open(path) as f:
            sample = f.readline().strip()
        res[srv] = {"requests": m["requests"], "log_lines": lines, "sample": sample}
        print(f"{srv:5} requests={m['requests']} access.log lines={lines}\n      sample: {sample}", flush=True)
    return res


def profile(servers, perf="perf"):
    res = {}
    for name in ("h1-static-1k", "proxy-1k-keepalive", "h2-tls-1k"):
        s = SCN[name]
        for srv in servers:
            ngx = server(srv)
            try:
                tool = wrk_cmd(s, s["url"], 12) if s["tool"] == "wrk" else None
                if s["tool"] == "h2load":
                    from bench import h2load_cmd
                    tool = h2load_cmd(s, s["url"], 12)
                load = subprocess.Popen(tool, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(2)
                data = f"{OUT}/perf-{name}-{srv}.data"
                # per-pid attach records nothing inside this container; the
                # workers own CPUs 0-1, so sample those CPUs system-wide
                subprocess.run(["sudo", perf, "record", "-e", "cpu-clock", "-F", "1999", "-a", "-C", SERVER_CPUS,
                                "-o", data, "--", "sleep", "6"], capture_output=True)
                load.wait()
                rep = subprocess.run(["sudo", perf, "report", "-i", data, "--no-children", "--sort", "dso,symbol", "--comm", "nginx-c-O2,nginx-rust",
                                      "--stdio", "--percent-limit", "0.7"],
                                     capture_output=True, text=True).stdout
                lines = [l for l in rep.splitlines() if l.strip() and not l.startswith("#")]
                res[f"{name}/{srv}"] = lines[:45]
                with open(f"{OUT}/perf-{name}-{srv}.txt", "w") as f:
                    f.write(rep)
                print(f"== {name} {srv}\n" + "\n".join(lines[:30]), flush=True)
            finally:
                stop(ngx)
    return res


def leak(servers, rounds=4, n=10000):
    """Open and close n idle connections several times: memory that keeps
    growing round after round is a leak; a plateau is allocator retention."""
    from bench import ENVS
    res = {}
    for mode, addr in (("h1", "127.0.0.1:18080"), ("h2", "127.0.0.1:18443")):
        for srv in servers:
            prefix = f"{B}/run/{srv}"
            ngx = Nginx(BINS[srv], render(SERVER_CONF, prefix), prefix, SERVER_CPUS, ports=(18080, 18443),
                        env=ENVS.get(srv))
            ngx.start()
            try:
                series = [round(mem_snapshot(ngx.pids)["total"]["Pss"] / 1024, 1)]
                for _ in range(rounds):
                    p = subprocess.Popen(["taskset", "-c", CLIENT_CPUS, f"{B}/bin/idleconns", "-mode", mode,
                                          "-addr", addr, "-n", str(n)], stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE, text=True)
                    p.stdout.readline()
                    time.sleep(1)
                    open_mb = round(mem_snapshot(ngx.pids)["total"]["Pss"] / 1024, 1)
                    p.stdin.close()
                    p.wait()
                    time.sleep(2)
                    series += [open_mb, round(mem_snapshot(ngx.pids)["total"]["Pss"] / 1024, 1)]
                res[f"{mode}/{srv}"] = series
                print(f"{mode} {srv:18} PSS MB: start {series[0]}  then (open, closed) x{rounds}: "
                      f"{list(zip(series[1::2], series[2::2]))}", flush=True)
            finally:
                stop(ngx)
    return res


def main():
    what = sys.argv[1]
    servers = (sys.argv[2] if len(sys.argv) > 2 else "c,rust").split(",")
    be = None
    if what in ("balance", "syscalls", "profile"):
        be = Backends()
        be.start()
    try:
        if what == "balance":
            r = balance(servers)
        elif what == "syscalls":
            r = syscalls(servers)
        elif what == "baseline":
            r = baseline(servers)
        elif what == "accesslog":
            r = accesslog(servers)
        elif what == "leak":
            r = leak(servers)
        elif what == "profile":
            r = profile(servers, os.environ.get("PERF", "perf"))
        else:
            sys.exit(__doc__)
    finally:
        if be:
            be.stop()
    with open(f"{OUT}/{what}.json", "w") as f:
        json.dump(r, f, indent=1)


if __name__ == "__main__":
    main()
