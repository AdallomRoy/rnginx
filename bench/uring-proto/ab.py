#!/usr/bin/env python3
"""A/B the I/O-model prototypes against C nginx and rnginx on `return 200`.

Servers on CPUs 0,1 (2 single-threaded workers), wrk on CPUs 4-7.
Usage: ab.py REPS DURATION [server ...]
"""
import os
import re
import subprocess
import sys
import time

EXP = os.path.dirname(os.path.abspath(__file__))
PROTO = f"{EXP}/target/release/uring-proto"
CNGINX = os.path.join(os.path.dirname(EXP), "bin", "nginx-c-O2")
RNGINX = os.environ.get("RNGINX", os.path.join(os.path.dirname(os.path.dirname(EXP)), "target", "release", "nginx"))
TCK = os.sysconf("SC_CLK_TCK")
CLIENT_CPUS = os.environ.get("CLIENT_CPUS", "4-7")
CLIENT_THREADS = int(os.environ.get("CLIENT_THREADS", "4"))
CLIENT_LIST = [int(c) for c in os.environ.get("CLIENT_LIST", "4,5,6,7").split(",")]

NGINX_CONF = """
daemon off;
master_process on;
worker_processes 2;
worker_cpu_affinity 01 10;
worker_rlimit_nofile 200000;
error_log {prefix}/logs/error.log warn;
pid {prefix}/logs/nginx.pid;
events {{ worker_connections 20000; }}
http {{
    access_log off;
    keepalive_requests 1000000;
    default_type text/plain;
    server {{
        listen 127.0.0.1:{port} backlog=4096;
        location = /return {{ return 200 "hello world\\n"; }}
    }}
}}
"""


def children(pid):
    out = subprocess.run(["pgrep", "-P", str(pid)], capture_output=True, text=True).stdout
    return [int(x) for x in out.split()]


def cpustat():
    """busy and total jiffies per CPU from /proc/stat"""
    res = {}
    for line in open("/proc/stat"):
        if line.startswith("cpu") and line[3].isdigit():
            f = line.split()
            v = [int(x) for x in f[1:]]
            idle = v[3] + v[4]
            res[int(f[0][3:])] = (sum(v) - idle, sum(v))
    return res


def busy(a, b, cpus):
    bz = sum(b[c][0] - a[c][0] for c in cpus)
    tot = sum(b[c][1] - a[c][1] for c in cpus)
    return bz / TCK, bz / tot if tot else 0


def cpu(pids):
    u = s = 0
    for p in pids:
        f = open(f"/proc/{p}/stat").read().rsplit(")", 1)[1].split()
        u += int(f[11])
        s += int(f[12])
    return u / TCK, s / TCK


def start(name, port):
    if name.startswith("proto-"):
        mode, _, knobs = name[len("proto-"):].partition("@")
        env = dict(os.environ)
        for kv in filter(None, knobs.split(",")):
            k, v = kv.split("=")
            env[k] = v
        p = subprocess.Popen([PROTO, mode, str(port), "0,1"], stdout=subprocess.PIPE, text=True, env=env)
        kids = [int(x) for x in p.stdout.readline().split()]
        time.sleep(0.3)
        return p, kids
    binary = CNGINX if name == "c" else RNGINX
    prefix = f"{EXP}/run/{name}"
    os.makedirs(f"{prefix}/logs", exist_ok=True)
    with open(f"{prefix}/nginx.conf", "w") as f:
        f.write(NGINX_CONF.format(prefix=prefix, port=port))
    p = subprocess.Popen(["taskset", "-c", "0,1", binary, "-p", prefix + "/", "-c", f"{prefix}/nginx.conf"])
    for _ in range(50):
        time.sleep(0.1)
        kids = children(p.pid)
        if len(kids) >= 2:
            break
    time.sleep(0.3)
    return p, kids


def wrk(port, duration):
    out = subprocess.run(["taskset", "-c", CLIENT_CPUS, "wrk", f"-t{CLIENT_THREADS}", "-c256", f"-d{duration}s",
                          f"http://127.0.0.1:{port}/return"], capture_output=True, text=True).stdout
    reqs = int(re.search(r"(\d+) requests in", out).group(1))
    rps = float(re.search(r"Requests/sec:\s+([\d.]+)", out).group(1))
    errs = re.search(r"Socket errors: (.*)", out)
    non2xx = re.search(r"Non-2xx or 3xx responses: (\d+)", out)
    return reqs, rps, (errs.group(1) if errs else ""), (non2xx.group(1) if non2xx else "0")


def main():
    reps, duration = int(sys.argv[1]), int(sys.argv[2])
    servers = sys.argv[3:] or ["c", "rust", "proto-epoll", "proto-uring", "proto-uring-arc"]
    rows = {s: [] for s in servers}
    port = 28100
    for rep in range(reps):
        for s in servers:
            port += 1
            p, kids = start(s, port)
            wrk(port, 2)  # warm-up
            u0, s0 = cpu(kids)
            c0 = cpustat()
            reqs, rps, errs, non2xx = wrk(port, duration)
            c1 = cpustat()
            u1, s1 = cpu(kids)
            us_u = (u1 - u0) / reqs * 1e6
            us_s = (s1 - s0) / reqs * 1e6
            sbusy, sfrac = busy(c0, c1, [0, 1])
            cbusy, cfrac = busy(c0, c1, CLIENT_LIST)
            us_cpu = sbusy / reqs * 1e6
            us_cli = cbusy / reqs * 1e6
            rows[s].append((rps, us_u, us_s, us_cpu, sfrac, us_cli, cfrac))
            print(f"rep{rep} {s:40s} {rps:9.0f} req/s | proc user {us_u:5.2f} sys {us_s:5.2f} | CPU0-1 {us_cpu:5.2f} us/req ({sfrac*100:3.0f}% busy) | client CPU4-7 {us_cli:5.2f} us/req ({cfrac*100:3.0f}%) {errs} non2xx={non2xx}", flush=True)
            p.terminate()
            p.wait()
            time.sleep(0.5)
    print()
    base = sorted(r[0] for r in rows[servers[0]])[len(rows[servers[0]]) // 2]
    for s in servers:
        rs = sorted(rows[s])
        med = rs[len(rs) // 2]
        print(f"{s:40s} median {med[0]:9.0f} req/s ({med[0] / base:.2f}x) | proc user {med[1]:.2f} sys {med[2]:.2f} | CPU0-1 {med[3]:.2f} us/req {med[4]*100:.0f}% | client {med[5]:.2f} us/req {med[6]*100:.0f}%")


main()
