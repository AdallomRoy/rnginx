#!/usr/bin/env python3
"""Benchmark harness: nginx C (nginx-c, -O2) vs the Rust port (rnginx).

CPU layout (8 dedicated cores, 0-7):
    0-1  nginx under test (2 workers, pinned with worker_cpu_affinity)
    2-3  backends (C nginx for proxy upstreams, Go FastCGI server, iperf3 server)
    4-7  load generators (wrk / h2load / oha / iperf3 client / idleconns)

Every run starts a fresh nginx, takes an idle memory snapshot, warms up,
then measures throughput/latency with the load tool while sampling the CPU
time (utime+stime from /proc/<pid>/stat, schedstat for ns precision) and the
memory (VmRSS/RssAnon every 0.2s, PSS from smaps_rollup every 1s) of the
nginx master and all its children.
"""
import argparse
import json
import os
import re
import resource
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time

B = os.path.dirname(os.path.abspath(__file__))
BINS = {"c": f"{B}/bin/nginx-c-O2", "rust": f"{B}/bin/nginx-rust"}
# the Rust port before the fixes of the bench-fixes branch (master 1196fa6)
BINS["rust-old"] = f"{B}/bin/nginx-rust-master-1196fa6"
# the previous master (bench fixes on 1196fa6, before the fixes branch was merged)
BINS["rust-ad69792"] = f"{B}/bin/nginx-rust-ad69792"
# experiment on master 7f01d41: request body copied with slices, read
# readiness cleared after a short read (experiment-fixes.patch)
BINS["rust-exp"] = f"{B}/bin/nginx-rust-exp"
# branch perf-fixes (worktree /home/ubuntu/rnginx-perf), copied at each step
BINS["rust-perf"] = f"{B}/bin/nginx-rust-perf"
# branch safe (/home/ubuntu/rnginx, unsafe removed), on master 7f01d41 without perf-fixes
BINS["rust-safe"] = f"{B}/bin/nginx-rust-safe"
# master after merging safe and perf-fixes (8dcf1ef)
BINS["rust-merged"] = f"{B}/bin/nginx-rust-merged"
# master after phase 1 of the performance plan (six workstreams, 85adcd1)
BINS["rust-p1"] = f"{B}/bin/nginx-rust-p1"
# any build, by path: NGX_BENCH_BIN=/path/to/nginx ... --servers custom
# (serialize runs that share the machine: flock /tmp/nginx-bench.lock python3 ...)
BINS["custom"] = os.environ.get("NGX_BENCH_BIN", BINS["rust"])
# the C build has the same module list as the Rust one, HTTP/3 included
H3_BIN = BINS["c"]
# what-if variants of the Rust port (not part of the main comparison)
BINS["rust-lto"] = f"{B}/bin/nginx-rust-lto"           # master 7f01d41, fat LTO, codegen-units=1
BINS["rust-jemalloc"] = BINS["rust"]
BINS["rust-mimalloc"] = BINS["rust"]
BINS["rust-lto-jemalloc"] = BINS["rust-lto"]
# the Phase 1 build on the distro's jemalloc 5.2 and mimalloc 2.0
BINS["rust-p1-jemalloc"] = BINS["rust-p1"]
BINS["rust-p1-mimalloc"] = BINS["rust-p1"]
# PLAN.md Phase 0 item 3 on the Phase 1 code (§1.5), all with the release
# profile's fat LTO, codegen-units=1 and panic=abort: -lto-je is the default
# build (jemalloc 5.3 for the Rust code's allocations), -lto has
# --no-default-features (glibc), -lto-je-all --features jemalloc-all, -lto-mi
# and -lto-mi-all --no-default-features --features mimalloc / mimalloc-all
# (mimalloc 3); "-all" is for the whole process, OpenSSL, PCRE2 and zlib too
BINS["rust-p0-lto"] = f"{B}/bin/nginx-rust-p0-lto"
BINS["rust-p0-lto-je"] = f"{B}/bin/nginx-rust-p0-lto-je"
BINS["rust-p0-lto-je-all"] = f"{B}/bin/nginx-rust-p0-lto-je-all"
BINS["rust-p0-lto-mi"] = f"{B}/bin/nginx-rust-p0-lto-mi"
BINS["rust-p0-lto-mi-all"] = f"{B}/bin/nginx-rust-p0-lto-mi-all"
JEMALLOC = "/usr/lib/x86_64-linux-gnu/libjemalloc.so.2"
MIMALLOC = "/usr/lib/x86_64-linux-gnu/libmimalloc.so.2"
ENVS = {"rust-jemalloc": {"LD_PRELOAD": JEMALLOC},
        "rust-mimalloc": {"LD_PRELOAD": MIMALLOC},
        "rust-lto-jemalloc": {"LD_PRELOAD": JEMALLOC},
        "rust-p1-jemalloc": {"LD_PRELOAD": JEMALLOC},
        "rust-p1-mimalloc": {"LD_PRELOAD": MIMALLOC}}
BACKEND_BIN = f"{B}/bin/nginx-c-O2"
SERVER_CPUS, BACKEND_CPUS, CLIENT_CPUS = "0,1", "2,3", "4-7"
CLK_TCK = os.sysconf("SC_CLK_TCK")
TEST_PORTS = [18080, 18443, 18444, 18445, 18090, 18091, 18493]

# --------------------------------------------------------------------------
# nginx configuration templates (@VAR@ placeholders, no Python formatting)
# --------------------------------------------------------------------------

COMMON_HTTP = r"""
    types {
        text/html                html;
        text/plain               txt;
        application/octet-stream bin;
    }
    default_type application/octet-stream;

    access_log off;
    sendfile on;
    tcp_nopush on;
    keepalive_timeout 120s;
    keepalive_requests 1000000;

    client_body_temp_path @PREFIX@/tmp/client_body;
    proxy_temp_path       @PREFIX@/tmp/proxy;
    fastcgi_temp_path     @PREFIX@/tmp/fastcgi;
    uwsgi_temp_path       @PREFIX@/tmp/uwsgi;
    scgi_temp_path        @PREFIX@/tmp/scgi;
"""

SERVER_CONF = r"""
daemon off;
master_process on;
worker_processes 2;
worker_cpu_affinity 01 10;
worker_rlimit_nofile 200000;
error_log @PREFIX@/logs/error.log warn;
pid @PREFIX@/logs/nginx.pid;

events {
    worker_connections 20000;
}

http {
@COMMON_HTTP@
    proxy_cache_path @PREFIX@/cache levels=1:2 keys_zone=bench:10m max_size=1g
                     inactive=1h use_temp_path=off;
    limit_req_zone $binary_remote_addr zone=lr:10m rate=10000000r/s;

    map $http_user_agent $ua_class {
        default                        other;
        ~*bot                          bot;
        ~*curl                         curl;
        ~*wrk                          tool;
        "~*mozilla.*(iphone|android)"  mobile;
    }

    upstream backend_ka {
        server 127.0.0.1:19080;
        keepalive 128;
    }
    upstream backend_noka {
        server 127.0.0.1:19080;
        keepalive 0;            # nginx 1.31 enables upstream keepalive by default
    }
    upstream backend_ssl_ka {
        server 127.0.0.1:19443;
        keepalive 128;
    }
    upstream fcgi_ka {
        server 127.0.0.1:19000;
        keepalive 64;
    }

    upstream backend_h2 {
        server 127.0.0.1:19081;
        keepalive 128;
    }

    upstream backend_h2s {
        server 127.0.0.1:19444;
        keepalive 128;
    }

    server {
        listen 127.0.0.1:18080 default_server backlog=4096;
        listen 127.0.0.1:18443 ssl default_server backlog=4096;
@QUIC@
        http2 on;
        server_name localhost;

        ssl_certificate     @CERTS@/ec.crt;
        ssl_certificate_key @CERTS@/ec.key;

        root @WWW@;

        location = /return {
            return 200 "hello world\n";
        }

        location /gzip/ {
            alias @WWW@/;
            gzip on;
            gzip_comp_level 1;
        }

        location /sub/ {
            alias @WWW@/;
            # rnginx skips sub_filter on sendfile-backed (file) buffers, so
            # force in-memory reads for both to compare the same work
            sendfile off;
            sub_filter "quick" "QUICK";
            sub_filter_once off;
        }

        location /subsf/ {
            alias @WWW@/;
            sub_filter "quick" "QUICK";
            sub_filter_once off;
        }

        location /log/ {
            alias @WWW@/;
            access_log @PREFIX@/logs/access.log combined buffer=64k;
        }

        location /limit/ {
            alias @WWW@/;
            limit_req zone=lr burst=100000 nodelay;
        }

        location ~ ^/regex/(?<word>[a-z]+)/(?<num>[0-9]+)$ {
            set $combo "$word:$num:$ua_class";
            if ($arg_debug) {
                return 403;
            }
            rewrite ^/regex/(.*)$ /internal/$1 last;
        }

        location /internal/ {
            internal;
            add_header X-Combo $combo;
            return 200 "$combo $uri $args\n";
        }

        location /proxy/ {
            proxy_pass http://backend_ka/;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
        }

        location /proxy-noka/ {
            proxy_pass http://backend_noka/;
            # the backend closes first (as with pre-1.31 defaults), so the
            # proxy does not pile up TIME_WAIT on its ephemeral ports
            proxy_set_header Connection close;
        }

        location /proxy-ssl/ {
            proxy_pass https://backend_ssl_ka/;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
        }

        location /cache/ {
            proxy_pass http://backend_ka/;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_cache bench;
            proxy_cache_valid 200 1h;
            add_header X-Cache $upstream_cache_status;
        }

        location /proxy-h2up/ {
            proxy_pass https://backend_h2s/;
            proxy_http_version 2;
        }

        location /proxy-h2c-up/ {
            proxy_pass http://backend_h2/;
            proxy_http_version 2;
        }

        location /grpc/ {
            grpc_pass grpcs://backend_h2s;
        }

        location /fcgi/ {
            fastcgi_pass fcgi_ka;
            fastcgi_keep_conn on;
            fastcgi_param REQUEST_METHOD  $request_method;
            fastcgi_param SCRIPT_NAME     $uri;
            fastcgi_param REQUEST_URI     $request_uri;
            fastcgi_param QUERY_STRING    $query_string;
            fastcgi_param SERVER_PROTOCOL $server_protocol;
            fastcgi_param SERVER_NAME     $server_name;
            fastcgi_param SERVER_PORT     $server_port;
            fastcgi_param REMOTE_ADDR     $remote_addr;
        }
    }

    # full-handshake servers: no session resumption (tickets and cache off)
    server {
        listen 127.0.0.1:18444 ssl backlog=4096;
        server_name localhost;
        ssl_certificate     @CERTS@/rsa.crt;
        ssl_certificate_key @CERTS@/rsa.key;
        ssl_session_tickets off;
        ssl_session_cache off;

        location = /return {
            return 200 "hello world\n";
        }
    }

    server {
        listen 127.0.0.1:18445 ssl backlog=4096;
        server_name localhost;
        ssl_certificate     @CERTS@/ec.crt;
        ssl_certificate_key @CERTS@/ec.key;
        ssl_session_tickets off;
        ssl_session_cache off;

        location = /return {
            return 200 "hello world\n";
        }
    }
}

stream {
    upstream s_backend {
        server 127.0.0.1:19080;
    }

    server {
        listen 127.0.0.1:18090 backlog=4096;
        proxy_pass s_backend;
    }

    server {
        listen 127.0.0.1:18091;
        proxy_pass 127.0.0.1:5201;
    }

    server {
        listen 127.0.0.1:18493 ssl backlog=4096;
        ssl_certificate     @CERTS@/ec.crt;
        ssl_certificate_key @CERTS@/ec.key;
        proxy_pass s_backend;
    }
}
"""

QUIC_LISTEN = "        listen 127.0.0.1:18443 quic reuseport;\n"

BACKEND_CONF = r"""
daemon off;
master_process on;
worker_processes 2;
worker_cpu_affinity 0100 1000;
worker_rlimit_nofile 200000;
error_log @PREFIX@/logs/error.log warn;
pid @PREFIX@/logs/nginx.pid;

events {
    worker_connections 20000;
}

http {
@COMMON_HTTP@
    server {
        listen 127.0.0.1:19080 default_server backlog=4096;
        listen 127.0.0.1:19443 ssl backlog=4096;
        ssl_certificate     @CERTS@/ec.crt;
        ssl_certificate_key @CERTS@/ec.key;
        root @WWW@;

        location = /return {
            return 200 "hello world\n";
        }

        location = /post {
            client_max_body_size 10m;
            return 200 "ok\n";
        }

        location = /status {
            stub_status;
        }
    }

    # HTTP/2 upstream of proxy_http_version 2 and grpc_pass: over TLS (19444), as nginx
    # sets TCP_NODELAY on TLS upstream connections only; over cleartext (19081, prior
    # knowledge) a buffered request waits for the backend's delayed ACK (Nagle)
    server {
        listen 127.0.0.1:19081 backlog=4096;
        listen 127.0.0.1:19444 ssl backlog=4096;
        http2 on;
        ssl_certificate     @CERTS@/ec.crt;
        ssl_certificate_key @CERTS@/ec.key;
        root @WWW@;

        location /grpc/ {
            alias @WWW@/;
        }
    }
}
"""

POST_LUA = """wrk.method = "POST"
wrk.body = string.rep("a", 10240)
wrk.headers["Content-Type"] = "application/octet-stream"
"""


def render(tmpl, prefix, quic=False):
    s = tmpl.replace("@COMMON_HTTP@", COMMON_HTTP)
    s = s.replace("@QUIC@", QUIC_LISTEN if quic else "")
    return (s.replace("@PREFIX@", prefix)
             .replace("@CERTS@", f"{B}/certs")
             .replace("@WWW@", f"{B}/www"))


# --------------------------------------------------------------------------
# /proc helpers
# --------------------------------------------------------------------------

def proc_stat(pid):
    with open(f"/proc/{pid}/stat") as f:
        s = f.read()
    return s[s.rindex(")") + 2:].split()


def children_of(pid):
    kids = []
    for d in os.listdir("/proc"):
        if d.isdigit():
            try:
                if int(proc_stat(int(d))[1]) == pid:
                    kids.append(int(d))
            except (OSError, ValueError, IndexError):
                pass
    return kids


def cpu_snapshot(pids):
    """Per-pid (utime_ticks, stime_ticks, sched_ns)."""
    snap = {}
    for pid in pids:
        try:
            f = proc_stat(pid)
            with open(f"/proc/{pid}/schedstat") as fh:
                ns = int(fh.read().split()[0])
            snap[pid] = (int(f[11]), int(f[12]), ns)
        except OSError:
            pass
    return snap


def cpu_delta(a, b):
    ut = st = ns = 0
    for pid, (u1, s1, n1) in b.items():
        u0, s0, n0 = a.get(pid, (0, 0, 0))
        ut += u1 - u0
        st += s1 - s0
        ns += n1 - n0
    return {"user_s": ut / CLK_TCK, "sys_s": st / CLK_TCK, "cpu_s": ns / 1e9}


def read_kv(path, keys):
    out = {}
    try:
        with open(path) as f:
            for line in f:
                k, _, v = line.partition(":")
                if k in keys:
                    out[k] = int(v.split()[0])
    except OSError:
        pass
    return out


STATUS_KEYS = {"VmRSS", "RssAnon", "RssFile", "RssShmem", "VmHWM"}
PSS_KEYS = {"Rss", "Pss", "Pss_Anon", "Pss_File", "Pss_Shmem"}


def mem_snapshot(pids):
    """Sum over pids, in KiB, plus per-process detail."""
    tot = {}
    per = {}
    for pid in pids:
        d = read_kv(f"/proc/{pid}/status", STATUS_KEYS)
        d.update(read_kv(f"/proc/{pid}/smaps_rollup", PSS_KEYS))
        per[pid] = d
        for k, v in d.items():
            tot[k] = tot.get(k, 0) + v
    return {"total": tot, "per_pid": per}


class Sampler(threading.Thread):
    def __init__(self, pids, interval=0.2):
        super().__init__(daemon=True)
        self.pids, self.interval = pids, interval
        self.ev = threading.Event()
        self.max_rss = self.max_anon = self.max_pss = 0
        self.samples = []

    def run(self):
        i = 0
        while not self.ev.is_set():
            rss = anon = 0
            for pid in self.pids:
                d = read_kv(f"/proc/{pid}/status", STATUS_KEYS)
                rss += d.get("VmRSS", 0)
                anon += d.get("RssAnon", 0)
            self.max_rss = max(self.max_rss, rss)
            self.max_anon = max(self.max_anon, anon)
            if i % 5 == 0:
                pss = sum(read_kv(f"/proc/{p}/smaps_rollup", PSS_KEYS).get("Pss", 0) for p in self.pids)
                self.max_pss = max(self.max_pss, pss)
                self.samples.append((round(time.time(), 2), rss, anon, pss))
            i += 1
            self.ev.wait(self.interval)

    def stop(self):
        self.ev.set()
        self.join()
        return {"max_rss_kb": self.max_rss, "max_anon_kb": self.max_anon,
                "max_pss_kb": self.max_pss, "samples": self.samples}


# --------------------------------------------------------------------------
# process control
# --------------------------------------------------------------------------

def port_open(port, host="127.0.0.1"):
    try:
        with socket.create_connection((host, port), timeout=0.2):
            return True
    except OSError:
        return False


def wait_ports_free(ports, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        if not any(port_open(p) for p in ports):
            return True
        time.sleep(0.1)
    return False


def reset_prefix(prefix):
    shutil.rmtree(prefix, ignore_errors=True)
    for d in ("logs", "tmp", "cache", "conf"):
        os.makedirs(f"{prefix}/{d}", exist_ok=True)


class Nginx:
    def __init__(self, binary, conf_text, prefix, cpus, workers=2, ports=(18080,), env=None):
        self.binary, self.prefix, self.cpus = binary, prefix, cpus
        self.env = dict(os.environ, **env) if env else None
        self.workers, self.ports = workers, ports
        reset_prefix(prefix)
        self.conf = f"{prefix}/conf/nginx.conf"
        with open(self.conf, "w") as f:
            f.write(conf_text)
        self.proc = None
        self.pids = []

    def test_config(self):
        r = subprocess.run([self.binary, "-t", "-p", self.prefix + "/", "-c", self.conf],
                           capture_output=True, text=True)
        return r.returncode == 0, r.stderr.strip()

    def start(self, timeout=15):
        out = open(f"{self.prefix}/logs/stdout.log", "w")
        self.proc = subprocess.Popen(
            ["taskset", "-c", self.cpus, self.binary, "-p", self.prefix + "/", "-c", self.conf],
            stdout=out, stderr=subprocess.STDOUT, start_new_session=True, env=self.env)
        end = time.time() + timeout
        while time.time() < end:
            if self.proc.poll() is not None:
                raise RuntimeError(f"nginx exited with {self.proc.returncode}: {self.error_log()[-2000:]}")
            kids = children_of(self.proc.pid)
            if len(kids) >= self.workers and all(port_open(p) for p in self.ports):
                time.sleep(0.3)
                self.pids = [self.proc.pid] + children_of(self.proc.pid)
                return self.pids
            time.sleep(0.05)
        raise RuntimeError("nginx did not become ready: " + self.error_log()[-2000:])

    def stop(self):
        if not self.proc or self.proc.poll() is not None:
            return
        self.proc.send_signal(signal.SIGTERM)
        self.forced_stop = False
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.forced_stop = True
            os.killpg(self.proc.pid, signal.SIGKILL)
            self.proc.wait()
        # make sure no worker survives
        try:
            os.killpg(self.proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def error_log(self):
        try:
            with open(f"{self.prefix}/logs/error.log", errors="replace") as f:
                return f.read()
        except OSError:
            return ""

    def problems(self):
        return [l for l in self.error_log().splitlines()
                if re.search(r"\[(alert|crit|emerg|error)\]", l)]


BACKENDS = None


class Backends:
    """Shared backends on CPUs 2-3: C nginx (HTTP+HTTPS), Go FastCGI, iperf3."""

    def __init__(self):
        self.nginx = Nginx(BACKEND_BIN, render(BACKEND_CONF, f"{B}/run/backend"), f"{B}/run/backend",
                           BACKEND_CPUS, ports=(19080, 19443, 19081, 19444))
        self.fcgi = None
        self.iperf = None

    def start(self):
        self.nginx.start()
        self.fcgi = subprocess.Popen(["taskset", "-c", BACKEND_CPUS, f"{B}/bin/fcgiserver"],
                                     env=dict(os.environ, GOMAXPROCS="2"),
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.iperf = subprocess.Popen(["taskset", "-c", BACKEND_CPUS, "iperf3", "-s", "-p", "5201"],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        end = time.time() + 10
        while time.time() < end and not (port_open(19000) and port_open(5201)):
            time.sleep(0.05)
        self.pids = self.nginx.pids + [self.fcgi.pid, self.iperf.pid]

    def restart_iperf(self):
        if self.iperf and self.iperf.poll() is None:
            self.iperf.kill()
            self.iperf.wait()
        self.iperf = subprocess.Popen(["taskset", "-c", BACKEND_CPUS, "iperf3", "-s", "-p", "5201"],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        end = time.time() + 10
        while time.time() < end and not port_open(5201):
            time.sleep(0.05)
        self.pids = self.nginx.pids + [self.fcgi.pid, self.iperf.pid]

    def alive(self):
        return (self.nginx.proc.poll() is None and self.fcgi.poll() is None
                and self.iperf.poll() is None)

    def stop(self):
        self.nginx.stop()
        for p in (self.fcgi, self.iperf):
            if p and p.poll() is None:
                p.kill()
                p.wait()


# --------------------------------------------------------------------------
# load tools
# --------------------------------------------------------------------------

UNIT_S = {"us": 1e-6, "ms": 1e-3, "s": 1.0, "m": 60.0}
UNIT_B = {"B": 1, "KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3, "TB": 1024 ** 4}


CLIENT_TIMEOUT = 60      # seconds on top of the run duration


def client_run(cmd, timeout=None):
    """Run a client command, returning (stdout, stderr, client_cpu_seconds).

    A client that does not finish within its timeout is killed and reported
    with stdout "" and stderr "TIMEOUT" (the server under test hung)."""
    r0 = resource.getrusage(resource.RUSAGE_CHILDREN)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out, err = r.stdout, r.stderr
    except subprocess.TimeoutExpired as e:
        out, err = "", f"TIMEOUT after {timeout}s: {(e.stdout or b'')[-500:]!r}"
    r1 = resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu = (r1.ru_utime - r0.ru_utime) + (r1.ru_stime - r0.ru_stime)
    return out, err, cpu


def wrk_cmd(s, url, duration):
    cmd = ["taskset", "-c", CLIENT_CPUS, "wrk", "-t", str(s.get("threads", 4)), "-c", str(s["conns"]),
           "-d", f"{duration}s", "--latency", "--timeout", "10s"]
    for h in s.get("headers", []):
        cmd += ["-H", h]
    if s.get("script"):
        cmd += ["-s", f"{B}/run/{s['script']}"]
    return cmd + [url]


def parse_wrk(out):
    res = {}
    m = re.search(r"(\d+) requests in ([\d.]+)(us|ms|s|m), ([\d.]+)(B|KB|MB|GB|TB) read", out)
    if not m:
        return None
    res["requests"] = int(m.group(1))
    res["duration_s"] = float(m.group(2)) * UNIT_S[m.group(3)]
    res["bytes"] = float(m.group(4)) * UNIT_B[m.group(5)]
    res["rps"] = float(re.search(r"Requests/sec:\s+([\d.]+)", out).group(1))
    m = re.search(r"Transfer/sec:\s+([\d.]+)(B|KB|MB|GB|TB)", out)
    res["bytes_per_s"] = float(m.group(1)) * UNIT_B[m.group(2)]
    lat = {}
    for p, v, u in re.findall(r"^\s+(50|75|90|99)%\s+([\d.]+)(us|ms|s)\s*$", out, re.M):
        lat[f"p{p}"] = float(v) * UNIT_S[u] * 1000.0
    res["latency_ms"] = lat
    m = re.search(r"Latency\s+([\d.]+)(us|ms|s)", out)
    if m:
        lat["mean"] = float(m.group(1)) * UNIT_S[m.group(2)] * 1000.0
    err = 0
    m = re.search(r"Socket errors: connect (\d+), read (\d+), write (\d+), timeout (\d+)", out)
    if m:
        res["socket_errors"] = dict(zip(("connect", "read", "write", "timeout"), map(int, m.groups())))
        err += sum(map(int, m.groups()))
    m = re.search(r"Non-2xx or 3xx responses: (\d+)", out)
    res["non2xx"] = int(m.group(1)) if m else 0
    res["errors"] = err + res["non2xx"]
    return res


def h2load_cmd(s, url, duration, logfile=None):
    cmd = ["taskset", "-c", CLIENT_CPUS, "h2load", "-t", str(s.get("threads", 4)), "-c", str(s["conns"]),
           "-m", str(s.get("streams", 1)), "-D", str(duration)]
    if s.get("h1"):
        cmd.append("--h1")
    if logfile:
        cmd += ["--log-file", logfile]
    return cmd + [url]


def parse_h2load(out, logfile=None):
    m = re.search(r"finished in ([\d.]+)(s|ms), ([\d.]+) req/s, ([\d.]+)(B|KB|MB|GB)/s", out)
    if not m:
        return None
    res = {"duration_s": float(m.group(1)) * UNIT_S[m.group(2)], "rps": float(m.group(3)),
           "bytes_per_s": float(m.group(4)) * UNIT_B[m.group(5)]}
    m = re.search(r"requests: (\d+) total, (\d+) started, (\d+) done, (\d+) succeeded, (\d+) failed, "
                  r"(\d+) errored, (\d+) timeout", out)
    total, started, done, ok, failed, errored, tmo = map(int, m.groups())
    res["requests"] = ok
    m = re.search(r"status codes: (\d+) 2xx, (\d+) 3xx, (\d+) 4xx, (\d+) 5xx", out)
    s2, s3, s4, s5 = map(int, m.groups())
    res["non2xx"] = s3 + s4 + s5
    res["errors"] = failed + errored + tmo + res["non2xx"]
    m = re.search(r"Application protocol: (\S+)", out)
    res["protocol"] = m.group(1) if m else None
    m = re.search(r"time for request:\s+([\d.]+)(us|ms|s)\s+([\d.]+)(us|ms|s)\s+([\d.]+)(us|ms|s)", out)
    lat = {}
    if m:
        lat["mean"] = float(m.group(5)) * UNIT_S[m.group(6)] * 1000.0
    if logfile and os.path.exists(logfile):
        durs = []
        with open(logfile) as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3:
                    durs.append(int(parts[2]))
        os.unlink(logfile)
        if durs:
            durs.sort()
            n = len(durs)
            for p in (50, 75, 90, 99):
                lat[f"p{p}"] = durs[min(n - 1, int(n * p / 100))] / 1000.0
    res["latency_ms"] = lat
    return res


def oha_cmd(s, url, duration, rate=None):
    oha = f"{B}/bin/oha-h3" if s.get("http_version") == "3" else f"{B}/bin/oha"   # h3 needs a feature build
    cmd = ["taskset", "-c", CLIENT_CPUS, oha, "-z", f"{duration}s", "-c", str(s["conns"]),
           "--no-tui", "--output-format", "json", "--insecure"]
    if s.get("http_version"):
        cmd += ["--http-version", s["http_version"]]
    if s.get("parallel"):
        cmd += ["-p", str(s["parallel"])]
    if rate:
        cmd += ["-q", str(rate), "--latency-correction"]
    cmd += s.get("oha_extra", [])
    return cmd + [url]


def parse_oha(out, cfg_duration=None):
    try:
        d = json.loads(out)
    except json.JSONDecodeError:
        return None
    summ = d["summary"]
    codes = d.get("statusCodeDistribution", {})
    ok = sum(v for k, v in codes.items() if k.startswith("2"))
    # requests still in flight when the -z deadline fires are not failures
    errs = sum(v for k, v in d.get("errorDistribution", {}).items() if k != "aborted due to deadline")
    if cfg_duration and summ["total"] > cfg_duration + 2:
        # oha's HTTP/3 client keeps running ~30s past the deadline (QUIC
        # connection teardown) and divides by that; use the configured window
        summ["total"] = float(cfg_duration)
        summ["requestsPerSec"] = ok / cfg_duration
        summ["sizePerSec"] = (summ.get("totalData") or 0) / cfg_duration
    pct = d.get("latencyPercentiles", {})
    lat = {"mean": (summ.get("average") or 0) * 1000.0}
    for k in ("p50", "p75", "p90", "p99", "p99.9"):
        if pct.get(k) is not None:
            lat[k] = pct[k] * 1000.0
    return {"rps": summ["requestsPerSec"], "requests": ok, "duration_s": summ["total"],
            "bytes_per_s": summ.get("sizePerSec") or 0, "non2xx": sum(codes.values()) - ok,
            "errors": errs + sum(codes.values()) - ok, "latency_ms": lat,
            "error_detail": d.get("errorDistribution", {})}


# --------------------------------------------------------------------------
# scenarios
# --------------------------------------------------------------------------

H = "http://127.0.0.1:18080"
S = "https://127.0.0.1:18443"

SCENARIOS = [
    # --- HTTP/1.1 cleartext ------------------------------------------------
    dict(name="h1-return", group="HTTP/1.1", tool="wrk", url=f"{H}/return", conns=256,
         desc='`return 200` (12 B body, no file I/O), keep-alive', check=dict(size=12)),
    dict(name="h1-static-1k", group="HTTP/1.1", tool="wrk", url=f"{H}/1k.bin", conns=256,
         desc="static 1 KB file, keep-alive", check=dict(size=1024)),
    dict(name="h1-static-100k", group="HTTP/1.1", tool="wrk", url=f"{H}/100k.bin", conns=64,
         desc="static 100 KB file (sendfile)", check=dict(size=102400)),
    dict(name="h1-static-1m", group="HTTP/1.1", tool="wrk", url=f"{H}/1m.bin", conns=32,
         desc="static 1 MB file (sendfile)", check=dict(size=1048576)),
    dict(name="h1-conn-close", group="HTTP/1.1", tool="wrk", url=f"{H}/1k.bin", conns=64,
         headers=["Connection: close"], desc="1 KB, new TCP connection per request",
         check=dict(size=1024)),
    dict(name="h1-2k-conns", group="HTTP/1.1", tool="wrk", url=f"{H}/1k.bin", conns=2000,
         desc="1 KB, 2000 concurrent keep-alive connections", check=dict(size=1024)),
    dict(name="h1-regex-rewrite", group="HTTP/1.1", tool="wrk", url=f"{H}/regex/hello/12345?x=1",
         conns=256, desc="regex location + map + set + if + rewrite last + add_header + vars",
         check=dict(header="X-Combo")),
    dict(name="h1-access-log", group="HTTP/1.1", tool="wrk", url=f"{H}/log/1k.bin", conns=256,
         desc="static 1 KB with buffered combined access_log", check=dict(size=1024)),
    dict(name="h1-gzip", group="HTTP/1.1", tool="wrk", url=f"{H}/gzip/100k.html", conns=64,
         headers=["Accept-Encoding: gzip"], desc="100 KB HTML gzip-compressed on the fly (level 1)",
         check=dict(header="Content-Encoding: gzip", args=["-H", "Accept-Encoding: gzip"])),
    dict(name="h1-sub-filter", group="HTTP/1.1", tool="wrk", url=f"{H}/sub/100k.html", conns=64,
         desc="100 KB HTML through sub_filter (424 replacements), sendfile off",
         check=dict(size=102575, body_has="QUICK", body_lacks="quick")),
    dict(name="h1-sub-filter-sendfile", group="HTTP/1.1", tool="wrk", url=f"{H}/subsf/100k.html", conns=64,
         desc="100 KB HTML through sub_filter (424 replacements), sendfile on (default)",
         check=dict(size=102575, body_has="QUICK", body_lacks="quick")),
    dict(name="h1-limit-req", group="HTTP/1.1", tool="wrk", url=f"{H}/limit/1k.bin", conns=256,
         desc="static 1 KB through limit_req (shared-memory zone, never rejects)",
         check=dict(size=1024)),
    # --- TLS ----------------------------------------------------------------
    dict(name="tls-h1-1k", group="HTTPS", tool="wrk", url=f"{S}/1k.bin", conns=256,
         desc="HTTPS 1 KB, keep-alive (ECDSA P-256, TLS 1.3)", check=dict(size=1024, args=["-k"])),
    dict(name="tls-h1-1m", group="HTTPS", tool="wrk", url=f"{S}/1m.bin", conns=32,
         desc="HTTPS 1 MB, keep-alive (bulk encryption)", check=dict(size=1048576, args=["-k"])),
    dict(name="tls-resume-ecdsa", group="HTTPS", tool="wrk", url=f"{S}/return", conns=64,
         headers=["Connection: close"], desc="new TLS connection per request, TLS 1.3 session resumption",
         check=dict(size=12, args=["-k"])),
    dict(name="tls-handshake-ecdsa", group="HTTPS", tool="wrk", url="https://127.0.0.1:18445/return",
         conns=64, headers=["Connection: close"], desc="full TLS 1.3 handshake per request, ECDSA P-256",
         check=dict(size=12, args=["-k"])),
    dict(name="tls-handshake-rsa", group="HTTPS", tool="wrk", url="https://127.0.0.1:18444/return",
         conns=64, headers=["Connection: close"], desc="full TLS 1.3 handshake per request, RSA 2048",
         check=dict(size=12, args=["-k"])),
    # --- HTTP/2 -------------------------------------------------------------
    dict(name="h2-tls-1k", group="HTTP/2", tool="h2load", url=f"{S}/1k.bin", conns=64, streams=16,
         desc="h2 over TLS, 1 KB, 64 conns x 16 streams", check=dict(size=1024, args=["-k", "--http2"])),
    dict(name="h2-tls-100k", group="HTTP/2", tool="h2load", url=f"{S}/100k.bin", conns=32, streams=8,
         desc="h2 over TLS, 100 KB, 32 conns x 8 streams",
         check=dict(size=102400, args=["-k", "--http2"])),
    dict(name="h2c-1k", group="HTTP/2", tool="h2load", url=f"{H}/1k.bin", conns=64, streams=16,
         desc="h2c (cleartext, prior knowledge), 1 KB, 64 conns x 16 streams",
         check=dict(size=1024, args=["--http2-prior-knowledge"])),
    dict(name="h2-tls-return", group="HTTP/2", tool="h2load", url=f"{S}/return", conns=16, streams=100,
         desc="h2 over TLS, `return 200`, 16 conns x 100 streams",
         check=dict(size=12, args=["-k", "--http2"])),
    # --- HTTP/3 (C only: not ported to Rust) --------------------------------
    dict(name="h3-1k", group="HTTP/3", tool="oha", http_version="3", url=f"{S}/1k.bin", conns=32,
         quic=True, desc="HTTP/3 (QUIC) 1 KB, 32 conns"),
    dict(name="h3-100k", group="HTTP/3", tool="oha", http_version="3", url=f"{S}/100k.bin", conns=32,
         quic=True, desc="HTTP/3 (QUIC) 100 KB, 32 conns"),
    # --- reverse proxy ------------------------------------------------------
    dict(name="proxy-1k-keepalive", group="Proxy", tool="wrk", url=f"{H}/proxy/1k.bin", conns=256,
         desc="proxy_pass, 1 KB, upstream keepalive", check=dict(size=1024)),
    dict(name="proxy-1k-no-keepalive", group="Proxy", tool="wrk", url=f"{H}/proxy-noka/1k.bin",
         conns=256, desc="proxy_pass, 1 KB, new upstream connection per request (keepalive 0, Connection: close)",
         check=dict(size=1024)),
    dict(name="proxy-100k", group="Proxy", tool="wrk", url=f"{H}/proxy/100k.bin", conns=64,
         desc="proxy_pass, 100 KB, buffering on", check=dict(size=102400)),
    dict(name="proxy-1m", group="Proxy", tool="wrk", url=f"{H}/proxy/1m.bin", conns=32,
         desc="proxy_pass, 1 MB, buffering on", check=dict(size=1048576)),
    dict(name="proxy-post-10k", group="Proxy", tool="wrk", url=f"{H}/proxy/post", conns=128,
         script="post10k.lua", desc="POST 10 KB request body through proxy_pass",
         check=dict(size=3, args=["-X", "POST", "--data-binary", "@" + f"{B}/www/1k.bin"])),
    dict(name="proxy-tls-terminate", group="Proxy", tool="wrk", url=f"{S}/proxy/1k.bin", conns=256,
         desc="HTTPS in, HTTP keepalive upstream, 1 KB", check=dict(size=1024, args=["-k"])),
    dict(name="proxy-to-tls-upstream", group="Proxy", tool="wrk", url=f"{H}/proxy-ssl/1k.bin",
         conns=256, desc="HTTP in, HTTPS keepalive upstream (proxy_ssl), 1 KB", check=dict(size=1024)),
    dict(name="proxy-h2-frontend", group="Proxy", tool="h2load", url=f"{S}/proxy/1k.bin", conns=64,
         streams=16, desc="h2 over TLS in, HTTP/1.1 keepalive upstream, 1 KB",
         check=dict(size=1024, args=["-k", "--http2"])),
    dict(name="proxy-cache-hit", group="Proxy", tool="wrk", url=f"{H}/cache/1k.bin", conns=256,
         desc="proxy_cache HIT, 1 KB (served from cache file)",
         check=dict(size=1024), postcheck=dict(header="X-Cache: HIT")),
    dict(name="proxy-h2-upstream", group="Proxy", tool="wrk", url=f"{H}/proxy-h2up/1k.bin", conns=128,
         desc="proxy_pass with proxy_http_version 2 to an HTTP/2 TLS upstream, keepalive, 1 KB", check=dict(size=1024)),
    dict(name="grpc-pass", group="Proxy", tool="h2load", url=f"{S}/grpc/1k.bin", conns=16, streams=8,
         desc="h2/TLS in (16 conns x 8 streams), grpc_pass to an HTTP/2 TLS upstream, keepalive, 1 KB",
         check=dict(size=1024, args=["-k", "--http2"])),
    dict(name="fastcgi-1k", group="Proxy", tool="wrk", url=f"{H}/fcgi/x", conns=128,
         desc="fastcgi_pass to Go FastCGI server, keepalive, 1 KB", check=dict(size=1024)),
    # --- stream (L4) --------------------------------------------------------
    dict(name="stream-tcp-proxy", group="Stream", tool="wrk", url="http://127.0.0.1:18090/1k.bin",
         conns=256, desc="stream proxy_pass (TCP relay) to HTTP backend, 1 KB keep-alive",
         check=dict(size=1024)),
    dict(name="stream-tls-terminate", group="Stream", tool="wrk", url="https://127.0.0.1:18493/1k.bin",
         conns=256, desc="stream ssl termination + TCP relay, 1 KB keep-alive",
         check=dict(size=1024, args=["-k"])),
    dict(name="stream-bulk-iperf", group="Stream", tool="iperf3", port=18091,
         desc="iperf3 single TCP stream through stream proxy (bulk relay)"),
    # --- fixed-rate latency / CPU efficiency ---------------------------------
    dict(name="rate-h1-static-1k", group="Fixed rate", tool="oha", url=f"{H}/1k.bin", conns=50,
         rate=10000, desc="10k req/s fixed, static 1 KB, 50 conns (latency at equal load)"),
    dict(name="rate-tls-1k", group="Fixed rate", tool="oha", url=f"{S}/1k.bin", conns=50, rate=10000,
         desc="10k req/s fixed, HTTPS 1 KB, 50 conns"),
    dict(name="rate-h2-1k", group="Fixed rate", tool="oha", url=f"{S}/1k.bin", conns=10, parallel=10,
         http_version="2", rate=10000, desc="10k req/s fixed, h2 1 KB, 10 conns x 10 streams"),
    dict(name="rate-proxy-1k", group="Fixed rate", tool="oha", url=f"{H}/proxy/1k.bin", conns=50,
         rate=10000, desc="10k req/s fixed, proxy_pass keepalive, 1 KB"),
    # --- idle connection memory ---------------------------------------------
    dict(name="idle-10k-h1", group="Memory", tool="idle", mode="h1", addr="127.0.0.1:18080", n=10000,
         desc="10,000 idle HTTP/1.1 keep-alive connections"),
    dict(name="idle-10k-tls", group="Memory", tool="idle", mode="tls", addr="127.0.0.1:18443", n=10000,
         desc="10,000 idle HTTPS keep-alive connections"),
    dict(name="idle-10k-h2", group="Memory", tool="idle", mode="h2", addr="127.0.0.1:18443", n=10000,
         desc="10,000 idle HTTP/2 (TLS) connections"),
]


def curl_check(s):
    c = s.get("check")
    if not c:
        return {"ok": True}
    cmd = ["curl", "-s", "-o", "/dev/null", "-D", "-", "-w", "\n__%{http_code} %{size_download} %{http_version}",
           "--max-time", "10"] + c.get("args", []) + [s["url"]]
    r = subprocess.run(cmd, capture_output=True, text=True)
    m = re.search(r"__(\d+) (\d+) (\S+)\s*$", r.stdout)
    if not m:
        return {"ok": False, "detail": f"curl failed: {r.stdout[-300:]} {r.stderr[-300:]}"}
    code, size, ver = int(m.group(1)), int(m.group(2)), m.group(3)
    ok = code == 200
    if "size" in c and size != c["size"]:
        ok = False
    if "body_has" in c or "body_lacks" in c:
        body = subprocess.run(["curl", "-s", "--max-time", "10"] + c.get("args", []) + [s["url"]],
                              capture_output=True).stdout
        if c.get("body_has") and c["body_has"].encode() not in body:
            ok = False
        if c.get("body_lacks") and c["body_lacks"].encode() in body:
            ok = False
    if "header" in c and c["header"].lower() not in r.stdout.lower():
        ok = False
    return {"ok": ok, "status": code, "size": size, "http_version": ver,
            "detail": None if ok else r.stdout[-600:]}


def postcheck(s):
    pc = s.get("postcheck")
    if not pc:
        return {"ok": True}
    return curl_check(dict(s, check=dict(s.get("check", {}), **pc)))


def run_load(s, duration, warmup):
    """Warm up then measure; return (metrics, client_cpu_s, raw_output)."""
    tool = s["tool"]
    tmo = duration + CLIENT_TIMEOUT
    wtmo = warmup + CLIENT_TIMEOUT
    if tool == "wrk":
        if warmup:
            client_run(wrk_cmd(s, s["url"], warmup), wtmo)
        out, err, ccpu = client_run(wrk_cmd(s, s["url"], duration), tmo)
        return parse_wrk(out), ccpu, out + err
    if tool == "h2load":
        if warmup:
            client_run(h2load_cmd(s, s["url"], warmup), wtmo)
        log = f"{B}/run/h2load.log"
        out, err, ccpu = client_run(h2load_cmd(s, s["url"], duration, log), tmo)
        return parse_h2load(out, log), ccpu, out + err
    if tool == "oha":
        if warmup:
            client_run(oha_cmd(s, s["url"], warmup, s.get("rate")), wtmo)
        out, err, ccpu = client_run(oha_cmd(s, s["url"], duration, s.get("rate")), tmo)
        res = parse_oha(out, duration)
        return res, ccpu, ("" if res else out) + err
    if tool == "iperf3":
        if BACKENDS:
            BACKENDS.restart_iperf()
        base = ["taskset", "-c", CLIENT_CPUS, "iperf3", "-c", "127.0.0.1", "-p", str(s["port"]), "-J"]
        if warmup:
            client_run(base + ["-t", str(warmup)], wtmo)
            time.sleep(0.5)
        out, err, ccpu = client_run(base + ["-t", str(duration)], tmo)
        try:
            d = json.loads(out)
            recv = d["end"]["sum_received"]
            res = {"bytes_per_s": recv["bits_per_second"] / 8, "bytes": recv["bytes"],
                   "duration_s": recv["seconds"], "rps": None, "requests": None, "errors": 0,
                   "gbit_per_s": recv["bits_per_second"] / 1e9, "latency_ms": {}}
        except (json.JSONDecodeError, KeyError) as e:
            res = None
            err += f" iperf parse error {e}"
        return res, ccpu, ("" if res else out) + err
    raise ValueError(tool)


def run_idle(s, ngx):
    """Open N idle connections, report memory delta per connection."""
    pids = ngx.pids
    before = mem_snapshot(pids)
    p = subprocess.Popen(["taskset", "-c", CLIENT_CPUS, f"{B}/bin/idleconns", "-mode", s["mode"],
                          "-addr", s["addr"], "-n", str(s["n"])],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    t0 = time.time()
    line = p.stdout.readline().split()
    t_open = time.time() - t0
    ok = int(line[1]) if len(line) == 3 else 0
    failed = int(line[2]) if len(line) == 3 else s["n"]
    time.sleep(3)
    after = mem_snapshot(pids)
    p.stdin.close()
    err = p.stderr.read()
    p.wait()
    time.sleep(1)
    closed = mem_snapshot(pids)
    d_pss = after["total"].get("Pss", 0) - before["total"].get("Pss", 0)
    d_anon = after["total"].get("RssAnon", 0) - before["total"].get("RssAnon", 0)
    return {
        "connections": ok, "failed": failed, "open_time_s": t_open, "stderr": err.strip()[:500],
        "mem_before": before["total"], "mem_after": after["total"], "mem_after_close": closed["total"],
        "pss_per_conn_kb": d_pss / ok if ok else None,
        "anon_per_conn_kb": d_anon / ok if ok else None,
        "errors": failed,
    }


def backend_accepts():
    """Connections accepted so far by the backend nginx (stub_status)."""
    try:
        out = subprocess.run(["curl", "-s", "--max-time", "5", "http://127.0.0.1:19080/status"],
                             capture_output=True, text=True).stdout
        return int(out.splitlines()[2].split()[0])
    except (IndexError, ValueError):
        return None


def worker_fds(pids):
    """Open descriptors of the given processes (a leak shows as growth)."""
    n = 0
    for p in pids:
        try:
            n += len(os.listdir(f"/proc/{p}/fd"))
        except OSError:
            pass
    return n


def run_one(s, server, args, backends):
    prefix = f"{B}/run/{server}"
    binary = H3_BIN if s.get("quic") and server == "c" else BINS[server]
    ngx = Nginx(binary, render(SERVER_CONF, prefix, quic=s.get("quic", False)), prefix,
                SERVER_CPUS, ports=(18080, 18443), env=ENVS.get(server))
    rec = {"scenario": s["name"], "server": server, "ts": time.time()}
    if backends and not backends.alive():
        raise RuntimeError("backend died")
    try:
        ngx.start()
    except RuntimeError as e:
        rec["fatal"] = str(e)
        ngx.stop()
        return rec
    try:
        rec["workers"] = len(ngx.pids) - 1
        rec["mem_idle"] = mem_snapshot(ngx.pids)["total"]
        if s["tool"] == "idle":
            rec["idle"] = run_idle(s, ngx)
            rec["metrics"] = {"errors": rec["idle"]["errors"]}
        else:
            rec["check"] = curl_check(s)
            sampler = Sampler(ngx.pids)
            # warm-up runs outside the measured window
            warm = args.warmup
            if warm:
                run_load(dict(s), warm, 0)
            if s.get("postcheck"):
                rec["postcheck"] = postcheck(s)
            a0 = backend_accepts()
            c0 = cpu_snapshot(ngx.pids)
            b0 = cpu_snapshot(backends.pids) if backends else {}
            t0 = time.time()
            sampler.start()
            metrics, ccpu, raw = run_load(s, args.duration, 0)
            t1 = time.time()
            mem = sampler.stop()
            c1 = cpu_snapshot(ngx.pids)
            b1 = cpu_snapshot(backends.pids) if backends else {}
            a1 = backend_accepts()
            # minus the 1 connection each stub_status poll itself costs
            rec["backend_accepts"] = (a1 - a0 - 1) if a0 is not None and a1 is not None else None
            rec["wall_s"] = t1 - t0
            rec["metrics"] = metrics
            rec["cpu"] = cpu_delta(c0, c1)
            rec["backend_cpu"] = cpu_delta(b0, b1) if backends else None
            rec["client_cpu_s"] = ccpu
            rec["mem_load"] = mem
            rec["mem_end"] = mem_snapshot(ngx.pids)["total"]
            rec["worker_fds_end"] = worker_fds(ngx.pids[1:])
            time.sleep(1.0)
            i0 = cpu_snapshot(ngx.pids)
            time.sleep(1.0)
            rec["post_idle_cpu_pct"] = 100.0 * cpu_delta(i0, cpu_snapshot(ngx.pids))["cpu_s"]
            if not metrics:
                rec["raw"] = raw[-3000:]
            dur = (metrics or {}).get("duration_s") or rec["wall_s"]
            rec["cpu"]["util_pct"] = 100.0 * rec["cpu"]["cpu_s"] / max(dur, 1e-9)
            if metrics and metrics.get("requests"):
                rec["cpu"]["us_per_req"] = 1e6 * rec["cpu"]["cpu_s"] / metrics["requests"]
            if metrics and metrics.get("bytes_per_s"):
                total_bytes = metrics["bytes_per_s"] * dur
                rec["cpu"]["s_per_gb"] = rec["cpu"]["cpu_s"] / (total_bytes / 1e9) if total_bytes else None
        rec["problems"] = ngx.problems()[:20]
    finally:
        ngx.stop()
        rec["forced_stop"] = getattr(ngx, "forced_stop", False)
        wait_ports_free([18080, 18443])
    return rec


def summarize_line(rec):
    if rec.get("fatal"):
        return f"FATAL {rec['fatal'][:200]}"
    m = rec.get("metrics") or {}
    if rec.get("idle"):
        i = rec["idle"]
        return (f"conns={i['connections']} failed={i['failed']} pss/conn={i['pss_per_conn_kb']:.2f}KB "
                f"anon/conn={i['anon_per_conn_kb']:.2f}KB")
    cpu = rec.get("cpu", {})
    lat = m.get("latency_ms", {})
    rps = m.get("rps")
    parts = []
    if rps:
        parts.append(f"rps={rps:,.0f}")
    if m.get("bytes_per_s"):
        parts.append(f"{m['bytes_per_s'] * 8 / 1e9:.2f}Gbit/s")
    if lat.get("p99") is not None:
        parts.append(f"p50={lat.get('p50', 0):.2f}ms p99={lat['p99']:.2f}ms")
    parts.append(f"cpu={cpu.get('util_pct', 0):.0f}%")
    if cpu.get("us_per_req"):
        parts.append(f"{cpu['us_per_req']:.1f}us/req")
    parts.append(f"pss_max={rec.get('mem_load', {}).get('max_pss_kb', 0) / 1024:.1f}MB")
    parts.append(f"err={m.get('errors')}")
    if rec.get("worker_fds_end") is not None:
        parts.append(f"fds={rec['worker_fds_end']}")
    if rec.get("check") and not rec["check"].get("ok"):
        parts.append(f"CHECK-FAIL {rec['check']}")
    if rec.get("postcheck") and not rec["postcheck"].get("ok"):
        parts.append(f"POSTCHECK-FAIL {rec['postcheck']}")
    if rec.get("problems"):
        parts.append(f"errlog={len(rec['problems'])}")
    if (rec.get("post_idle_cpu_pct") or 0) > 10:
        parts.append(f"SPIN-AFTER-LOAD={rec['post_idle_cpu_pct']:.0f}%")
    if rec.get("forced_stop"):
        parts.append("FORCED-STOP")
    if not m.get("rps") and not m.get("bytes_per_s"):
        parts.append(f"NO-RESULT {(rec.get('raw') or '')[-200:]!r}")
    return " ".join(parts)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", help="comma-separated scenario names or groups (substring match)")
    ap.add_argument("--servers", default="c,rust")
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--duration", type=int, default=10)
    ap.add_argument("--warmup", type=int, default=3)
    ap.add_argument("--out", default=None)
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()

    if args.list:
        for s in SCENARIOS:
            print(f"{s['group']:12} {s['name']:24} {s['desc']}")
        return

    with open(f"{B}/run/post10k.lua", "w") as f:
        f.write(POST_LUA)

    scen = SCENARIOS
    if args.only:
        keys = args.only.split(",")
        scen = [s for s in SCENARIOS if any(k == s["name"] or k == s["group"] or
                                            (k.endswith("*") and s["name"].startswith(k[:-1])) for k in keys)]
    servers = args.servers.split(",")
    out = args.out or f"{B}/results/run-{time.strftime('%Y%m%d-%H%M%S')}.jsonl"
    print(f"results -> {out}", flush=True)

    if not wait_ports_free(TEST_PORTS + [19080, 19443, 19081, 19444, 19000, 5201], timeout=2):
        sys.exit("ports busy: stop other nginx instances first")
    global BACKENDS
    backends = BACKENDS = Backends()
    backends.start()
    try:
        with open(out, "a") as fo:
            for s in scen:
                order = [x for x in servers if x in s.get("servers", servers)]
                for rep in range(args.reps):
                    seq = order if rep % 2 == 0 else list(reversed(order))
                    for server in seq:
                        rec = run_one(s, server, args, backends)
                        rec["rep"] = rep
                        rec["duration_cfg"] = args.duration
                        fo.write(json.dumps(rec) + "\n")
                        fo.flush()
                        print(f"{s['name']:24} {server:5} rep{rep} {summarize_line(rec)}", flush=True)
    finally:
        backends.stop()


if __name__ == "__main__":
    main()
