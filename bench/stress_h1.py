#!/usr/bin/env python3
"""stress_h1.py <nginx binary> <io_uring|epoll> [uring writes mode]

HTTP/1.1 and proxying under stress, after docs/IO_URING_PLAN.md §4: churn
(keepalive, Connection: close, proxied), clients that close or reset while
their proxied request waits for the backend (the client watch: 499, and the
upstream connection closed at once, as ngx_http_upstream_check_broken_connection
does), the same with a pipelined request received first, clients killed
mid-response, clients that never read (send_timeout), idle floods, QUIT
with requests in flight. After each phase the worker's descriptors and
stub_status must be back to the baseline; the backend's connections too."""
import asyncio
import os
import re
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

BIN, EVENTS = sys.argv[1], sys.argv[2]
WRITES = sys.argv[3] if len(sys.argv) > 3 else None
D = f"/tmp/stress-h1-{EVENTS}{'-' + WRITES if WRITES else ''}"
PORT, BPORT = 18182, 18183
WWW = os.path.join(os.path.dirname(os.path.abspath(__file__)), "www")   # made by setup.sh: run from the main checkout

CONF = f"""
worker_processes 1;
error_log {D}/error.log info;
pid {D}/nginx.pid;
worker_shutdown_timeout 3s;
events {{ worker_connections 8192; }}
http {{
    access_log {D}/access.log;
    send_timeout 2s;
    keepalive_timeout 30s;
    upstream backend {{
        server 127.0.0.1:{BPORT};
        keepalive 16;
        keepalive_timeout 1s;
    }}
    server {{
        listen 127.0.0.1:{PORT};
        root {WWW};
        location = /status {{ stub_status; }}
        location /proxy/ {{
            proxy_pass http://backend/;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
        }}
    }}
}}
"""

BIG = b"x" * (4 << 20)


class Backend:
    """An HTTP/1.1 backend: /slow answers after 3 s unless the peer closes
    first (counted), /big sends 4 MB, anything else a short body."""

    def __init__(self):
        self.active = 0
        self.closed_early = 0
        self.loop = None

    async def handle(self, reader, writer):
        self.active += 1
        try:
            while True:
                head = await reader.readuntil(b"\r\n\r\n")
                path = head.split(b" ", 2)[1]
                if path.startswith(b"/slow"):
                    try:
                        if await asyncio.wait_for(reader.read(1), 3.0) == b"":
                            self.closed_early += 1
                            return
                    except asyncio.TimeoutError:
                        pass
                    body = b"slow\n"
                elif path.startswith(b"/big"):
                    body = BIG
                else:
                    body = b"ok\n"
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, asyncio.LimitOverrunError):
            pass
        finally:
            self.active -= 1
            writer.close()

    def start(self):
        ready = threading.Event()

        async def main():
            self.loop = asyncio.get_running_loop()
            server = await asyncio.start_server(self.handle, "127.0.0.1", BPORT, backlog=1024)
            ready.set()
            async with server:
                await server.serve_forever()

        threading.Thread(target=lambda: asyncio.run(main()), daemon=True).start()
        ready.wait(10)


backend = Backend()


def status():
    s = socket.create_connection(("127.0.0.1", PORT))
    s.sendall(b"GET /status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    data = b""
    while True:
        b = s.recv(4096)
        if not b:
            break
        data += b
    s.close()
    text = data.decode()
    active = int(re.search(r"Active connections: (\d+)", text).group(1))
    r, w, wt = map(int, re.search(r"Reading: (\d+) Writing: (\d+) Waiting: (\d+)", text).groups())
    return active, r, w, wt


def workers(master):
    out = subprocess.run(["pgrep", "-P", str(master)], capture_output=True, text=True).stdout.split()
    return [int(p) for p in out]


def fds(pid):
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except FileNotFoundError:
        return -1


failures = []


def check(name, cond, detail=""):
    print(f"{'ok  ' if cond else 'FAIL'} {name} {detail}", flush=True)
    if not cond:
        failures.append(name)


def settle(master, base_fds, what, timeout=10):
    """Waits until the worker's descriptors and stub_status are back to
    the idle baseline (the status request is the one active connection)
    and the backend has no connection left (upstream keepalive_timeout
    1s)."""
    end = time.time() + timeout
    while True:
        w = workers(master)
        n = fds(w[0]) if w else -1
        st = status()
        if (n == base_fds and st == (1, 0, 1, 0) and backend.active == 0) or time.time() > end:
            break
        time.sleep(0.2)
    check(f"{what}: descriptors back", n == base_fds, f"({n} vs {base_fds})")
    check(f"{what}: stub_status back", st == (1, 0, 1, 0), f"(active, reading, writing, waiting = {st})")
    check(f"{what}: backend connections closed", backend.active == 0, f"({backend.active} open)")


def wrk(path, seconds=3, conns=100, headers=()):
    cmd = ["wrk", "-t2", f"-c{conns}", f"-d{seconds}s"]
    for h in headers:
        cmd += ["-H", h]
    r = subprocess.run(cmd + [f"http://127.0.0.1:{PORT}{path}"], capture_output=True, text=True)
    n = re.search(r"(\d+) requests in", r.stdout)
    bad = re.search(r"Socket errors:.*|Non-2xx or 3xx responses: \d+", r.stdout)
    return (int(n.group(1)) if n else 0), (bad.group(0) if bad else None)


def access_statuses():
    try:
        return [int(l.split('"')[2].split()[0]) for l in open(f"{D}/access.log") if l.count('"') >= 2]
    except (FileNotFoundError, IndexError, ValueError):
        return []


def request(path, extra=b""):
    s = socket.create_connection(("127.0.0.1", PORT))
    s.sendall(b"GET " + path + b" HTTP/1.1\r\nHost: localhost\r\n\r\n" + extra)
    return s


def abandon(what, n, extra=b"", reset=False):
    """n clients send a proxied request to /slow and go away while it waits
    for the backend: each gets 499, and nginx closes the upstream connection
    at once (it is not cacheable)."""
    early0, st0 = backend.closed_early, len(access_statuses())
    clients = [request(b"/proxy/slow", extra) for _ in range(n)]
    end = time.time() + 5
    while backend.active < n and time.time() < end:
        time.sleep(0.05)
    for s in clients:
        if reset:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        s.close()
    t0 = time.time()
    while backend.closed_early - early0 < n and time.time() - t0 < 5:
        time.sleep(0.02)
    took = time.time() - t0
    check(f"{what}: upstream connections closed at once", backend.closed_early - early0 == n and took < 1.5,
          f"({backend.closed_early - early0} of {n} in {took:.2f} s)")
    time.sleep(0.3)
    new = access_statuses()[st0:]
    check(f"{what}: 499 logged", new.count(499) == n, f"(statuses {sorted(set(new))}, {new.count(499)} x 499)")


def main():
    subprocess.run(["rm", "-rf", D])
    os.makedirs(f"{D}/logs")
    with open(f"{D}/nginx.conf", "w") as f:
        f.write(CONF)
    backend.start()
    env = {"PATH": "/usr/bin:/bin", "RNGINX_EVENTS": EVENTS}
    if WRITES:
        env["RNGINX_URING_WRITES"] = WRITES
    ngx = subprocess.Popen([BIN, "-p", D + "/", "-c", f"{D}/nginx.conf", "-g", "daemon off;"], env=env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    try:
        run(ngx)
    finally:
        if ngx.poll() is None:
            ngx.send_signal(signal.SIGTERM)
            try:
                ngx.wait(10)
            except subprocess.TimeoutExpired:
                ngx.kill()
    log = open(f"{D}/error.log").read()
    bad = [l for l in log.splitlines() if re.search(r"\[(alert|emerg|crit)\]", l)]
    check("no alerts in error.log", not bad, "\n".join(bad[:5]))
    print(f"{'PASS' if not failures else 'FAILED: ' + ', '.join(failures)}")
    sys.exit(1 if failures else 0)


def run(ngx):
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", PORT)).close()
            break
        except OSError:
            time.sleep(0.05)
    time.sleep(0.3)
    master = ngx.pid
    w = workers(master)
    check("one worker", len(w) == 1, str(w))
    if EVENTS == "io_uring":
        log = open(f"{D}/error.log").read()
        check("io_uring in use (no fallback notice)", "io_uring is not available" not in log)
    status()
    time.sleep(0.2)
    base = fds(w[0])
    print(f"worker {w[0]}: {base} descriptors at idle", flush=True)

    # 1. churn: keepalive, a connection per request, proxied
    for what, path, headers in (("churn keepalive", "/1k.bin", ()),
                                ("churn close", "/1k.bin", ("Connection: close",)),
                                ("churn proxied", "/proxy/1k", ())):
        n, bad = wrk(path, headers=headers)
        check(f"{what}: requests without errors", n > 1000 and bad is None, f"({n} requests{', ' + bad if bad else ''})")
    settle(master, base, "churn")

    # 2. clients that go away while their proxied request waits: the
    # watch on the client connection (C's check_broken_connection)
    abandon("closed while proxied", 50)
    abandon("reset while proxied", 50, reset=True)
    abandon("closed with a pipelined request", 50, extra=b"GET /1k.bin HTTP/1.1\r\nHost: localhost\r\n\r\n")
    settle(master, base, "abandoned requests")

    # 3. clients killed mid-response (4 MB proxied responses)
    for _ in range(3):
        p = subprocess.Popen(["wrk", "-t2", "-c64", "-d30s", f"http://127.0.0.1:{PORT}/proxy/big"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.0)
        p.kill()
        p.wait()
    settle(master, base, "killed clients")

    # 4. clients that never read: send_timeout (2 s) closes them
    t0 = time.time()
    stalled = []
    for _ in range(50):
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        s.connect(("127.0.0.1", PORT))
        s.sendall(b"GET /proxy/big HTTP/1.1\r\nHost: localhost\r\n\r\n")
        stalled.append(s)
    time.sleep(0.5)
    st = status()
    check("stalled: all writing", st[2] >= 50, f"(stub_status {st})")
    time.sleep(2.0)
    closed_at = []
    for s in stalled:
        s.settimeout(10)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
            while s.recv(1 << 16):
                pass
            closed_at.append(time.time() - t0)
        except (ConnectionResetError, socket.timeout) as e:
            closed_at.append(time.time() - t0 if isinstance(e, ConnectionResetError) else 99)
        s.close()
    worst = max(closed_at)
    check("stalled: closed by send_timeout", worst < 5.0, f"(last closed after {worst:.2f} s)")
    settle(master, base, "stalled clients")

    # 5. idle floods: connections with no request, then keepalive ones
    idle = [socket.create_connection(("127.0.0.1", PORT)) for _ in range(2000)]
    time.sleep(1.0)
    st = status()
    check("idle flood: all waiting", st[3] >= 2000, f"(stub_status {st})")
    for s in idle:
        s.close()
    settle(master, base, "idle flood")
    idle = []
    for _ in range(2000):
        s = request(b"/1k.bin")
        idle.append(s)
    for s in idle:
        s.settimeout(5)
        got = b""
        while b"\r\n\r\n" not in got or len(got) < got.index(b"\r\n\r\n") + 4 + 1024:
            got += s.recv(65536)
    time.sleep(0.5)
    st = status()
    check("keepalive flood: all waiting", st[3] >= 2000, f"(stub_status {st})")
    for s in idle:
        s.close()
    settle(master, base, "keepalive flood")

    # 6. QUIT with proxied requests in flight and idle connections: the
    # worker exits by worker_shutdown_timeout (3 s)
    busy = [request(b"/proxy/slow") for _ in range(20)]
    idle = [socket.create_connection(("127.0.0.1", PORT)) for _ in range(20)]
    time.sleep(0.5)
    w = workers(master)
    t0 = time.time()
    os.kill(master, signal.SIGQUIT)
    gone = None
    while time.time() - t0 < 10:
        if all(not os.path.exists(f"/proc/{p}") or open(f"/proc/{p}/stat").read().split()[2] == "Z" for p in w):
            gone = time.time() - t0
            break
        time.sleep(0.05)
    check("QUIT: the worker exits", gone is not None and gone < 5.0, f"({gone if gone is None else round(gone, 2)} s)")
    for s in busy + idle:
        s.close()
    ngx.wait(10)


main()
