#!/usr/bin/env python3
"""stress_h2.py <nginx binary> <io_uring|epoll> [uring writes mode]

HTTP/2 (prior knowledge, plain TCP) under stress, after
docs/IO_URING_PLAN.md §4: connection churn, clients killed mid-response,
clients that never read (send_timeout must close them on time, with the
send waiting in the kernel), idle floods, QUIT with sends in flight. After
each phase the worker's descriptors and stub_status must be back to the
baseline."""
import os
import re
import signal
import socket
import struct
import subprocess
import sys
import time

BIN, EVENTS = sys.argv[1], sys.argv[2]
WRITES = sys.argv[3] if len(sys.argv) > 3 else None
D = f"/tmp/p2-stress-{EVENTS}{'-' + WRITES if WRITES else ''}"
PORT = 18180
WWW = os.path.join(os.path.dirname(os.path.abspath(__file__)), "www")   # made by setup.sh: run from the main checkout

CONF = f"""
worker_processes 1;
error_log {D}/error.log info;
pid {D}/nginx.pid;
worker_shutdown_timeout 3s;
events {{ worker_connections 8192; }}
http {{
    access_log off;
    send_timeout 2s;
    keepalive_timeout 30s;
    server {{
        listen 127.0.0.1:{PORT};
        http2 on;
        root {WWW};
        location = /status {{ stub_status; }}
    }}
}}
"""

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def frame(ty, flags, sid, payload):
    return struct.pack(">I", len(payload))[1:] + bytes([ty, flags]) + struct.pack(">I", sid) + payload


def request(path, sid=1):
    def lit(index, value):
        # a literal field without indexing, the name indexed (RFC 7541 6.2.2)
        return bytes([index]) + bytes([len(value)]) + value

    block = b"\x82\x86" + lit(4, path) + lit(1, b"localhost")
    return frame(1, 0x5, sid, block)


def h2_client(path=None, rcvbuf=None, window=1 << 24, streams=1):
    s = socket.socket()
    if rcvbuf:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
    s.connect(("127.0.0.1", PORT))
    out = PREFACE + frame(4, 0, 0, struct.pack(">HI", 4, window)) + frame(8, 0, 0, struct.pack(">I", window))
    if path:
        for i in range(streams):
            out += request(path, 1 + 2 * i)
    s.sendall(out)
    return s


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
    the idle baseline (the status request is the one active connection)."""
    end = time.time() + timeout
    while True:
        w = workers(master)
        n = fds(w[0]) if w else -1
        st = status()
        if (n == base_fds and st == (1, 0, 1, 0)) or time.time() > end:
            break
        time.sleep(0.2)
    check(f"{what}: descriptors back", n == base_fds, f"({n} vs {base_fds})")
    check(f"{what}: stub_status back", st == (1, 0, 1, 0), f"(active, reading, writing, waiting = {st})")


def main():
    subprocess.run(["rm", "-rf", D])
    os.makedirs(f"{D}/logs")
    with open(f"{D}/nginx.conf", "w") as f:
        f.write(CONF)
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

    # 1. churn: many short connections, many streams each
    r = subprocess.run(["h2load", "-n", "40000", "-c", "100", "-m", "10", f"http://127.0.0.1:{PORT}/1k.bin"],
                       capture_output=True, text=True)
    m = re.search(r"(\d+) succeeded, (\d+) failed", r.stdout)
    check("churn: all requests succeeded", m and m.group(2) == "0", m.group(0) if m else r.stdout[-300:])
    settle(master, base, "churn")

    # 2. clients killed mid-response (1 MB responses, sends in flight)
    for _ in range(3):
        p = subprocess.Popen(["h2load", "-n", "100000", "-c", "64", "-m", "8", f"http://127.0.0.1:{PORT}/1m.bin"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.0)
        p.kill()
        p.wait()
    settle(master, base, "killed clients")

    # 3. clients that never read: the sends wait in the kernel until
    # send_timeout (2 s) closes the connections
    t0 = time.time()
    stalled = [h2_client(b"/10m.bin", rcvbuf=4096) for _ in range(50)]
    time.sleep(0.5)
    st = status()
    check("stalled: all writing", st[2] >= 50, f"(stub_status {st})")
    closed_at = []
    for s in stalled:
        s.settimeout(10)
    # read nothing until the server gives up; then the end comes
    time.sleep(2.0)
    for s in stalled:
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
            while True:
                b = s.recv(1 << 16)
                if not b:
                    break
            closed_at.append(time.time() - t0)
        except (ConnectionResetError, socket.timeout) as e:
            closed_at.append(time.time() - t0 if isinstance(e, ConnectionResetError) else 99)
        s.close()
    worst = max(closed_at)
    check("stalled: closed by send_timeout", worst < 5.0, f"(last closed after {worst:.2f} s)")
    settle(master, base, "stalled clients")

    # 4. idle flood: connections that send the preface and no request
    idle = [h2_client() for _ in range(2000)]
    time.sleep(1.0)
    st = status()
    check("idle flood: all waiting", st[3] >= 2000, f"(stub_status {st})")
    for s in idle:
        s.close()
    settle(master, base, "idle flood")

    # 5. QUIT with sends in flight (stalled clients) and idle connections:
    # the worker exits by worker_shutdown_timeout (3 s)
    stalled = [h2_client(b"/10m.bin", rcvbuf=4096) for _ in range(20)]
    idle = [h2_client() for _ in range(20)]
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
    for s in stalled + idle:
        s.close()
    ngx.wait(10)


main()
