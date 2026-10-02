"""Functional checks for the rnginx bug fixes (run against any binary)."""
import collections, os, subprocess, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bench import *

def server(binary, prefix_name):
    prefix = f"{B}/run/{prefix_name}"
    ngx = Nginx(binary, render(SERVER_CONF, prefix), prefix, SERVER_CPUS, ports=(18080, 18443))
    ngx.start()
    return ngx, prefix

def fds(ngx):
    return sum(len(os.listdir(f"/proc/{p}/fd")) for p in ngx.pids[1:3])

def check_leak(binary, name):
    ngx, _ = server(binary, name)
    try:
        out = {}
        for scen in ("proxy-1k-keepalive", "proxy-to-tls-upstream", "fastcgi-1k"):
            s = dict([x for x in SCENARIOS if x["name"] == scen][0], conns=64)
            f0 = fds(ngx)
            o, _, _ = client_run(wrk_cmd(s, s["url"], 3), 60)
            m = parse_wrk(o)
            time.sleep(0.5)
            out[scen] = (m["requests"], m["errors"], f0, fds(ngx))
        return out
    finally:
        ngx.stop(); wait_ports_free([18080, 18443])

def check_body_temp(binary, name):
    """POST bodies of several sizes; count temp files created (watch dir + log warnings)."""
    ngx, prefix = server(binary, name)
    res = {}
    try:
        import http.client
        for size in (8192, 9000, 10240, 10300, 12000, 102400):
            body = b"a" * size
            before = len([l for l in ngx.error_log().splitlines() if "buffered to a temporary file" in l])
            c = http.client.HTTPConnection("127.0.0.1", 18080)
            for i in range(20):
                c.request("POST", "/proxy/post", body=body, headers={"Content-Type": "application/octet-stream"})
                r = c.getresponse(); r.read(); assert r.status == 200, r.status
            c.close()
            time.sleep(0.2)
            after = len([l for l in ngx.error_log().splitlines() if "buffered to a temporary file" in l])
            res[size] = after - before
        return res
    finally:
        ngx.stop(); wait_ports_free([18080, 18443])

if __name__ == "__main__":
    what = sys.argv[1]
    be = Backends(); be.start()
    try:
        for label, binary in [x.split("=", 1) for x in sys.argv[2:]]:
            if what == "leak":
                for scen, (req, err, f0, f1) in check_leak(binary, label).items():
                    print(f"{label:10} {scen:22} requests={req:>7} errors={err} worker fds {f0} -> {f1}")
            elif what == "body":
                print(f"{label:10} temp-file warnings per 20 POSTs by body size: {check_body_temp(binary, label)}")
    finally:
        be.stop()
