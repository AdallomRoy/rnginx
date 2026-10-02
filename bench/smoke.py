import os, sys, subprocess, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bench
from bench import *
open(f"{B}/run/post10k.lua", "w").write(POST_LUA)
be = Backends(); be.start()
try:
    for srv in ("c", "rust"):
        prefix = f"{B}/run/{srv}"
        ngx = Nginx(BINS[srv], render(SERVER_CONF, prefix), prefix, SERVER_CPUS, ports=(18080, 18443))
        ngx.start()
        print(f"== {srv}: pids {ngx.pids}")
        for s in SCENARIOS:
            if s.get("check"):
                r = curl_check(s)
                print(f"  {s['name']:24} {'OK ' if r['ok'] else 'BAD'} {r.get('status')} {r.get('size')} h{r.get('http_version')} {r.get('detail') or ''}")
        for url in (f"{H}/1k.bin", f"{S}/1k.bin"):
            out = subprocess.run(["h2load", "-n", "2000", "-c", "10", "-m", "10", url], capture_output=True, text=True).stdout
            proto = [l for l in out.splitlines() if "Application protocol" in l]
            st = [l for l in out.splitlines() if l.startswith("status codes") or l.startswith("requests:")]
            print("  h2load", url, proto, st)
        out = subprocess.run(["wrk", "-t1", "-c4", "-d1s", "-H", "Connection: close", f"{S}/return"], capture_output=True, text=True).stdout
        print("  wrk tls conn-close:", " ".join(l.strip() for l in out.splitlines() if "requests in" in l or "Socket" in l or "Non-2xx" in l))
        r = subprocess.run([f"{B}/bin/idleconns", "-mode", "h2", "-addr", "127.0.0.1:18443", "-n", "50"], input="", capture_output=True, text=True)
        print("  idle h2:", r.stdout.strip(), r.stderr.strip()[:200])
        r = subprocess.run([f"{B}/bin/idleconns", "-mode", "tls", "-addr", "127.0.0.1:18443", "-n", "50"], input="", capture_output=True, text=True)
        print("  idle tls:", r.stdout.strip(), r.stderr.strip()[:200])
        print("  problems:", ngx.problems()[:5])
        ngx.stop(); wait_ports_free([18080, 18443])
    # h3 on C
    prefix = f"{B}/run/c"
    ngx = Nginx(H3_BIN, render(SERVER_CONF, prefix, quic=True), prefix, SERVER_CPUS, ports=(18080, 18443))
    ngx.start()
    out = subprocess.run([f"{B}/bin/oha", "-n", "500", "-c", "5", "--no-tui", "--output-format", "json", "--insecure", "--http-version", "3", f"{S}/1k.bin"], capture_output=True, text=True)
    print("h3 oha:", parse_oha(out.stdout), out.stderr[-300:])
    ngx.stop(); wait_ports_free([18080, 18443])
finally:
    be.stop()
