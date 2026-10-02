import os, sys, subprocess, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bench import *
open(f"{B}/run/post10k.lua", "w").write(POST_LUA)
for srv in ("c", "rust"):
    prefix = f"{B}/run/{srv}"
    n = Nginx(BINS[srv], render(SERVER_CONF, prefix, quic=True), prefix, SERVER_CPUS)
    print(srv, "nginx -t (with quic):", n.test_config()[0])
be = Backends(); be.start()
try:
    for srv in ("c", "rust"):
        prefix = f"{B}/run/{srv}"
        ngx = Nginx(BINS[srv], render(SERVER_CONF, prefix, quic=True), prefix, SERVER_CPUS, ports=(18080, 18443))
        ngx.start()
        bad = []
        for s in SCENARIOS:
            if s.get("check"):
                r = curl_check(s)
                if not r["ok"]:
                    bad.append((s["name"], r))
        for name in ("proxy-h2-upstream", "grpc-pass"):
            s = [x for x in SCENARIOS if x["name"] == name][0]
            print(f"  {srv:5} {name:20} {curl_check(s)}")
        for name in ("h3-1k", "h3-100k"):
            s = [x for x in SCENARIOS if x["name"] == name][0]
            out, err, _ = client_run(oha_cmd(s, s["url"], 2), 60)
            m = parse_oha(out, 2) or {}
            print(f"  {srv:5} {name:20} rps={m.get('rps', 0):,.0f} errors={m.get('errors')} {err[-120:]}")
        s = [x for x in SCENARIOS if x["name"] == "grpc-pass"][0]
        out, _, _ = client_run(h2load_cmd(s, s["url"], 2), 60)
        print(f"  {srv:5} grpc h2load:", parse_h2load(out))
        print(f"  {srv:5} failing checks: {bad}")
        print(f"  {srv:5} error.log problems: {ngx.problems()[:5]}")
        ngx.stop(); wait_ports_free([18080, 18443])
finally:
    be.stop()
