import os, sys, time, subprocess
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bench import *
def churn(label, binary, env=None, rounds=4, mode="h2", addr="127.0.0.1:18443"):
    prefix = f"{B}/run/{label}"
    ngx = Nginx(binary, render(SERVER_CONF, prefix), prefix, SERVER_CPUS, ports=(18080, 18443), env=env)
    ngx.start()
    try:
        series = []
        base = round(mem_snapshot(ngx.pids)["total"]["Pss"] / 1024)
        for i in range(rounds):
            p = subprocess.Popen(["taskset", "-c", CLIENT_CPUS, f"{B}/bin/idleconns", "-mode", mode, "-addr", addr, "-n", "10000"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            line = p.stdout.readline().split(); time.sleep(1)
            opn = round(mem_snapshot(ngx.pids)["total"]["Pss"] / 1024)
            p.stdin.close(); p.wait(); time.sleep(2)
            series.append((opn, round(mem_snapshot(ngx.pids)["total"]["Pss"] / 1024)) if line[2] == "0" else ("FAILED", line))
        print(f"{label:22} {mode} start {base} MB; (open, closed) per round: {series}", flush=True)
    finally:
        ngx.stop(); wait_ports_free([18080, 18443])
if __name__ == "__main__":
    for spec in sys.argv[1:]:
        label, binary, *rest = spec.split("=")
        env = {"LD_PRELOAD": JEMALLOC} if rest and rest[0] == "je" else None
        churn(label, binary, env)
