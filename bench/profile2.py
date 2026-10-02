import glob, sys, subprocess, time, os, signal
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bench import *
PERF = (sorted(glob.glob("/usr/lib/linux-tools/*/perf")) or ["perf"])[-1]   # the /usr/bin/perf wrapper wants tools for the running kernel
name, srv = sys.argv[1], sys.argv[2]
s = [x for x in SCENARIOS if x["name"] == name][0]
be = Backends() if "proxy" in name else None
if be: be.start()
prefix = f"{B}/run/{srv}"
ngx = Nginx(BINS[srv], render(SERVER_CONF, prefix), prefix, SERVER_CPUS, ports=(18080, 18443))
data = f"{B}/results/extra/perf2-{name}-{srv}.data"
p = subprocess.Popen([PERF, "record", "-e", "cpu-clock", "-F", "1999", "-o", data, "--",
                      "taskset", "-c", SERVER_CPUS, ngx.binary, "-p", prefix + "/", "-c", ngx.conf],
                     stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
end = time.time() + 10
while time.time() < end and not port_open(18080): time.sleep(0.1)
time.sleep(0.5)
tool = wrk_cmd(s, s["url"], 6) if s["tool"] == "wrk" else h2load_cmd(s, s["url"], 6)
out, _, _ = client_run(tool, 60)
print((parse_wrk(out) if s["tool"] == "wrk" else parse_h2load(out) or {}).get("rps"))
pid = int(open(f"{prefix}/logs/nginx.pid").read())
os.kill(pid, signal.SIGTERM)
p.wait(timeout=30)
if be: be.stop()
def report(sort, limit):
    return subprocess.run([PERF, "report", "-i", data, "--no-children", "--sort", sort, "--stdio",
                           "--percent-limit", str(limit)], capture_output=True, text=True).stdout
dso = report("dso", 0.5)
sym = report("dso,symbol", 0.4)
open(f"{B}/results/extra/perf2-{name}-{srv}.txt", "w").write(dso + "\n" + sym)
clean = lambda t: [l.rstrip()[:140] for l in t.splitlines() if l.strip() and not l.startswith("#")]
print("DSO:", " | ".join(" ".join(l.split()) for l in clean(dso)[:6]))
print("\n".join(clean(sym)[:22]))
