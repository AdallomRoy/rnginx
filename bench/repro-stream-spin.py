import os, sys, subprocess, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bench import *
iperf = subprocess.Popen(["taskset", "-c", BACKEND_CPUS, "iperf3", "-s", "-p", "5201"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(0.5)
prefix = f"{B}/run/rust"
ngx = Nginx(BINS["rust"], render(SERVER_CONF, prefix), prefix, SERVER_CPUS, ports=(18080, 18443))
ngx.start()
try:
    cl = subprocess.Popen(["taskset", "-c", CLIENT_CPUS, "iperf3", "-c", "127.0.0.1", "-p", "18091", "-t", "4"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(1.5)
    for pid in ngx.pids[1:3]:
        st = open(f"/proc/{pid}/stat").read().split(") ")[1].split()
        print(f"worker {pid}: utime={st[11]} stime={st[12]}")
        out = subprocess.run(["sudo", "timeout", "1.5", "strace", "-c", "-p", str(pid)], capture_output=True, text=True)
        print("  strace -c:", "\n".join(out.stderr.splitlines()[-12:]))
    out = subprocess.run(["sudo", "gdb", "-p", str(ngx.pids[1]), "-batch", "-ex", "bt 25"], capture_output=True, text=True)
    print("gdb bt worker1:\n", "\n".join(l for l in out.stdout.splitlines() if l.startswith("#"))[:4000])
    out = subprocess.run(["sudo", "gdb", "-p", str(ngx.pids[2]), "-batch", "-ex", "bt 25"], capture_output=True, text=True)
    print("gdb bt worker2:\n", "\n".join(l for l in out.stdout.splitlines() if l.startswith("#"))[:4000])
    print(cl.communicate(timeout=60)[0][-600:])
finally:
    ngx.stop()
    iperf.kill()
