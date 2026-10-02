#!/usr/bin/env python3
"""Turn bench.py JSONL results into Markdown tables (medians over reps)."""
import json
import math
import statistics
import sys
from collections import defaultdict

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from bench import SCENARIOS  # noqa: E402

SCN = {s["name"]: s for s in SCENARIOS}
ORDER = [s["name"] for s in SCENARIOS]


def load(paths):
    """Records from all files; a scenario re-run in a later file replaces
    that scenario's records from earlier files."""
    per_file = []
    for p in paths:
        with open(p) as f:
            per_file.append([json.loads(l) for l in f if l.strip()])
    owner = {}
    for i, recs in enumerate(per_file):
        for r in recs:
            owner[r["scenario"]] = i
    return [r for i, recs in enumerate(per_file) for r in recs if owner[r["scenario"]] == i]


def invalid_reason(r):
    if r.get("fatal"):
        return "nginx failed to start: " + r["fatal"][:120]
    m = r.get("metrics")
    if r.get("idle"):
        i = r["idle"]
        return None if i["failed"] == 0 else f"{i['failed']} connections failed"
    if not m or (not m.get("rps") and not m.get("bytes_per_s")):
        raw = (r.get("raw") or "").strip()
        return "no result" + (" (client timed out: server stalled)" if "TIMEOUT" in raw else f": {raw[-120:]}")
    req = m.get("requests") or 0
    if req and m.get("errors", 0) > max(1, 0.001 * req):
        return f"{m['errors']} errors / {req} requests"
    if r.get("check") and not r["check"].get("ok"):
        return f"response check failed: {r['check']}"
    if r.get("postcheck") and not r["postcheck"].get("ok"):
        return f"post-check failed: {r['postcheck']}"
    return None


def med(xs):
    xs = [x for x in xs if x is not None]
    return statistics.median(xs) if xs else None


def spread(xs):
    """max relative deviation from the median, in %."""
    xs = [x for x in xs if x]
    if len(xs) < 2:
        return None
    m = statistics.median(xs)
    return 100.0 * max(abs(x - m) for x in xs) / m


def aggregate(recs):
    by = defaultdict(list)
    for r in recs:
        by[(r["scenario"], r["server"])].append(r)
    agg = {}
    for key, rs in by.items():
        good = [r for r in rs if not invalid_reason(r)]
        bad = [invalid_reason(r) for r in rs if invalid_reason(r)]
        a = {"runs": len(rs), "valid": len(good), "invalid": bad,
             "spin": max((r.get("post_idle_cpu_pct") or 0) for r in rs),
             "forced_stop": any(r.get("forced_stop") for r in rs),
             "problems": sorted({p.split("]", 1)[-1].split(",")[0].strip()[:140]
                                 for r in rs for p in (r.get("problems") or [])})[:5]}
        if good:
            g = lambda f: med([f(r) for r in good])  # noqa: E731
            a["rps"] = g(lambda r: r["metrics"].get("rps"))
            a["rps_spread"] = spread([r["metrics"].get("rps") for r in good])
            a["gbps"] = g(lambda r: (r["metrics"].get("bytes_per_s") or 0) * 8 / 1e9)
            for p in ("p50", "p90", "p99", "mean"):
                a[p] = g(lambda r, p=p: r["metrics"].get("latency_ms", {}).get(p))
            a["cpu_pct"] = g(lambda r: r.get("cpu", {}).get("util_pct"))
            a["us_req"] = g(lambda r: r.get("cpu", {}).get("us_per_req"))
            a["s_per_gb"] = g(lambda r: r.get("cpu", {}).get("s_per_gb"))
            a["sys_frac"] = g(lambda r: (r["cpu"]["sys_s"] / max(r["cpu"]["user_s"] + r["cpu"]["sys_s"], 1e-9))
                              if r.get("cpu") else None)
            a["pss_idle"] = g(lambda r: r["mem_idle"].get("Pss", 0) / 1024)
            a["pss_peak"] = g(lambda r: (r.get("mem_load") or {}).get("max_pss_kb", 0) / 1024 or None)
            a["rss_peak"] = g(lambda r: (r.get("mem_load") or {}).get("max_rss_kb", 0) / 1024 or None)
            a["anon_peak"] = g(lambda r: (r.get("mem_load") or {}).get("max_anon_kb", 0) / 1024 or None)
            a["client_cpu"] = g(lambda r: r.get("client_cpu_s"))
            a["backend_cpu"] = g(lambda r: (r.get("backend_cpu") or {}).get("cpu_s"))
            if good[0].get("idle"):
                a["conns"] = g(lambda r: r["idle"]["connections"])
                a["pss_per_conn"] = g(lambda r: r["idle"]["pss_per_conn_kb"])
                a["anon_per_conn"] = g(lambda r: r["idle"]["anon_per_conn_kb"])
                a["pss_before"] = g(lambda r: r["idle"]["mem_before"]["Pss"] / 1024)
                a["pss_after"] = g(lambda r: r["idle"]["mem_after"]["Pss"] / 1024)
                a["pss_closed"] = g(lambda r: r["idle"]["mem_after_close"]["Pss"] / 1024)
                a["open_time"] = g(lambda r: r["idle"]["open_time_s"])
        agg[key] = a
    return agg


def f(x, fmt="{:,.0f}", dash="-"):
    return dash if x is None or (isinstance(x, float) and math.isnan(x)) else fmt.format(x)


def ratio(r, c):
    if not r or not c:
        return None
    return r / c


def status_cell(a):
    if not a:
        return "n/a"
    if a["valid"] == 0:
        return "**FAILED**"
    return ""


def throughput_table(agg, names):
    out = ["| Scenario | C req/s | Rust req/s | **Rust/C** | C p50 / p99 ms | Rust p50 / p99 ms "
           "| C CPU µs/req | Rust CPU µs/req | C peak PSS MB | Rust peak PSS MB |",
           "|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|"]
    for n in names:
        c, r = agg.get((n, "c")), agg.get((n, "rust"))
        if not c and not r:
            continue
        cv = lambda a, k: a.get(k) if a and a["valid"] else None  # noqa: E731
        rr = ratio(cv(r, "rps"), cv(c, "rps"))
        big = SCN[n].get("desc", "")
        rcell = f"{f(cv(r, 'rps'))}" if r and r["valid"] else ("not supported" if not r else "**FAILED**")
        out.append(
            f"| `{n}` — {big} | {f(cv(c, 'rps'))} | {rcell} | **{f(rr, '{:.2f}x')}** "
            f"| {f(cv(c, 'p50'), '{:.2f}')} / {f(cv(c, 'p99'), '{:.2f}')} "
            f"| {f(cv(r, 'p50'), '{:.2f}')} / {f(cv(r, 'p99'), '{:.2f}')} "
            f"| {f(cv(c, 'us_req'), '{:.1f}')} | {f(cv(r, 'us_req'), '{:.1f}')} "
            f"| {f(cv(c, 'pss_peak'), '{:.1f}')} | {f(cv(r, 'pss_peak'), '{:.1f}')} |")
    return "\n".join(out)


def bandwidth_table(agg, names):
    out = ["| Scenario | C Gbit/s | Rust Gbit/s | **Rust/C** | C CPU s/GB | Rust CPU s/GB "
           "| C peak PSS MB | Rust peak PSS MB |", "|---|--:|--:|--:|--:|--:|--:|--:|"]
    for n in names:
        c, r = agg.get((n, "c")), agg.get((n, "rust"))
        cv = lambda a, k: a.get(k) if a and a["valid"] else None  # noqa: E731
        rcell = f(cv(r, "gbps"), "{:.2f}") if r and r["valid"] else "**FAILED**"
        out.append(f"| `{n}` — {SCN[n]['desc']} | {f(cv(c, 'gbps'), '{:.2f}')} | {rcell} "
                   f"| **{f(ratio(cv(r, 'gbps'), cv(c, 'gbps')), '{:.2f}x')}** "
                   f"| {f(cv(c, 's_per_gb'), '{:.2f}')} | {f(cv(r, 's_per_gb'), '{:.2f}')} "
                   f"| {f(cv(c, 'pss_peak'), '{:.1f}')} | {f(cv(r, 'pss_peak'), '{:.1f}')} |")
    return "\n".join(out)


def rate_table(agg, names):
    out = ["| Scenario | C CPU % | Rust CPU % | **Rust/C CPU** | C p50 / p90 / p99 ms | Rust p50 / p90 / p99 ms "
           "| C peak PSS MB | Rust peak PSS MB |", "|---|--:|--:|--:|--:|--:|--:|--:|"]
    for n in names:
        c, r = agg.get((n, "c")), agg.get((n, "rust"))
        cv = lambda a, k: a.get(k) if a and a["valid"] else None  # noqa: E731
        out.append(f"| `{n}` — {SCN[n]['desc']} | {f(cv(c, 'cpu_pct'), '{:.0f}')} | {f(cv(r, 'cpu_pct'), '{:.0f}')} "
                   f"| **{f(ratio(cv(r, 'cpu_pct'), cv(c, 'cpu_pct')), '{:.2f}x')}** "
                   f"| {f(cv(c, 'p50'), '{:.2f}')} / {f(cv(c, 'p90'), '{:.2f}')} / {f(cv(c, 'p99'), '{:.2f}')} "
                   f"| {f(cv(r, 'p50'), '{:.2f}')} / {f(cv(r, 'p90'), '{:.2f}')} / {f(cv(r, 'p99'), '{:.2f}')} "
                   f"| {f(cv(c, 'pss_peak'), '{:.1f}')} | {f(cv(r, 'pss_peak'), '{:.1f}')} |")
    return "\n".join(out)


def idle_table(agg, names):
    out = ["| Scenario | C PSS before → with 10k conns (MB) | Rust PSS before → with 10k conns (MB) "
           "| C KB/conn | Rust KB/conn | **Rust/C** | C after close (MB) | Rust after close (MB) |",
           "|---|--:|--:|--:|--:|--:|--:|--:|"]
    for n in names:
        c, r = agg.get((n, "c")), agg.get((n, "rust"))
        cv = lambda a, k: a.get(k) if a and a["valid"] else None  # noqa: E731
        out.append(f"| `{n}` — {SCN[n]['desc']} "
                   f"| {f(cv(c, 'pss_before'), '{:.1f}')} → {f(cv(c, 'pss_after'), '{:.1f}')} "
                   f"| {f(cv(r, 'pss_before'), '{:.1f}')} → {f(cv(r, 'pss_after'), '{:.1f}')} "
                   f"| {f(cv(c, 'pss_per_conn'), '{:.2f}')} | {f(cv(r, 'pss_per_conn'), '{:.2f}')} "
                   f"| **{f(ratio(cv(r, 'pss_per_conn'), cv(c, 'pss_per_conn')), '{:.1f}x')}** "
                   f"| {f(cv(c, 'pss_closed'), '{:.1f}')} | {f(cv(r, 'pss_closed'), '{:.1f}')} |")
    return "\n".join(out)


def geomean(xs):
    xs = [x for x in xs if x]
    return math.exp(sum(math.log(x) for x in xs) / len(xs)) if xs else None


def main():
    paths = sys.argv[1:]
    recs = load(paths)
    agg = aggregate(recs)
    groups = []
    for s in SCENARIOS:
        if s["group"] not in groups:
            groups.append(s["group"])
    print(f"<!-- generated by report.py from {', '.join(paths)} ({len(recs)} runs) -->\n")

    sat = [n for n in ORDER if SCN[n]["tool"] in ("wrk", "h2load") and (n, "c") in agg]
    ratios = [ratio(agg.get((n, "rust"), {}).get("rps"), agg[(n, "c")].get("rps")) for n in sat
              if agg.get((n, "rust"), {}).get("valid")]
    cpu_ratios = [ratio(agg.get((n, "rust"), {}).get("us_req"), agg[(n, "c")].get("us_req")) for n in sat
                  if agg.get((n, "rust"), {}).get("valid")]
    print(f"Saturation scenarios: {len(sat)}; Rust/C throughput geomean = {f(geomean(ratios), '{:.2f}x')} "
          f"(min {f(min(ratios) if ratios else None, '{:.2f}x')}, max {f(max(ratios) if ratios else None, '{:.2f}x')}); "
          f"Rust/C CPU-per-request geomean = {f(geomean(cpu_ratios), '{:.2f}x')}\n")

    for g in groups:
        names = [s["name"] for s in SCENARIOS if s["group"] == g]
        print(f"### {g}\n")
        if g == "Fixed rate":
            print(rate_table(agg, names))
        elif g == "Memory":
            print(idle_table(agg, names))
        else:
            tp = [n for n in names if SCN[n]["tool"] != "iperf3"]
            bw = [n for n in names if SCN[n]["tool"] == "iperf3" or n.endswith(("-1m", "-100k"))]
            if tp:
                print(throughput_table(agg, tp))
            if bw:
                print("\nBandwidth view:\n")
                print(bandwidth_table(agg, bw))
        print()

    print("### Run health\n")
    print("| Scenario | Server | valid/runs | rps spread | invalid reasons | post-load CPU spin | forced stop "
          "| error.log (first distinct) |")
    print("|---|---|--:|--:|---|--:|---|---|")
    for n in ORDER:
        for srv in ("c", "rust"):
            a = agg.get((n, srv))
            if not a:
                continue
            flag = a["invalid"] or a["spin"] > 10 or a["forced_stop"] or a["problems"] or \
                (a.get("rps_spread") or 0) > 10
            if flag:
                print(f"| `{n}` | {srv} | {a['valid']}/{a['runs']} | {f(a.get('rps_spread'), '{:.0f}%')} "
                      f"| {'; '.join(sorted(set(a['invalid'])))[:200]} | {a['spin']:.0f}% "
                      f"| {'yes' if a['forced_stop'] else ''} | {'<br>'.join(a['problems'])[:300]} |")


if __name__ == "__main__":
    main()
