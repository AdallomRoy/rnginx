#!/usr/bin/env python3
"""Before/after table: the Rust port before the bench-fixes branch (old run)
against the fixed build (new run), with C from the new run as reference.

    compare.py OLD.jsonl[,OLD2.jsonl...] NEW.jsonl[,NEW2.jsonl...]
"""
import math
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from report import SCENARIOS, aggregate, load  # noqa: E402


def f(x, fmt="{:,.0f}"):
    return "-" if x is None or (isinstance(x, float) and math.isnan(x)) else fmt.format(x)


def val(agg, key, k):
    a = agg.get(key)
    return a.get(k) if a and a["valid"] else None


def main():
    old = aggregate(load(sys.argv[1].split(",")))
    new_files = sys.argv[2].split(",")
    new = aggregate(load(new_files))

    print("| Scenario | C req/s | Rust before | Rust after | **after/before** | Rust/C before | **Rust/C after** "
          "| Rust CPU µs/req before → after |")
    print("|---|--:|--:|--:|--:|--:|--:|--:|")
    for s in SCENARIOS:
        n = s["name"]
        if s["tool"] in ("idle",) or s.get("servers") == ["c"]:
            continue
        key_rate = "gbps" if s["tool"] == "iperf3" else "rps"
        c = val(new, (n, "c"), key_rate)
        rb = val(old, (n, "rust"), key_rate)
        ra = val(new, (n, "rust"), key_rate)
        if c is None and ra is None:
            continue
        failed_before = (n, "rust") in old and not old[(n, "rust")]["valid"]
        fmt = "{:.2f} Gbit/s" if key_rate == "gbps" else "{:,.0f}"
        rb_cell = "**FAILED**" if failed_before else f(rb, fmt)
        ratio = lambda a, b: (a / b) if a and b else None  # noqa: E731
        print(f"| `{n}` | {f(c, fmt)} | {rb_cell} | {f(ra, fmt)} | **{f(ratio(ra, rb), '{:.2f}x')}** "
              f"| {f(ratio(rb, val(old, (n, 'c'), key_rate)), '{:.2f}x')} | **{f(ratio(ra, c), '{:.2f}x')}** "
              f"| {f(val(old, (n, 'rust'), 'us_req'), '{:.1f}')} → {f(val(new, (n, 'rust'), 'us_req'), '{:.1f}')} |")

    print("\n| Memory scenario | C KB/conn | Rust before KB/conn | Rust after KB/conn |")
    print("|---|--:|--:|--:|")
    for s in SCENARIOS:
        if s["tool"] != "idle":
            continue
        n = s["name"]
        print(f"| `{n}` | {f(val(new, (n, 'c'), 'pss_per_conn'), '{:.2f}')} "
              f"| {f(val(old, (n, 'rust'), 'pss_per_conn'), '{:.2f}')} | {f(val(new, (n, 'rust'), 'pss_per_conn'), '{:.2f}')} |")

    # descriptors left open by the workers after each run (leak check)
    import json
    fds = {}
    for r in load(new_files):
        if r.get("worker_fds_end") is not None:
            k = (r["scenario"], r["server"])
            fds[k] = max(fds.get(k, 0), r["worker_fds_end"])
    worst = sorted(((v, k) for k, v in fds.items() if k[1] == "rust"), reverse=True)[:5]
    print("\nLargest worker descriptor counts after a run (Rust, fixed): "
          + ", ".join(f"`{k[0]}` {v} (C {fds.get((k[0], 'c'), '-')})" for v, k in worst))


if __name__ == "__main__":
    main()
