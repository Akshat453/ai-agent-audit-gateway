"""Figure 5.1: RQ1 median decision latency per configuration and concurrency.

Data: experiments/rq1_latency/results/summary.csv (recomputed by the harness from raw.csv);
p50 with its 95 % bootstrap interval. Grouped bars (configuration comparison), log y because
values span three orders of magnitude.
"""
import csv

import matplotlib.pyplot as plt
import style

style.apply()
rows = list(csv.DictReader(open(style.ROOT / "experiments/rq1_latency/results/summary.csv")))
cfgs = ["C1", "C2", "C3", "C4", "C5", "C6"]
conc = ["1", "10", "50"]


def cell(cfg, c, key):
    return float(next(r for r in rows if r["config"] == cfg and r["concurrency"] == c)[key])


fig, ax = plt.subplots(figsize=style.SIZE)
w = 0.27
for j, c in enumerate(conc):
    xs = [i + (j - 1) * w for i in range(len(cfgs))]
    p50 = [cell(k, c, "p50_ms") for k in cfgs]
    lo = [cell(k, c, "p50_ci_lo") for k in cfgs]
    hi = [cell(k, c, "p50_ci_hi") for k in cfgs]
    ax.bar(xs, p50, width=w - 0.03, color=style.SERIES3[j], edgecolor="white", linewidth=0.5,
           label=f"{c} agent{'s' if c != '1' else ''}")
    ax.errorbar(xs, p50, yerr=[[v - a for v, a in zip(p50, lo)], [b - v for v, b in zip(p50, hi)]],
                fmt="none", ecolor="#222222", elinewidth=0.8, capsize=2)
ax.set_yscale("log")
ax.set_xticks(range(len(cfgs)))
ax.set_xticklabels(cfgs)
ax.set_ylabel("p50 decision latency (ms)")
ax.set_xlabel("Configuration (C0 baseline 0.001-0.002 ms, not drawn)")
ax.legend(title="Concurrency", frameon=False, ncol=3, loc="lower center", bbox_to_anchor=(0.5, 1.0))
style.save(fig, "fig5_1_rq1_latency")
