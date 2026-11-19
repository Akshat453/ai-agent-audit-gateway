"""Figure 5.2: fixed vs adaptive sealing (simulated).

Data: experiments/risk/results/phase4-seal-comparison.md (output of experiments/risk/seal_comparison.py).
(a) p95 unsealed time of HIGH+CRITICAL events, linear; (b) epochs per hour, log scale.
"""
import re

import matplotlib.pyplot as plt
import style

style.apply()
rows = []
for line in (style.ROOT / "experiments/risk/results/phase4-seal-comparison.md").read_text().splitlines():
    m = re.match(r"\|\s*([\d.]+)\s*\|\s*([^|]+?)\s*\|\s*(\d+)\s*\|[^|]*\|\s*([\d.]+)\s*\|\s*([\d.]+)\s*\|", line)
    if m:
        rows.append({"rate": m[1], "policy": m[2], "epochs": int(m[3]), "p95": float(m[5])})
rates = ["0.05", "0.5", "5.0"]
pols = [("fixed-100", "Fixed 100-event", style.VERMILION),
        ("adaptive (lowest, default)", "Adaptive (default)", style.DARK_BLUE),
        ("adaptive (strictest)", "Adaptive (strictest)", style.SKY)]


def val(rate, pol, key):
    return next(r for r in rows if r["rate"] == rate and r["policy"] == pol)[key]


fig, (a1, a2) = plt.subplots(1, 2, figsize=(6.0, 3.0))
w = 0.27
for j, (pid, lab, col) in enumerate(pols):
    xs = [i + (j - 1) * w for i in range(3)]
    p95 = [val(r, pid, "p95") for r in rates]
    ep = [val(r, pid, "epochs") for r in rates]
    b1 = a1.bar(xs, p95, width=w - 0.03, color=col, label=lab)
    a2.bar(xs, ep, width=w - 0.03, color=col, label=lab)
    for x, v in zip(xs, p95):
        a1.text(x, v + 4, f"{v:.1f}", ha="center", va="bottom", fontsize=8)
for a, yl, t in [(a1, "p95 unsealed time (s)", "(a) HIGH+CRITICAL exposure"),
                 (a2, "Epochs per hour (log)", "(b) Sealing cost")]:
    a.set_xticks(range(3))
    a.set_xticklabels([f"{r}/s" for r in rates])
    a.set_xlabel("Action rate")
    a.set_ylabel(yl)
    a.set_title(t)
a2.set_yscale("log")
h, l = a1.get_legend_handles_labels()
fig.legend(h, l, frameon=False, ncol=3, loc="lower center", bbox_to_anchor=(0.5, 0.98))
fig.tight_layout()
style.save(fig, "fig5_2_seal_comparison")
