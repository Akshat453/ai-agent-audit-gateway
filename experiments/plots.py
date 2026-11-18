"""Figures for docs/gateway/research/results.md, generated ONLY from the experiments' raw /
summary CSVs (no numbers typed in here). A figure is skipped if its CSV does not exist.

    uv run python -m experiments.plots
"""

from __future__ import annotations

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from experiments.lib.common import REPO, read_csv

OUT = REPO / "docs" / "gateway" / "research" / "figures"
EXP = REPO / "experiments"
# Categorical slots in fixed order (validated default palette, light mode).
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]
INK, INK2, GRID = "#0b0b0b", "#52514e", "#e4e3df"
CONFIGS = ["C0", "C1", "C2", "C3", "C4", "C5", "C6"]


def style(ax: plt.Axes, title: str, ylabel: str) -> None:
    ax.set_title(title, loc="left", fontsize=11, color=INK)
    ax.set_ylabel(ylabel, color=INK2, fontsize=9)
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(GRID)
    ax.tick_params(colors=INK2, labelsize=8)


def rq1() -> None:
    f = EXP / "rq1_latency" / "results" / "summary.csv"
    if not f.exists():
        return
    rows = read_csv(f)
    concs = sorted({int(r["concurrency"]) for r in rows})
    fig, axes = plt.subplots(1, len(concs), figsize=(4.2 * len(concs), 3.6), squeeze=False)
    for ax, c in zip(axes[0], concs, strict=True):
        rs = [r for r in rows if int(r["concurrency"]) == c and r["config"] != "C0"]
        rs.sort(key=lambda r: CONFIGS.index(r["config"]))
        x = range(len(rs))
        for k, (p, color) in enumerate(zip((50, 95, 99), SERIES, strict=False)):
            vals = [float(r[f"p{p}_ms"]) for r in rs]
            err = [[v - float(r[f"p{p}_ci_lo"]) for v, r in zip(vals, rs, strict=True)],
                   [float(r[f"p{p}_ci_hi"]) - v for v, r in zip(vals, rs, strict=True)]]  # fmt: skip
            ax.bar([i + (k - 1) * 0.26 for i in x], vals, 0.24, color=color, label=f"P{p}",
                   yerr=err, ecolor=INK2, capsize=2, error_kw={"linewidth": 0.8})  # fmt: skip
        ax.set_xticks(list(x), [r["config"] for r in rs])
        style(ax, f"{c} concurrent agent{'s' if c > 1 else ''}", "decision latency (ms)")
    axes[0][0].legend(frameon=False, fontsize=8)
    fig.suptitle("RQ1: POST /v1/actions latency per configuration (mean of 5 runs, 95% bootstrap CI)",
                 fontsize=10, color=INK, x=0.01, ha="left")  # fmt: skip
    fig.tight_layout()
    fig.savefig(OUT / "rq1-latency.png", dpi=150)
    plt.close(fig)

    stages = ["auth", "risk", "policy", "durable_write", "dispatch_tx", "adapter", "result_tx"]
    rs = [r for r in rows if int(r["concurrency"]) == 1 and r["config"] != "C0"]
    rs.sort(key=lambda r: CONFIGS.index(r["config"]))
    fig, ax = plt.subplots(figsize=(7, 3.6))
    bottom = [0.0] * len(rs)
    for stage, color in zip(stages, SERIES, strict=False):
        vals = [float(r.get(f"{stage}_ms") or 0.0) for r in rs]
        ax.bar([r["config"] for r in rs], vals, 0.6, bottom=bottom, color=color, label=stage,
               edgecolor="white", linewidth=1)  # fmt: skip
        bottom = [b + v for b, v in zip(bottom, vals, strict=True)]
    style(ax, "RQ1: mean time per stage, 1 agent (seal is per epoch, see table)", "ms")
    ax.legend(frameon=False, fontsize=8, ncols=4, loc="upper left")
    fig.tight_layout()
    fig.savefig(OUT / "rq1-stages.png", dpi=150)
    plt.close(fig)


def rq2() -> None:
    f = EXP / "rq2_batching" / "results" / "summary.csv"
    if not f.exists():
        return
    rows = read_csv(f)
    workloads = list(dict.fromkeys(r["workload"] for r in rows))
    fig, ax = plt.subplots(figsize=(7, 3.8))
    for w, color in zip(workloads, SERIES, strict=False):
        for r in (r for r in rows if r["workload"] == w):
            marker = "o" if r["config"].startswith("C4") else "^"
            ax.scatter(float(r["anchors_per_day"]), float(r["high_exposure_max_s"]), s=48,
                       color=color, marker=marker, edgecolor="white", linewidth=1.5)  # fmt: skip
        ax.scatter([], [], color=color, label=w)
    ax.scatter([], [], color=INK2, marker="o", label="C4 fixed")
    ax.scatter([], [], color=INK2, marker="^", label="C5 adaptive")
    style(ax, "RQ2: anchoring cost vs worst unanchored exposure of HIGH events", "max exposure (s)")
    ax.set_xlabel("anchors per day", color=INK2, fontsize=9)
    ax.legend(frameon=False, fontsize=7, loc="upper right")
    fig.tight_layout()
    fig.savefig(OUT / "rq2-exposure.png", dpi=150)
    plt.close(fig)


def rq3() -> None:
    f = EXP / "rq3_tamper" / "results" / "summary.csv"
    if not f.exists():
        return
    rows = [r for r in read_csv(f) if not r["class"].startswith("HONEST")]
    fig, ax = plt.subplots(figsize=(8, 3.8))
    labels = [r["class"] for r in rows]
    for k, (root, color) in enumerate(zip(("none", "before", "after"), SERIES, strict=False)):
        vals = [float(r[f"rate_{root}"] or 0) * 100 for r in rows]
        ax.bar([i + (k - 1) * 0.26 for i in range(len(rows))], vals, 0.24, color=color,
               label={"none": "no trust root", "before": "anchor before tamper",
                      "after": "anchor after tamper"}[root])  # fmt: skip
    ax.set_xticks(range(len(rows)), labels, rotation=30, ha="right")
    style(ax, "RQ3: detection rate by tamper class and trust root", "% detected")
    ax.set_ylim(0, 105)
    ax.legend(frameon=False, fontsize=8, loc="lower left")
    fig.tight_layout()
    fig.savefig(OUT / "rq3-detection.png", dpi=150)
    plt.close(fig)


def rq4() -> None:
    f = EXP / "rq4_authz" / "results" / "summary.csv"
    if not f.exists():
        return
    rows = read_csv(f)
    cats = list(dict.fromkeys(r["category"] for r in rows))
    fig, ax = plt.subplots(figsize=(7.5, 3.8))
    bottom = [0.0] * len(CONFIGS)
    for cat, color in zip(cats, SERIES, strict=False):
        vals = [float(next((r["unauthorized_executions"] for r in rows
                            if r["config"] == c and r["category"] == cat), 0)) for c in CONFIGS]  # fmt: skip
        ax.bar(
            CONFIGS,
            vals,
            0.6,
            bottom=bottom,
            color=color,
            label=cat,
            edgecolor="white",
            linewidth=1,
        )
        bottom = [b + v for b, v in zip(bottom, vals, strict=True)]
    for i, b in enumerate(bottom):
        ax.text(i, b + 0.3, f"{int(b)}", ha="center", fontsize=8, color=INK)
    style(ax, "RQ4: unauthorized executions per configuration (attack corpus)", "executions")
    ax.legend(frameon=False, fontsize=7, ncols=2, loc="upper right")
    fig.tight_layout()
    fig.savefig(OUT / "rq4-authz.png", dpi=150)
    plt.close(fig)


def rq6() -> None:
    f = EXP / "rq6_agents" / "results" / "summary.csv"
    if not f.exists():
        return
    rows = read_csv(f)
    fig, ax = plt.subplots(figsize=(7, 3.4))
    labels = [f"{r['task']} {r['mode']}" for r in rows]
    colors = [SERIES[0] if r["mode"] == "direct" else SERIES[1] for r in rows]
    ax.barh(labels, [float(r["median_wall_s"]) for r in rows], color=colors, height=0.6)
    ax.invert_yaxis()
    style(ax, "RQ6: median wall time per agent task (direct vs gateway)", "")
    ax.set_xlabel("seconds (includes the scripted approver)", color=INK2, fontsize=9)
    ax.grid(axis="x", color=GRID)
    fig.tight_layout()
    fig.savefig(OUT / "rq6-agents.png", dpi=150)
    plt.close(fig)


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    for fn in (rq1, rq2, rq3, rq4, rq6):
        fn()
    print("\n".join(sorted(p.name for p in OUT.glob("*.png"))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
