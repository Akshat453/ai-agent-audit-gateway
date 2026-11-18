"""RQ2: risk-adaptive (C5) vs fixed (C4) sealing + anchoring. SEEDED SIMULATION.

    uv run python -m experiments.rq2_batching.run

The seal decisions are the PRODUCTION function (`agw_worker.sealing.policy.decide`, 1 s tick,
EPOCH_SEALED receipts appended as the real sealer does). Anchoring is modelled: one tx per
epoch (as EpochAnchor.sol), C4 anchors every sealed epoch at a fixed interval, C5 anchors
epochs containing a HIGH/CRITICAL event at seal time and routine epochs at the interval;
finality = anchor time + a stated delay. Gas per anchor is the measured mean (Anvil); prices are
stated assumptions. Workloads: synthetic risk mixes (Poisson) and the REAL agent trace recorded
by RQ6 (replayed in a loop). Output: raw.csv (one row per seed x mix x policy), summary.csv.
"""

from __future__ import annotations

import math
import random
import statistics
import sys
from pathlib import Path
from typing import Any

from experiments.lib.common import (
    REPO,
    bootstrap_ci,
    environment,
    load_config,
    percentile,
    read_csv,
    results_dir,
    write_csv,
    write_json,
)

sys.path.insert(0, str(REPO / "experiments" / "risk"))
from seal_comparison import Sim

from agw_worker.sealing.policy import SealPolicy, decide

HERE = Path(__file__).resolve().parent
LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
URGENT = {"HIGH", "CRITICAL"}


class EpochSim(Sim):
    """Sim that also records each epoch's [first, last] and seal time."""

    def __post_init__(self) -> None:
        self.epochs: list[tuple[int, int, float]] = []

    def tick(self, now: float) -> None:
        for _ in range(10_000):
            due = decide(self.window(now), self.policy)
            if due is None:
                return
            up_to, reason = due
            first = self.sealed_up_to + 1
            for seq in range(first, up_to + 1):
                self.sealed_at[seq] = now
            self.sealed_up_to = up_to
            self.reasons[reason] += 1
            self.epochs.append((first, up_to, now))
            self.append(now, None)


def synthetic(
    mix: list[float], rate: float, seconds: float, seed: int, per: dict[str, int]
) -> list[tuple[float, str, int]]:
    rng, out, t = random.Random(seed), [], 0.0
    while True:
        t += rng.expovariate(rate)
        if t >= seconds:
            return out
        r, acc = rng.random(), 0.0
        for level, p in zip(LEVELS, mix, strict=True):
            acc += p
            if r < acc:
                out.append((t, level, per[level]))
                break


def replay(
    trace: list[dict[str, str]], seconds: float, per: dict[str, int]
) -> list[tuple[float, str, int]]:
    """Loop the recorded agent trace (relative times) until `seconds`, 5 s gap between loops."""
    span = max(float(r["t_s"]) for r in trace) + 5.0
    out, base = [], 0.0
    while base < seconds:
        for r in trace:
            t = base + float(r["t_s"])
            if t < seconds:
                out.append((t, r["risk_level"], per[r["risk_level"]]))
        base += span
    return sorted(out)


def simulate(
    policy_name: str, actions: list[tuple[float, str, int]], seconds: float, cfg: dict[str, Any]
) -> dict[str, Any]:
    policy = SealPolicy.fixed(100, 300.0) if policy_name == "C4" else SealPolicy.adaptive()
    sim, i, tick = EpochSim(policy), 0, 1.0
    sim.__post_init__()
    while tick <= seconds + 900:
        while i < len(actions) and actions[i][0] <= tick:
            t, level, n = actions[i]
            for _ in range(n):
                sim.append(t, level)
            i += 1
        sim.tick(tick)
        tick += 1.0
    interval = (
        cfg["fixed_anchor_interval_s"] if policy_name == "C4" else cfg["routine_anchor_interval_s"]
    )
    fin = cfg["finality_delay_s"]
    final_at: dict[int, float] = {}
    for first, last, sealed in sim.epochs:
        urgent = any(sim.levels[s] in URGENT for s in range(first, last + 1))
        anchored = (
            sealed if (policy_name != "C4" and urgent) else math.ceil(sealed / interval) * interval
        )
        for s in range(first, last + 1):
            final_at[s] = anchored + fin
    exposure = [
        final_at[s] - sim.times[s]
        for s in range(len(sim.times))
        if sim.levels[s] in URGENT and s in final_at
    ]
    days = seconds / 86400
    anchors = len(sim.epochs)
    row = {
        "epochs": anchors,
        "anchors_per_day": anchors / days,
        "gas_per_day": anchors / days * cfg["gas_per_anchor"],
        "high_events": len(exposure),
        "high_exposure_max_s": max(exposure, default=0.0),
        "high_exposure_p95_s": percentile(exposure, 95) if exposure else 0.0,
        "high_exposure_mean_s": statistics.fmean(exposure) if exposure else 0.0,
    }
    for gp in cfg["gas_price_gwei"]:
        row[f"usd_per_day_at_{gp}gwei"] = row["gas_per_day"] * gp * 1e-9 * cfg["eth_usd"]
    return row


def main() -> int:
    cfg = load_config(HERE / "config.toml")
    out = results_dir(HERE)
    seconds = cfg["hours"] * 3600
    workloads: dict[str, Any] = {name: ("synthetic", mix) for name, mix in cfg["mixes"].items()}
    trace_file = REPO / "experiments" / "rq6_agents" / "results" / "trace.csv"
    if trace_file.exists():
        workloads["real-agents (RQ6 trace)"] = ("trace", read_csv(trace_file))
    raw = []
    for wname, (kind, data) in workloads.items():
        for seed in cfg["seeds"]:
            acts = (synthetic(data, cfg["rate_actions_per_s"], seconds, seed, cfg["events"]) if kind == "synthetic"
                    else replay(data, seconds, cfg["events"]))  # fmt: skip
            for pol in ("C4", "C5"):
                row = simulate(pol, acts, seconds, cfg)
                raw.append(
                    {"workload": wname, "seed": seed, "config": pol, "actions": len(acts), **row}
                )
                print(f"{wname:<26} seed={seed} {pol}: anchors/day={row['anchors_per_day']:.0f} "
                      f"HIGH max={row['high_exposure_max_s']:.0f}s p95={row['high_exposure_p95_s']:.0f}s", flush=True)  # fmt: skip
            if kind == "trace":
                break  # the trace is deterministic: one "seed"
    write_csv(out / "raw.csv", raw)
    summary = []
    metrics = [k for k in raw[0] if k not in ("workload", "seed", "config", "actions")]
    for wname in workloads:
        for pol in ("C4", "C5"):
            rows = [r for r in raw if r["workload"] == wname and r["config"] == pol]
            s: dict[str, Any] = {"workload": wname, "config": pol, "runs": len(rows)}
            for m in metrics:
                mean, lo, hi = bootstrap_ci([float(r[m]) for r in rows], seed=1)
                s[m], s[f"{m}_ci_lo"], s[f"{m}_ci_hi"] = round(mean, 3), round(lo, 3), round(hi, 3)
            summary.append(s)
    write_csv(out / "summary.csv", summary)
    write_json(out / "env.json", environment({"config": cfg, "kind": "simulation"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
