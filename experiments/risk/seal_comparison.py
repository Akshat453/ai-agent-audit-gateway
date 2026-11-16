"""Fixed 100-event sealing vs risk-adaptive sealing (Phase 4). LOCAL, PRELIMINARY, SIMULATED.

A seeded discrete-time simulation of one tenant's chain. It uses the PRODUCTION seal decision
(``agw_worker.sealing.policy.decide``) with a 1 s sealer tick, and appends an EPOCH_SEALED
receipt after every seal exactly as the real sealer does. The workload is synthetic:

* actions arrive as a Poisson process at ``rate`` actions/s;
* risk mix (hypothesis, not measured): LOW 80 %, MEDIUM 15 %, HIGH 4 %, CRITICAL 1 %;
* events per action: LOW/MEDIUM 5 (requested .. completed); HIGH 3 (.. APPROVAL_REQUIRED);
  CRITICAL 3 (.. ACTION_DENIED). All events of an action share its arrival time.

Policies compared:
* ``fixed``: Phase 3 behaviour, every level 100 events / 300 s, no risk trigger;
* ``adaptive``: Phase 4 defaults, LOW 100/300 s, MEDIUM 25/60 s, HIGH/CRITICAL immediate,
  with the count threshold taken from the lowest level present (default, the prompt's
  wording) or from the strictest level present.

Reported per policy: epochs created (= future anchors), epochs by reason, and the time an
event waited unsealed ("unsealed age"), max/p95 for HIGH+CRITICAL events and max for all.

    uv run python experiments/risk/seal_comparison.py [--seeds 5] [--hours 1]

Limitations: no DB, no network, no concurrency, no executor latency; seal itself takes 0 s.
Numbers say how the RULE behaves under this workload, not how a deployment performs.
"""

from __future__ import annotations

import argparse
import math
import random
from collections import Counter
from dataclasses import dataclass, field

from agw_worker.sealing.policy import PendingLevel, PendingWindow, SealPolicy, decide

MIX = (("LOW", 0.80, 5), ("MEDIUM", 0.15, 5), ("HIGH", 0.04, 3), ("CRITICAL", 0.01, 3))
URGENT = {"HIGH", "CRITICAL"}


@dataclass
class Sim:
    policy: SealPolicy
    times: list[float] = field(default_factory=list)  # event time by seq
    levels: list[str | None] = field(default_factory=list)  # None = receipt
    sealed_at: list[float | None] = field(default_factory=list)
    sealed_up_to: int = -1
    reasons: Counter[str] = field(default_factory=Counter)

    def append(self, t: float, level: str | None) -> None:
        self.times.append(t)
        self.levels.append(level)
        self.sealed_at.append(None)

    def window(self, now: float) -> PendingWindow:
        agg: dict[str, list[float]] = {}
        for seq in range(self.sealed_up_to + 1, len(self.times)):
            lv = self.levels[seq]
            if lv is None:
                continue
            a = agg.setdefault(lv, [0, math.inf, -1])
            a[0] += 1
            a[1] = min(a[1], self.times[seq])
            a[2] = seq
        return PendingWindow(
            sealed_up_to=self.sealed_up_to,
            last_seq=len(self.times) - 1,
            levels=tuple(PendingLevel(k, int(v[0]), now - v[1], int(v[2])) for k, v in agg.items()),
        )

    def tick(self, now: float) -> None:
        for _ in range(10_000):  # same bounded drain as Sealer.drain
            due = decide(self.window(now), self.policy)
            if due is None:
                return
            up_to, reason = due
            for seq in range(self.sealed_up_to + 1, up_to + 1):
                self.sealed_at[seq] = now
            self.sealed_up_to = up_to
            self.reasons[reason] += 1
            self.append(now, None)  # EPOCH_SEALED receipt (lands in a later epoch)


def workload(rate: float, seconds: float, seed: int) -> list[tuple[float, str, int]]:
    rng = random.Random(seed)
    out, t = [], 0.0
    while True:
        t += rng.expovariate(rate)
        if t >= seconds:
            return out
        r, acc = rng.random(), 0.0
        for level, p, n in MIX:
            acc += p
            if r < acc:
                out.append((t, level, n))
                break


def simulate(policy: SealPolicy, actions: list[tuple[float, str, int]], seconds: float) -> dict:
    sim, i = Sim(policy), 0
    tick = 1.0
    end = seconds + 600  # let the tail drain by age
    while tick <= end:
        while i < len(actions) and actions[i][0] <= tick:
            t, level, n = actions[i]
            for _ in range(n):
                sim.append(t, level)
            i += 1
        sim.tick(tick)
        tick += 1.0
    waits = [
        (s - t, lv)
        for t, lv, s in zip(sim.times, sim.levels, sim.sealed_at, strict=True)
        if lv is not None and s is not None
    ]
    urgent = sorted(w for w, lv in waits if lv in URGENT)
    allw = [w for w, _ in waits]
    unsealed = sum(1 for lv, s in zip(sim.levels, sim.sealed_at, strict=True) if lv and s is None)
    return {
        "epochs": sum(sim.reasons.values()),
        "reasons": dict(sim.reasons),
        "urgent_events": len(urgent),
        "urgent_max": max(urgent, default=0.0),
        "urgent_p95": urgent[int(0.95 * (len(urgent) - 1))] if urgent else 0.0,
        "all_max": max(allw, default=0.0),
        "all_mean": sum(allw) / len(allw) if allw else 0.0,
        "unsealed_at_end": unsealed,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--hours", type=float, default=1.0)
    args = ap.parse_args()
    seconds = args.hours * 3600
    policies = {
        "fixed-100": SealPolicy.fixed(100, 300),
        "adaptive (lowest, default)": SealPolicy.adaptive(),
        "adaptive (strictest)": SealPolicy.adaptive(count_basis="strictest"),
    }
    print(f"SIMULATED, local, preliminary. {args.seeds} seeds x {args.hours} h, 1 s sealer tick.")
    print(
        "| rate (actions/s) | policy | epochs/h | epochs by reason | HIGH+CRIT max unsealed s "
        "| HIGH+CRIT p95 s | all-events max s | all-events mean s |"
    )
    print("|---|---|---|---|---|---|---|---|")
    for rate in (0.05, 0.5, 5.0):
        for name, policy in policies.items():
            runs = [
                simulate(policy, workload(rate, seconds, seed), seconds)
                for seed in range(args.seeds)
            ]
            mean = {k: sum(r[k] for r in runs) / len(runs) for k in runs[0] if k != "reasons"}
            reasons: Counter[str] = Counter()
            for r in runs:
                reasons.update(r["reasons"])
            rs = ", ".join(
                f"{k} {v / len(runs) / args.hours:.0f}" for k, v in sorted(reasons.items())
            )
            worst_urgent = max(r["urgent_max"] for r in runs)
            print(
                f"| {rate} | {name} | {mean['epochs'] / args.hours:.0f} | {rs} | "
                f"{worst_urgent:.1f} | {mean['urgent_p95']:.1f} | "
                f"{max(r['all_max'] for r in runs):.1f} | {mean['all_mean']:.1f} |"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
