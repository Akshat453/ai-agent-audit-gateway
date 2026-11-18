"""RQ1: decision latency and per-stage timings for the ablation configurations C0..C6.

    uv run python -m experiments.rq1_latency.run [--config experiments/rq1_latency/config.toml]

Each run: a fresh tenant, `warmup_requests` excluded, then N concurrent agents (threads, real
HTTP to the in-process gateway, one executor) submit `test_echo` (LOW, no approval).
Measured: client POST->decision latency; server stage timers (auth, risk, policy,
durable_write, dispatch_tx, adapter, result_tx) and, for C3+, the seal of the run's events.
C0 is the plain tool call (no gateway). Output: raw.csv, stages.csv, summary.csv, env.json.
"""

from __future__ import annotations

import argparse
import random
import statistics
import threading
import time
import uuid
from pathlib import Path

import httpx

from experiments.lib.common import (
    bootstrap_ci,
    environment,
    load_config,
    percentile,
    read_csv,
    results_dir,
    write_csv,
    write_json,
)
from experiments.lib.stack import gateway, postgres

HERE = Path(__file__).resolve().parent


def run_c0(n: int) -> list[float]:
    from agw_gateway.tools.spec import ToolResult

    def echo(text: str) -> ToolResult:  # the same no-op tool the gateway dispatches
        return ToolResult(public={"echo": text})

    out = []
    for i in range(n):
        t0 = time.perf_counter()
        echo(f"x{i}")
        out.append((time.perf_counter() - t0) * 1000)
    return out


def drive(url: str, token: str, tool: str, agents: int, per_agent: int) -> list[tuple[float, int]]:
    """(latency ms, HTTP status) for EVERY request: a fail-closed 503 is an answer too and
    stays in the sample (dropping it would bias the percentiles)."""
    lat: list[tuple[float, int]] = []
    lock = threading.Lock()
    run_id = str(uuid.uuid4())

    def agent() -> None:
        with httpx.Client(base_url=url, timeout=60) as c:
            for i in range(per_agent):
                t0 = time.perf_counter()
                r = c.post(
                    "/v1/actions",
                    json={
                        "run_id": run_id,
                        "tool": tool,
                        "environment": "dev",
                        "args": {"text": f"x{i}"},
                    },
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Idempotency-Key": uuid.uuid4().hex,
                    },
                )
                dt = (time.perf_counter() - t0) * 1000
                with lock:
                    lat.append((dt, r.status_code))

    threads = [threading.Thread(target=agent) for _ in range(agents)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    return lat


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=str(HERE / "config.toml"))
    cfg = load_config(Path(ap.parse_args().config))
    random.seed(cfg["seed"])
    out = results_dir(HERE)
    from tests.servekit import serve

    from agw_gateway import timing
    from agw_gateway.api.app import create_app
    from agw_gateway.evidence import EvidenceWriter
    from agw_worker.sealing import Sealer
    from agw_worker.sealing.policy import SealPolicy

    raw: list[dict[str, object]] = []
    stages: list[dict[str, object]] = []
    runs: list[dict[str, object]] = []
    with postgres() as urls:
        for config in cfg["configs"]:
            for conc in cfg["concurrency"]:
                per_agent = max(cfg["requests_per_agent"], -(-cfg["min_requests"] // conc))
                for run in range(cfg["runs"]):
                    if config == "C0":
                        t_run = time.perf_counter()
                        c0 = run_c0(conc * per_agent)
                        runs.append({"config": config, "concurrency": conc, "run": run, "n": len(c0),
                                     "errors": 0, "wall_s": time.perf_counter() - t_run})  # fmt: skip
                        for i, ms in enumerate(c0):
                            raw.append({"config": config, "concurrency": conc, "run": run,
                                        "i": i, "decision_ms": ms, "http": 0})  # fmt: skip
                        continue
                    with gateway(urls, ablation=config, executor_mode="inprocess",
                                 rate_limit_per_minute=0, executor_poll_seconds=0.05) as gw, \
                            serve(create_app(gw.state, sync_registry=False)) as url:  # fmt: skip
                        drive(url, gw.token, cfg["tool"], 1, cfg["warmup_requests"])
                        timing.enable(True)
                        t_run = time.perf_counter()
                        lat = drive(url, gw.token, cfg["tool"], conc, per_agent)
                        wall = time.perf_counter() - t_run
                        time.sleep(1.0)  # let the in-process executor finish dispatching
                        if config not in ("C1", "C2"):
                            # max age 0: seal everything the run produced, so the seal
                            # cost is measured per epoch (<= 100 events) in every run
                            policy = (SealPolicy.fixed(100, 0.0) if config in ("C3", "C4")
                                          else SealPolicy.adaptive(low_max_age_seconds=0.0,
                                                                   medium_max_age_seconds=0.0))  # fmt: skip
                            sealer = Sealer(engine=gw.engine, writer=EvidenceWriter(),
                                                crash=gw.state.crash, policy=policy,
                                                max_events=100, max_age_seconds=0.0)  # fmt: skip
                            sealer.drain()
                        samples = timing.drain()
                        timing.enable(False)
                    errors = sum(1 for _, code in lat if code != 201)
                    runs.append({"config": config, "concurrency": conc, "run": run, "n": len(lat),
                                 "errors": errors, "wall_s": wall})  # fmt: skip
                    for i, (ms, code) in enumerate(lat):
                        raw.append({"config": config, "concurrency": conc, "run": run, "i": i,
                                    "decision_ms": ms, "http": code})  # fmt: skip
                    for stage, dt in samples:
                        stages.append(
                            {
                                "config": config,
                                "concurrency": conc,
                                "run": run,
                                "stage": stage,
                                "ms": dt * 1000,
                            }
                        )
                    print(
                        f"{config} c={conc} run={run}: n={len(lat)} errors={errors} "
                        f"p50={percentile([x for x, _ in lat], 50):.1f} ms",
                        flush=True,
                    )
    write_csv(out / "raw.csv", raw)
    write_csv(out / "stages.csv", stages)
    write_csv(out / "runs.csv", runs)
    write_summary(out, cfg["seed"])
    write_json(out / "env.json", environment({"config": cfg}))
    return 0


STAGES = ("auth", "risk", "policy", "durable_write", "dispatch_tx", "adapter", "result_tx", "seal")


def summarize(
    raw: list[dict[str, str]],
    stages: list[dict[str, str]],
    seed: int,
    runs_meta: list[dict[str, str]] | None = None,
) -> list[dict[str, object]]:
    """From the RAW CSV rows only (strings), so the summary can be recomputed by anyone."""
    lat: dict[tuple[str, int], dict[int, list[float]]] = {}
    for r in raw:
        lat.setdefault((r["config"], int(r["concurrency"])), {}).setdefault(
            int(r["run"]), []
        ).append(float(r["decision_ms"]))
    st: dict[tuple[str, int, str], dict[int, list[float]]] = {}
    for s in stages:
        key = (s["config"], int(s["concurrency"]), s["stage"])
        st.setdefault(key, {}).setdefault(int(s["run"]), []).append(float(s["ms"]))
    order = {c: i for i, c in enumerate(["C0", "C1", "C2", "C3", "C4", "C5", "C6"])}
    rows = []
    for (config, conc), runs in sorted(
        lat.items(), key=lambda kv: (order.get(kv[0][0], 9), kv[0][1])
    ):
        row: dict[str, object] = {"config": config, "concurrency": conc, "runs": len(runs),
                                  "n": sum(len(v) for v in runs.values())}  # fmt: skip
        for p in (50, 95, 99):
            m, lo, hi = bootstrap_ci([percentile(v, p) for v in runs.values()], seed=seed)
            row[f"p{p}_ms"], row[f"p{p}_ci_lo"], row[f"p{p}_ci_hi"] = (
                round(m, 3),
                round(lo, 3),
                round(hi, 3),
            )
        meta = [
            m for m in runs_meta or [] if (m["config"], int(m["concurrency"])) == (config, conc)
        ]
        if meta:
            for name, vals in (
                ("error_rate", [int(m["errors"]) / int(m["n"]) for m in meta]),
                ("throughput_rps", [int(m["n"]) / float(m["wall_s"]) for m in meta]),
            ):
                m_, lo, hi = bootstrap_ci(vals, seed=seed)
                row[name], row[f"{name}_ci_lo"], row[f"{name}_ci_hi"] = (
                    round(m_, 4), round(lo, 4), round(hi, 4))  # fmt: skip
        for stage in STAGES:
            per_run = [statistics.fmean(v) for v in st.get((config, conc, stage), {}).values()]
            if per_run:
                m, lo, hi = bootstrap_ci(per_run, seed=seed)
                row[f"{stage}_ms"], row[f"{stage}_ci_lo"], row[f"{stage}_ci_hi"] = (
                    round(m, 4), round(lo, 4), round(hi, 4))  # fmt: skip
        rows.append(row)
    return rows


def write_summary(out: Path, seed: int) -> None:
    rows = summarize(read_csv(out / "raw.csv"), read_csv(out / "stages.csv"), seed,
                     read_csv(out / "runs.csv"))  # fmt: skip
    fields = ["config", "concurrency", "runs", "n"]
    fields += [
        f"{k}{x}" for k in ("error_rate", "throughput_rps") for x in ("", "_ci_lo", "_ci_hi")
    ]
    fields += [f"p{p}_{x}" for p in (50, 95, 99) for x in ("ms", "ci_lo", "ci_hi")]
    fields += [f"{s}_{x}" for s in STAGES for x in ("ms", "ci_lo", "ci_hi")]
    write_csv(out / "summary.csv", rows, fields)


if __name__ == "__main__":
    raise SystemExit(main())
