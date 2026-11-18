"""RQ5: failure resilience. Final states correct, no duplicate side effects for
non-idempotent tools, evidence consistent (independent verifier), under:

  A. kill  - a REAL process death (os._exit in a subprocess, no cleanup) at each lifecycle
             step: after_tx1_commit, after_claim, after_dispatch_commit, after_adapter_return
             (x non-idempotent create_ticket / idempotent public_doc_search) and
             seal_before_commit; recovery = a NEW gateway process state after the lease
             expired (no manual DB edits). Repeated `kill_reps` times each.
  B. partition - the database container is frozen (`docker pause`: TCP stays open, nothing
             answers) while clients send requests; then unpaused. Clients retry timed-out
             requests with the SAME Idempotency-Key (the documented client contract).
  C. existing fault tests re-run `test_reps` times: DB down, object store unreachable, chain
             RPC down for a CRITICAL pre-anchor, RPC killed mid-submit (x2), RPC outage
             back-off, tool timeout. Each asserts its own final states / side effects.

    uv run python -m experiments.rq5_faults.run
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from dataclasses import asdict
from pathlib import Path
from typing import Any

import httpx

from experiments.lib.common import (
    REPO,
    environment,
    load_config,
    results_dir,
    write_csv,
    write_json,
)
from experiments.lib.stack import gateway, new_tenant, postgres_container
from experiments.rq5_faults.kit import ADAPTER_TIMEOUT, LEASE, TOOLS, effects, logged_spies, verify

HERE = Path(__file__).resolve().parent
POINTS = ["after_tx1_commit", "after_claim", "after_dispatch_commit", "after_adapter_return"]
ARGS = {"create_ticket": {"title": "rq5"}, "public_doc_search": {"query": "evidence"}}
FINAL_EVENT = {"COMPLETED": "ACTION_COMPLETED", "OUTCOME_UNKNOWN": "ACTION_OUTCOME_UNKNOWN",
               "FAILED": "ACTION_FAILED"}  # fmt: skip
EXISTING_TESTS = {
    "DB down": "tests/e2e/test_fail_closed.py::test_db_down_fails_closed",
    "object store unreachable": "tests/e2e/test_encryption.py::test_object_storage_down_fails_closed_for_large_payloads_only",
    "RPC down (CRITICAL pre-anchor)": "tests/e2e/test_anchoring.py::test_critical_pre_anchor_rpc_down_fails_closed",
    "RPC killed mid-submit": "tests/e2e/test_anchoring.py::test_kill_rpc_mid_submit_restart_same_root_single_anchor",
    "RPC killed + crash before broadcast": "tests/e2e/test_anchoring.py::test_kill_rpc_mid_submit_restart_crash_before_broadcast",
    "RPC outage back-off": "tests/e2e/test_anchoring.py::test_rpc_outage_backs_off_and_metrics_show_backlog",
    "tool timeout": "tests/e2e/test_flow.py::test_adapter_timeout_is_outcome_unknown",
}


def expected(point: str, tool: str) -> tuple[str, str]:
    """(status, side effects) per ADR-0011: never re-invoke a non-idempotent tool whose
    outcome is unknown; an idempotent one is re-dispatched."""
    if point in ("after_tx1_commit", "after_claim", "seal_before_commit"):
        return "COMPLETED", "1"
    if TOOLS[tool]:
        return "COMPLETED", ">=1"
    return "OUTCOME_UNKNOWN", "0" if point == "after_dispatch_commit" else "1"


def action_state(gw: Any, run_id: str) -> tuple[str | None, str | None, str | None]:
    from sqlalchemy import text

    with gw.engine.connect() as conn:
        a = conn.execute(text("SELECT action_id, status FROM actions WHERE run_id = :r"),
                         {"r": run_id}).one_or_none()  # fmt: skip
        if a is None:
            return None, None, None
        last = conn.execute(text("SELECT event_type FROM evidence_events WHERE action_id = :a "
                                 "ORDER BY seq DESC LIMIT 1"), {"a": a.action_id}).scalar()  # fmt: skip
    return str(a.action_id), a.status, last


def kill_case(urls: Any, point: str, tool: str, rep: int, log: Path) -> dict[str, Any]:
    from agw_worker.sealing import Sealer
    from agw_worker.sealing.policy import SealPolicy

    tenant = new_tenant_for(urls)
    run_id = str(uuid.uuid4())
    spec = {"urls": asdict(urls), "tenant": tenant[0], "token": tenant[1], "point": point,
            "tool": tool, "args": ARGS[tool], "run_id": run_id, "log": str(log)}  # fmt: skip
    proc = subprocess.run([sys.executable, "-m", "experiments.rq5_faults.victim", json.dumps(spec)],
                          cwd=REPO, capture_output=True, text=True, timeout=180, check=False)  # fmt: skip
    died = proc.returncode == 137
    time.sleep(LEASE + 0.5)  # the dead process's lease runs out (no manual DB edits)
    with gateway(urls, ablation=None, tenant=tenant, spies=logged_spies(log), lease_seconds=LEASE,
                 adapter_timeout_seconds=ADAPTER_TIMEOUT) as gw:  # fmt: skip
        for _ in range(2):
            while gw.state.executor.run_once():
                pass
            gw.state.reconciler.run_once()
        Sealer(engine=gw.engine, writer=gw.state.writer, crash=gw.state.crash,
               policy=SealPolicy.fixed(100, 0.0)).drain()  # fmt: skip
        aid, status, last = action_state(gw, run_id)
        chain, epochs = verify(gw)
    n = effects(log, aid or "-")
    exp_status, exp_effects = expected(point, tool)
    effects_ok = n >= 1 if exp_effects == ">=1" else n == int(exp_effects)
    consistent = last == FINAL_EVENT.get(status or "", "?") and chain == "VERIFIED" and \
        epochs in ("VERIFIED", "UNANCHORED")  # fmt: skip
    duplicate = int(not TOOLS[tool] and n > 1)
    return {"point": point, "tool": tool, "rep": rep, "died_at_point": int(died),
            "victim_rc": proc.returncode, "status": status, "expected_status": exp_status,
            "side_effects": n, "expected_side_effects": exp_effects, "last_event": last,
            "chain": chain, "epochs": epochs, "duplicate_side_effect": duplicate,
            "correct": int(died and status == exp_status and effects_ok and consistent)}  # fmt: skip


_MIG: dict[str, Any] = {}


def new_tenant_for(urls: Any) -> tuple[str, str]:
    from agw_gateway.db import create_db_engine

    if "e" not in _MIG:
        _MIG["e"] = create_db_engine(urls.migrator, pool_size=2)
    return new_tenant(_MIG["e"])


def partition(container: Any, urls: Any, cfg: dict[str, Any], log: Path) -> dict[str, Any]:
    from tests.servekit import serve

    from agw_gateway.api.app import create_app

    docker = container.get_wrapped_container()
    timeout = cfg["client_timeout_seconds"]
    outcomes: dict[str, int] = {}
    keys: list[str] = []
    with gateway(urls, ablation=None, spies=logged_spies(log), executor_mode="inprocess",
                 executor_poll_seconds=0.05, lease_seconds=LEASE, rate_limit_per_minute=0,
                 adapter_timeout_seconds=ADAPTER_TIMEOUT) as gw, \
            serve(create_app(gw.state, sync_registry=False)) as url:  # fmt: skip
        h = {"Authorization": f"Bearer {gw.token}"}

        def send(key: str) -> str:
            try:
                r = httpx.post(f"{url}/v1/actions", timeout=timeout, headers={**h, "Idempotency-Key": key},
                               json={"run_id": key, "tool": "create_ticket", "environment": "dev",
                                     "args": {"title": "partition"}})  # fmt: skip
                return str(r.status_code)
            except httpx.TimeoutException:
                return "client-timeout"

        def batch(label: str, n: int) -> None:
            res: list[str] = []
            lock = threading.Lock()

            def one() -> None:
                k = uuid.uuid4().hex
                out = send(k)
                with lock:
                    keys.append(k)
                    res.append(out)

            ths = [threading.Thread(target=one) for _ in range(n)]
            for th in ths:
                th.start()
            for th in ths:
                th.join()
            for o in res:
                outcomes[f"{label}:{o}"] = outcomes.get(f"{label}:{o}", 0) + 1

        batch("before", cfg["partition_requests"])
        docker.pause()
        t0 = time.time()
        batch("during", cfg["partition_requests"])
        time.sleep(max(0.0, cfg["partition_seconds"] - (time.time() - t0)))
        docker.unpause()
        healed = time.time()
        # client contract: retry every request with the SAME key until it has an answer
        retried = {k: send(k) for k in keys}
        for o in retried.values():
            outcomes[f"retry:{o}"] = outcomes.get(f"retry:{o}", 0) + 1
        batch("after", cfg["partition_requests"])
        deadline = time.time() + 60
        while time.time() < deadline:
            from sqlalchemy import text

            with gw.engine.connect() as conn:
                open_ = conn.execute(text("SELECT count(*) FROM actions WHERE tenant_id = :t AND status "
                                          "NOT IN ('COMPLETED','FAILED','OUTCOME_UNKNOWN','DENIED')"),
                                     {"t": gw.tenant}).scalar_one()  # fmt: skip
            if open_ == 0:
                break
            time.sleep(0.2)
        recovery_s = time.time() - healed
        with gw.engine.connect() as conn:
            rows = conn.execute(text("SELECT action_id, status, run_id FROM actions WHERE tenant_id = :t"),
                                {"t": gw.tenant}).all()  # fmt: skip
        chain, epochs = verify(gw)
    per_key: dict[str, int] = {}
    for r in rows:
        per_key[str(r.run_id)] = per_key.get(str(r.run_id), 0) + 1
    side = {str(r.action_id): effects(log, str(r.action_id)) for r in rows}
    completed_wo_effect = sum(
        1 for r in rows if r.status == "COMPLETED" and side[str(r.action_id)] != 1
    )
    effect_wo_completion = sum(1 for r in rows if side[str(r.action_id)] and r.status not in
                               ("COMPLETED", "OUTCOME_UNKNOWN"))  # fmt: skip
    return {
        "outcomes": outcomes, "actions": len(rows), "keys_sent": len(keys) + cfg["partition_requests"] * 0,
        "actions_per_key_max": max(per_key.values()) if per_key else 0,
        "duplicate_side_effects": sum(max(0, n - 1) for n in side.values()),
        "completed_without_exactly_one_effect": completed_wo_effect,
        "effect_without_completed_or_unknown": effect_wo_completion,
        "statuses": {s: sum(1 for r in rows if r.status == s) for s in {r.status for r in rows}},
        "chain": chain, "epochs_unsealed_ok": epochs, "seconds_to_all_final_after_heal": round(recovery_s, 2),
    }  # fmt: skip


def existing_tests(reps: int, out: Path) -> list[dict[str, Any]]:
    rows = []
    for rep in range(reps):
        xml = out / f"junit-{rep}.xml"
        subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                        f"--junitxml={xml}", *EXISTING_TESTS.values()],
                       cwd=REPO / "apps" / "gateway", capture_output=True, text=True, check=False)  # fmt: skip
        cases = {c.get("name"): c for c in ET.parse(xml).getroot().iter("testcase")}  # noqa: S314
        for fault, node in EXISTING_TESTS.items():
            c = cases.get(node.split("::")[1])
            ok = c is not None and not any(ch.tag in ("failure", "error", "skipped") for ch in c)
            rows.append({"fault": fault, "test": node, "rep": rep, "passed": int(ok)})
        xml.unlink()
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=str(HERE / "config.toml"))
    ap.add_argument("--only", choices=["kill", "partition", "tests"], default=None)
    a = ap.parse_args()
    cfg = load_config(Path(a.config))
    out = results_dir(HERE)
    log = Path(tempfile.mkdtemp(prefix="rq5-")) / "side-effects.log"
    if a.only in (None, "kill", "partition"):
        with postgres_container() as (container, urls):
            if a.only in (None, "kill"):
                rows = []
                cases = [(p, t) for p in POINTS for t in TOOLS] + [
                    ("seal_before_commit", "create_ticket")
                ]
                for rep in range(cfg["kill_reps"]):
                    for point, tool in cases:
                        row = kill_case(urls, point, tool, rep, log)
                        rows.append(row)
                        print(f"kill {point} {tool} rep={rep}: status={row['status']} "
                              f"effects={row['side_effects']} correct={row['correct']}", flush=True)  # fmt: skip
                write_csv(out / "kill.csv", rows)
            if a.only in (None, "partition"):
                res = partition(container, urls, cfg, log)
                print(json.dumps(res, indent=1), flush=True)
                write_json(out / "partition.json", res)
    if a.only in (None, "tests"):
        rows_t = existing_tests(cfg["test_reps"], out)
        write_csv(out / "existing-tests.csv", rows_t)
    write_json(out / "env.json", environment({"config": cfg}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
