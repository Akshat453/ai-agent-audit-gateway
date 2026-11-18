"""RQ7: independent audit on a "fresh machine".

    uv run python -m experiments.rq7_audit.run

1. PRODUCER (operator side): a real gateway (C6) + worker sealing + anchoring to a throwaway
   Anvil chain (EpochAnchor from the committed artifact). It runs `actions` actions, seals
   (fixed 100), anchors and finalises every epoch, then leaves an unsealed tail. It exports an
   AUDIT KIT: chain export, epochs export, `bundles` per-event evidence bundles, the pinned
   trust config (agw-anchor-trust/v1) - plus "missing evidence" variants of the kit.
2. AUDITOR (fresh machine): a new container from the pinned python:3.12-slim image
   (same digest as infra/docker/gateway/Dockerfile) with ONLY the kit (read-only) and the
   verifier wheel mounted. `pip install --no-index` of the stdlib-only wheel - no repo, no
   database, no gateway, no PyPI. Its only network use is the chain RPC (the public chain in
   a real audit; Anvil here). Every check is the `agw-verify` CLI; each is timed.

Metrics: success rate on the honest kit (VERIFIED / checks), time per check and for the
whole audit, and the detection rate for each missing-evidence class (any result other than
VERIFIED counts as detected; INCOMPLETE is reported separately from TAMPERED).
"""

from __future__ import annotations

import argparse
import io
import json
import random
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from experiments.lib.common import (
    REPO,
    environment,
    load_config,
    results_dir,
    write_csv,
    write_json,
)
from experiments.lib.stack import gateway, postgres

HERE = Path(__file__).resolve().parent
IMAGE = "python@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b"

AUDIT_SCRIPT = r"""
import json, subprocess, sys, time
cases = json.load(open("/kit/cases.json"))
rpc = sys.argv[1]
out = []
for c in cases:
    argv = ["agw-verify", c["cmd"], *c["args"], "--json"]
    if c["cmd"] != "chain":
        argv += ["--chain-rpc", rpc, "--trust-config", "/kit/trust.json"]
    t0 = time.perf_counter()
    p = subprocess.run(argv, capture_output=True, text=True, cwd="/kit")
    dt = time.perf_counter() - t0
    try:
        rep = json.loads(p.stdout)
    except ValueError:
        rep = {"result": "NO_OUTPUT", "reason": p.stderr[-200:]}
    out.append({"id": c["id"], "class": c["class"], "rc": p.returncode, "seconds": round(dt, 4),
                "result": rep.get("result"), "reason": rep.get("reason")})
json.dump(out, sys.stdout)
"""


class _Shim:
    """The bits of a test `Gw` that anchorkit.register / Recorder.anchorer use."""

    def __init__(self, gw: Any) -> None:
        self.engine, self.state = gw.engine, gw.state
        self.world = type("W", (), {"tenant_id": gw.tenant})()


def produce(cfg: dict[str, Any], kit: Path) -> tuple[Any, str]:
    """Returns (anvil container, rpc url): the chain stays up for the auditor."""
    from fastapi.testclient import TestClient
    from tests.anchorkit import deploy_registry, register, start_anvil

    from agw_gateway.api.app import create_app
    from agw_gateway.evidence.bundle import build_bundle, export_epochs
    from agw_gateway.evidence.export import export_chain
    from agw_worker.sealing import Sealer
    from agw_worker.sealing.policy import SealPolicy

    anvil, rpc = start_anvil()
    chain = deploy_registry(rpc, anvil)
    rng = random.Random(cfg["seed"])
    with postgres() as urls, gateway(urls, ablation=None, rate_limit_per_minute=0) as gw:
        from agw_gateway.db import create_db_engine

        mig = create_db_engine(urls.migrator, pool_size=1)
        rec = register(chain, mig, _Shim(gw))
        with TestClient(create_app(gw.state, sync_registry=False)) as c:
            h = {"Authorization": f"Bearer {gw.token}"}
            tools = [("test_echo", {"text": "a"}), ("public_doc_search", {"query": "evidence"}),
                     ("create_ticket", {"title": "audit"}), ("delete_record",
                     {"record_id": "00000000-0000-0000-0000-000000000001"})]  # fmt: skip

            def act(i: int) -> None:
                tool, args = tools[i % len(tools)]
                c.post("/v1/actions", headers={**h, "Idempotency-Key": f"k{i}"},
                       json={"run_id": "00000000-0000-0000-0000-0000000000a7", "tool": tool,
                             "environment": "dev", "args": args})  # fmt: skip

            for i in range(cfg["actions"]):
                act(i)
            while gw.state.executor.run_once():
                pass
            Sealer(engine=gw.engine, writer=gw.state.writer, crash=gw.state.crash,
                   policy=SealPolicy.fixed(100, 0.0)).drain()  # fmt: skip
            a = rec.anchorer()
            for _ in range(4):
                a.tick()
                chain.mine(2)
            for i in range(cfg["actions"], cfg["actions"] + cfg["tail_actions"]):
                act(i)  # unsealed tail
            while gw.state.executor.run_once():
                pass
        statuses = [r.status for r in rec.anchors()]
        assert statuses and set(statuses) == {"FINALIZED"}, statuses
        ev, ep = io.StringIO(), io.StringIO()
        export_chain(gw.engine, gw.tenant, ev)
        from sqlalchemy import text

        with gw.engine.connect() as conn:
            export_epochs(conn, gw.tenant, ep)
            sealed_last = conn.execute(text("SELECT max(last_seq) FROM epochs WHERE tenant_id = :t"),
                                       {"t": gw.tenant}).scalar_one()  # fmt: skip
            ids = [r.event_id for r in conn.execute(text(
                "SELECT event_id FROM evidence_events WHERE tenant_id = :t AND seq <= :s ORDER BY seq"),
                {"t": gw.tenant, "s": sealed_last})]  # fmt: skip
            sample = rng.sample(ids, min(cfg["bundles"], len(ids)))
            (kit / "bundles").mkdir(parents=True)
            for n, eid in enumerate(sample):
                b = build_bundle(conn, eid, tenant_id=gw.tenant)
                (kit / "bundles" / f"b{n:04d}.json").write_text(json.dumps(b))
        mig.dispose()
    trust = rec.trust()
    (kit / "trust.json").write_text(json.dumps(trust))
    (kit / "events.jsonl").write_text(ev.getvalue())
    (kit / "epochs.jsonl").write_text(ep.getvalue())
    missing_variants(kit, ev.getvalue(), ep.getvalue(), cfg, rng)
    return anvil, rpc


def missing_variants(kit: Path, ev: str, ep: str, cfg: dict[str, Any], rng: random.Random) -> None:
    """Kits with evidence REMOVED (not edited): what an auditor must notice is missing."""
    lines, elines = ev.splitlines(), ep.splitlines()
    head, events = lines[0], lines[1:]
    ehead, epochs = elines[0], [json.loads(x) for x in elines[1:]]
    sealed_last = max(e["last_seq"] for e in epochs)
    d = kit / "missing"
    d.mkdir()
    cases: list[dict[str, Any]] = []
    for k in range(cfg["missing_cases_per_class"]):
        # 1. one sealed event dropped from the chain export (chain check)
        i = rng.randint(1, sealed_last - 1)
        p = d / f"drop-event-{k}.jsonl"
        p.write_text("\n".join([head, *events[:i], *events[i + 1 :]]) + "\n")
        cases.append(
            {
                "class": "event dropped (chain export)",
                "cmd": "chain",
                "args": ["--export", str(p.relative_to(kit))],
            }
        )
        cases.append({"class": "event dropped (epochs + events, anchors)", "cmd": "epochs",
                      "args": ["--export", "epochs.jsonl", "--events", str(p.relative_to(kit))]})  # fmt: skip
        # 2. the newest anchored epoch removed from the epochs export
        p = d / f"drop-last-epoch-{k}.jsonl"
        p.write_text("\n".join([ehead, *[json.dumps(e) for e in epochs[:-1]]]) + "\n")
        cases.append(
            {
                "class": "newest anchored epoch removed",
                "cmd": "epochs",
                "args": ["--export", str(p.relative_to(kit))],
            }
        )
        # 3. a middle epoch removed
        j = rng.randint(1, len(epochs) - 2)
        p = d / f"drop-mid-epoch-{k}.jsonl"
        p.write_text(
            "\n".join([ehead, *[json.dumps(e) for n, e in enumerate(epochs) if n != j]]) + "\n"
        )
        cases.append(
            {
                "class": "middle epoch removed",
                "cmd": "epochs",
                "args": ["--export", str(p.relative_to(kit))],
            }
        )
        # 4. sealed events truncated at the end (export stops inside the last anchored epoch)
        cut = rng.randint(epochs[-1]["first_seq"], sealed_last)
        p = d / f"truncate-sealed-{k}.jsonl"
        p.write_text("\n".join([head, *events[:cut]]) + "\n")
        cases.append({"class": "sealed tail truncated (epochs + events, anchors)", "cmd": "epochs",
                      "args": ["--export", "epochs.jsonl", "--events", str(p.relative_to(kit))]})  # fmt: skip
        # 5. the UNSEALED tail truncated (03 R2: expected NOT to be detectable)
        tail = len(events) - (sealed_last + 1)
        p = d / f"truncate-unsealed-{k}.jsonl"
        p.write_text("\n".join([head, *events[: len(events) - rng.randint(1, tail)]]) + "\n")
        cases.append(
            {
                "class": "UNSEALED tail truncated",
                "cmd": "chain",
                "args": ["--export", str(p.relative_to(kit))],
            }
        )
        # 6. a bundle whose Merkle inclusion proof was stripped
        src = rng.choice(sorted((kit / "bundles").glob("*.json")))
        b = json.loads(src.read_text())
        b["proof"]["audit_path"] = []  # the sibling hashes withheld
        p = d / f"bundle-no-proof-{k}.json"
        p.write_text(json.dumps(b))
        cases.append(
            {
                "class": "bundle inclusion proof withheld",
                "cmd": "event",
                "args": ["--bundle", str(p.relative_to(kit))],
            }
        )
    honest = [{"class": "honest: chain", "cmd": "chain", "args": ["--export", "events.jsonl"]},
              {"class": "honest: epochs + events + anchors", "cmd": "epochs",
               "args": ["--export", "epochs.jsonl", "--events", "events.jsonl"]}]  # fmt: skip
    honest += [{"class": "honest: event bundle", "cmd": "event", "args": ["--bundle", f"bundles/{b.name}"]}
               for b in sorted((kit / "bundles").glob("*.json"))]  # fmt: skip
    allc = honest + cases
    for n, c in enumerate(allc):
        c["id"] = n
    (kit / "cases.json").write_text(json.dumps(allc))


def audit(kit: Path, wheel_dir: Path, rpc: str) -> tuple[list[dict[str, Any]], float]:
    (kit / "audit.py").write_text(AUDIT_SCRIPT)
    port = rpc.rsplit(":", 1)[1]
    t0 = time.perf_counter()
    p = subprocess.run(
        ["docker", "run", "--rm", "--add-host", "host.docker.internal:host-gateway",  # noqa: S607
         "-v", f"{kit}:/kit:ro", "-v", f"{wheel_dir}:/wheel:ro", "--entrypoint", "sh", IMAGE, "-c",
         "pip install -q --no-index --root-user-action=ignore /wheel/*.whl >/dev/null && "
         f"python /kit/audit.py http://host.docker.internal:{port}"],
        capture_output=True, text=True, check=False, timeout=1800,
    )  # fmt: skip
    total = time.perf_counter() - t0
    if p.returncode != 0:
        raise RuntimeError(p.stderr[-2000:])
    return json.loads(p.stdout), total


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=str(HERE / "config.toml"))
    cfg = load_config(Path(ap.parse_args().config))
    out = results_dir(HERE)
    work = Path(tempfile.mkdtemp(prefix="rq7-"))
    kit, wheel = work / "kit", work / "wheel"
    kit.mkdir()
    subprocess.run(["uv", "build", "-q", "--wheel", "packages/verifier", "-o", str(wheel)],  # noqa: S607
                   cwd=REPO, check=True)  # fmt: skip
    anvil, rpc = produce(cfg, kit)
    try:
        rows, total = audit(kit, wheel, rpc)
    finally:
        anvil.stop()
    write_csv(out / "raw.csv", rows)
    summary = []
    for cls in dict.fromkeys(r["class"] for r in rows):
        rs = [r for r in rows if r["class"] == cls]
        secs = sorted(r["seconds"] for r in rs)
        summary.append({
            "class": cls, "checks": len(rs),
            "verified": sum(r["result"] == "VERIFIED" for r in rs),
            "tampered": sum(r["result"] == "TAMPERED" for r in rs),
            "incomplete": sum(r["result"] == "INCOMPLETE" for r in rs),
            "other": sum(r["result"] not in ("VERIFIED", "TAMPERED", "INCOMPLETE") for r in rs),
            "rate": round((sum(r["result"] == "VERIFIED" for r in rs) if cls.startswith("honest")
                           else sum(r["result"] != "VERIFIED" for r in rs)) / len(rs), 4),
            "median_s": secs[len(secs) // 2], "max_s": secs[-1],
            "reasons": "; ".join(sorted({str(r["reason"]) for r in rs if r["reason"]}))[:300],
        })  # fmt: skip
    write_csv(out / "summary.csv", summary)
    files = sorted(p.relative_to(kit).as_posix() for p in kit.rglob("*") if p.is_file())
    write_json(out / "env.json", environment({
        "config": cfg, "auditor_image": IMAGE, "audit_wall_seconds_incl_container_start": round(total, 2),
        "kit_files": len(files), "kit_bytes": sum((kit / f).stat().st_size for f in files),
        "auditor_has": ["kit (read-only)", "agw_verifier wheel (stdlib only)", "chain RPC"],
    }))  # fmt: skip
    shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
