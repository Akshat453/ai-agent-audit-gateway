"""RQ3: tamper detection rate + false positives, >= 1000 injected cases per class.

    uv run python -m experiments.rq3_tamper.run [--regenerate]

Material: one honest tenant export (headers + decrypted payloads) and its epochs, produced by the
REAL gateway (C6) and committed as results/material-*.jsonl so reruns are exact. Attacks reuse
experiments/tampering/tamper_suite.py at seeded random positions; verification is the standalone
`agw_verifier` (full audit: events re-hashed against every epoch's Merkle root).

Trust roots per case (what a detection needed):
  none    no external root (an auditor with only the export)
  before  the anchored root of the epoch BEFORE the attacked one (an older anchor)
  after   the anchored root of the latest epoch (an up-to-date on-chain anchor)
"""

from __future__ import annotations

import argparse
import io
import random
import sys
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

sys.path.insert(0, str(REPO / "experiments" / "tampering"))
from tamper_suite import (
    Material,
    delete_epoch,
    delete_epoch_naive,
    delete_event,
    detected,
    edit_event,
    edit_event_naive,
    fork_epoch,
    reorder_events,
    truncate_tail,
)

from agw_verifier.epochs import verify_epochs

HERE = Path(__file__).resolve().parent


def payload_swap(m: Material, seq: int, rng: random.Random) -> Material:
    t = m.copy()
    with_payload = [i for i, e in enumerate(t.events) if e["payload"] and i != seq]
    other = rng.choice(with_payload)
    t.events[seq]["payload"], t.events[other]["payload"] = (
        t.events[other]["payload"],
        t.events[seq]["payload"],
    )
    return t


def truncate_unsealed(m: Material, k: int) -> Material:
    t = m.copy()
    t.events = t.events[:-k]
    return t


def make_material(cfg: dict[str, Any], out: Path) -> None:
    from fastapi.testclient import TestClient

    from agw_gateway.api.app import create_app
    from agw_gateway.evidence.bundle import export_epochs
    from agw_gateway.evidence.export import export_chain
    from agw_worker.sealing import Sealer
    from agw_worker.sealing.policy import SealPolicy
    from experiments.lib.stack import gateway, postgres

    with postgres() as urls, gateway(urls, ablation=None, rate_limit_per_minute=0) as gw:
        with TestClient(create_app(gw.state, sync_registry=False)) as c:
            h = {"Authorization": f"Bearer {gw.token}"}

            def act(i: int) -> None:
                r = c.post("/v1/actions", json={"run_id": "00000000-0000-0000-0000-000000000001",
                           "tool": "test_echo", "environment": "dev", "args": {"text": f"m{i}"}},
                           headers={**h, "Idempotency-Key": f"k{i}"})  # fmt: skip
                assert r.status_code == 201

            for i in range(cfg["material_actions"]):
                act(i)
            while gw.state.executor.run_once():
                pass
            Sealer(engine=gw.engine, writer=gw.state.writer, crash=gw.state.crash,
                   policy=SealPolicy.fixed(100, 0.0)).drain()  # fmt: skip
            for i in range(cfg["material_tail_actions"]):
                act(10_000 + i)
            while gw.state.executor.run_once():
                pass
        ev, ep = io.StringIO(), io.StringIO()
        export_chain(gw.engine, gw.tenant, ev, store=gw.state.payloads)
        with gw.engine.connect() as conn:
            export_epochs(conn, gw.tenant, ep)
    (out / "material-events.jsonl").write_text(ev.getvalue())
    (out / "material-epochs.jsonl").write_text(ep.getvalue())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--regenerate", action="store_true")
    args = ap.parse_args()
    cfg = load_config(HERE / "config.toml")
    out = results_dir(HERE)
    if (
        args.regenerate
        or cfg["regenerate_material"]
        or not (out / "material-events.jsonl").exists()
    ):
        make_material(cfg, out)
    m = Material.load((out / "material-events.jsonl").read_text().splitlines(),
                      (out / "material-epochs.jsonl").read_text().splitlines())  # fmt: skip
    rng = random.Random(cfg["seed"])
    n_ep = len(m.epochs)
    sealed_last = m.epochs[-1]["last_seq"]
    tail = len(m.events) - (sealed_last + 1)
    latest = (bytes.fromhex(m.epochs[-1]["epoch_root"]), m.epochs[-1]["epoch_no"])

    def trust_for(epoch_no: int) -> dict[str, tuple[bytes | None, int | None]]:
        before = (
            (bytes.fromhex(m.epochs[epoch_no - 1]["epoch_root"]), epoch_no - 1)
            if epoch_no >= 1
            else (None, None)
        )
        return {"none": (None, None), "before": before, "after": latest}

    def rand_event() -> tuple[int, int]:  # a sealed event NOT in epoch 0 (so "before" exists)
        seq = rng.randint(m.epochs[1]["first_seq"], sealed_last - 1)
        return seq, m.epoch_of(seq)

    def on_event(attack: Any) -> Any:
        def make() -> tuple[Any, int]:
            seq, epoch_no = rand_event()
            return attack(m, seq), epoch_no

        return make

    def on_epoch(attack: Any) -> Any:
        def make() -> tuple[Any, int]:
            epoch_no = rng.randint(1, n_ep - 1)
            return attack(m, epoch_no), epoch_no

        return make

    classes = {
        "edit (naive)": on_event(edit_event_naive),
        "edit (rewriter)": on_event(edit_event),
        "delete event (rewriter)": on_event(delete_event),
        "reorder (rewriter)": on_event(reorder_events),
        "truncate sealed tail": on_epoch(truncate_tail),
        "truncate UNSEALED tail": lambda: (truncate_unsealed(m, rng.randint(1, tail)), n_ep - 1),
        "delete epoch (naive)": on_epoch(delete_epoch_naive),
        "delete epoch (rewriter)": on_epoch(delete_epoch),
        "fork / equivocation": on_epoch(fork_epoch),
        "payload swap": on_event(lambda mat, seq: payload_swap(mat, seq, rng)),
    }
    raw = []
    t0 = time.time()
    for name, make in classes.items():
        for case in range(cfg["cases_per_class"]):
            tampered, epoch_no = make()
            ev, ep = tampered.lines()
            row: dict[str, Any] = {"class": name, "case": case, "epoch": epoch_no}
            for label, (root, eno) in trust_for(epoch_no).items():
                if root is None and label != "none":
                    row[label] = "n/a"
                    continue
                res = verify_epochs(ep, trusted_root=root, trusted_epoch=eno, event_lines=ev)
                row[label], row[f"{label}_reason"] = res.result, res.reason
            raw.append(row)
        print(f"{name:<26} done ({time.time() - t0:.0f} s)", flush=True)
    # False positives: honest epoch-aligned prefixes with their own latest root as the anchor.
    fp = []
    for case in range(cfg["honest_prefix_cases"]):
        k = rng.randint(1, n_ep)
        t = m.copy()
        last = m.epochs[k - 1]["last_seq"]
        t.events = [e for e in t.events if e["rec"]["seq"] <= last]
        t.epochs = t.epochs[:k]
        ev, ep = t.lines()
        root = bytes.fromhex(t.epochs[-1]["epoch_root"])
        res_none = verify_epochs(ep, event_lines=ev)
        res_anchor = verify_epochs(ep, trusted_root=root, trusted_epoch=k - 1, event_lines=ev)
        fp.append({"case": case, "epochs": k, "none": res_none.result, "after": res_anchor.result})
    write_csv(
        out / "raw.csv",
        raw,
        [
            "class",
            "case",
            "epoch",
            "none",
            "none_reason",
            "before",
            "before_reason",
            "after",
            "after_reason",
        ],
    )
    write_csv(out / "false_positives.csv", fp)
    summary = []
    for name in classes:
        rows = [r for r in raw if r["class"] == name]
        s: dict[str, Any] = {"class": name, "cases": len(rows)}
        for label in ("none", "before", "after"):
            usable = [r for r in rows if r[label] != "n/a"]
            s[f"detected_{label}"] = sum(detected(r[label]) for r in usable)
            s[f"rate_{label}"] = round(s[f"detected_{label}"] / len(usable), 4) if usable else None
        summary.append(s)
    summary.append({"class": "HONEST prefixes (false positives)", "cases": len(fp),
                    "detected_none": sum(detected(r["none"]) for r in fp), "rate_none": round(sum(detected(r["none"]) for r in fp) / len(fp), 4),
                    "detected_after": sum(detected(r["after"]) for r in fp), "rate_after": round(sum(detected(r["after"]) for r in fp) / len(fp), 4)})  # fmt: skip
    write_csv(
        out / "summary.csv",
        summary,
        [
            "class",
            "cases",
            "detected_none",
            "rate_none",
            "detected_before",
            "rate_before",
            "detected_after",
            "rate_after",
        ],
    )
    write_json(out / "env.json", environment({"config": cfg, "material_events": len(m.events),
                                              "material_epochs": n_ep, "unsealed_tail": tail}))  # fmt: skip
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
