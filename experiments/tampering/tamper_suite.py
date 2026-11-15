"""Reusable tamper suite (Phase 3; extended in later phases).

Input: an honest chain export (``agw-export/v1``) and epochs export (``agw-epochs/v1``) of one
tenant. Each attack returns tampered exports; ``run_matrix`` verifies them with the standalone
verifier (``agw_verifier``) under three trust settings:

    none     no external trust root (verifier can only say UNANCHORED at best)
    before   trusted root of the epoch BEFORE the attacked one (an older anchor)
    after    trusted root of the original LATEST epoch (>= the attacked epoch)

Adversary models:
    naive       edits stored bytes only (no recomputation)
    rewriter    full DB control: re-encodes headers, re-chains every later event, re-seals every
                later epoch consistently. The strongest insider without the trusted root.

Only uses agw_verifier (no gateway imports), so it can run against exports from any system.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from agw_verifier.cbor import dumps, loads
from agw_verifier.chain import event_hash
from agw_verifier.epochs import verify_epochs
from agw_verifier.merkle import ZERO32, epoch_root, root_of


@dataclass
class Material:
    meta: dict[str, Any]
    events: list[dict[str, Any]]  # {"rec": decoded header, "payload": hex | None}
    epochs_meta: dict[str, Any]
    epochs: list[dict[str, Any]]

    @classmethod
    def load(cls, event_lines: list[str], epoch_lines: list[str]) -> Material:
        meta, *ev = (json.loads(x) for x in event_lines if x.strip())
        emeta, *ep = (json.loads(x) for x in epoch_lines if x.strip())
        events = [
            {"rec": loads(bytes.fromhex(e["header"])), "payload": e.get("payload")} for e in ev
        ]
        return cls(meta, events, emeta, ep)

    def copy(self) -> Material:
        return Material(
            dict(self.meta),
            [{"rec": dict(e["rec"]), "payload": e["payload"]} for e in self.events],
            dict(self.epochs_meta),
            [dict(r) for r in self.epochs],
        )

    def lines(self) -> tuple[list[str], list[str]]:
        ev = [json.dumps(self.meta)]
        for e in self.events:
            line = {"seq": e["rec"]["seq"], "header": dumps(e["rec"]).hex()}
            if e["payload"] is not None:
                line["payload"] = e["payload"]
            ev.append(json.dumps(line))
        return ev, [json.dumps(self.epochs_meta), *(json.dumps(r) for r in self.epochs)]

    def epoch_of(self, seq: int) -> int:
        return next(r["epoch_no"] for r in self.epochs if r["first_seq"] <= seq <= r["last_seq"])


# --------------------------------------------------------------------------- rewriting
def rechain(m: Material) -> None:
    """Renumber seq by position and recompute every prev link (attacker re-encodes headers)."""
    prev = ZERO32
    for i, e in enumerate(m.events):
        e["rec"]["seq"], e["rec"]["prev"] = i, prev
        prev = event_hash(dumps(e["rec"]))


def reseal(m: Material, sizes: list[int]) -> None:
    """Re-seal epochs of the given sizes over the (re-chained) events, consistently."""
    hashes = [event_hash(dumps(e["rec"])) for e in m.events]
    tenant, out, first, prev = m.epochs_meta["tenant"], [], 0, ZERO32
    for no, size in enumerate(sizes):
        if size <= 0:
            continue
        last = first + size - 1
        mroot = root_of(hashes[first : last + 1])
        root = epoch_root(tenant, len(out), size, first, last, mroot, prev)
        out.append(
            {
                "tenant": tenant,
                "epoch_no": len(out),
                "tree_size": size,
                "first_seq": first,
                "last_seq": last,
                "merkle_root": mroot.hex(),
                "prev_root": prev.hex(),
                "epoch_root": root.hex(),
                "sealed_at": None,
                "seal_reason": "MANUAL",
            }
        )
        first, prev = last + 1, root
        del no
    m.epochs = out


def _sizes(m: Material) -> list[int]:
    return [r["tree_size"] for r in m.epochs]


def _drop_unsealed_tail(m: Material) -> None:
    last = m.epochs[-1]["last_seq"]
    m.events = [e for e in m.events if e["rec"]["seq"] <= last]


# --------------------------------------------------------------------------- attacks
def edit_event_naive(m: Material, seq: int) -> Material:
    t = m.copy()
    rec = t.events[seq]["rec"]
    rec["ts"] = rec["ts"] + 1  # header changed, nothing recomputed
    return t


def edit_event(m: Material, seq: int) -> Material:
    t = m.copy()
    _drop_unsealed_tail(t)
    t.events[seq]["rec"]["ts"] += 1
    rechain(t)
    reseal(t, _sizes(m))
    return t


def delete_event(m: Material, seq: int) -> Material:
    t = m.copy()
    _drop_unsealed_tail(t)
    sizes = _sizes(m)
    k = m.epoch_of(seq)
    del t.events[seq]
    sizes[k] -= 1
    rechain(t)
    reseal(t, sizes)
    return t


def reorder_events(m: Material, seq: int) -> Material:
    t = m.copy()
    _drop_unsealed_tail(t)
    t.events[seq], t.events[seq + 1] = t.events[seq + 1], t.events[seq]
    rechain(t)
    reseal(t, _sizes(m))
    return t


def delete_epoch_naive(m: Material, epoch_no: int) -> Material:
    t = m.copy()
    t.epochs = [r for r in t.epochs if r["epoch_no"] != epoch_no]
    return t


def delete_epoch(m: Material, epoch_no: int) -> Material:
    t = m.copy()
    _drop_unsealed_tail(t)
    r = m.epochs[epoch_no]
    t.events = [e for e in t.events if not r["first_seq"] <= e["rec"]["seq"] <= r["last_seq"]]
    sizes = [s for i, s in enumerate(_sizes(m)) if i != epoch_no]
    rechain(t)
    reseal(t, sizes)
    return t


def truncate_tail(m: Material, epoch_no: int) -> Material:
    t = m.copy()
    first = m.epochs[epoch_no]["first_seq"]
    t.epochs = [r for r in t.epochs if r["epoch_no"] < epoch_no]
    t.events = [e for e in t.events if e["rec"]["seq"] < first]
    return t


def fork_epoch(m: Material, epoch_no: int) -> Material:
    """A second, different epoch `epoch_no` with the SAME prev_root (equivocation)."""
    t = m.copy()
    _drop_unsealed_tail(t)
    seq = m.epochs[epoch_no]["first_seq"]
    t.events[seq]["rec"]["ts"] += 7
    rechain(t)
    reseal(t, _sizes(m))
    assert t.epochs[epoch_no]["prev_root"] == m.epochs[epoch_no]["prev_root"]
    assert t.epochs[epoch_no]["epoch_root"] != m.epochs[epoch_no]["epoch_root"]
    return t


@dataclass(frozen=True)
class Attack:
    name: str
    adversary: str
    fn: Callable[[Material, int], Material]
    target: str  # "event" (arg = seq) or "epoch" (arg = epoch_no)


ATTACKS = [
    Attack("edit event", "naive", edit_event_naive, "event"),
    Attack("edit event", "rewriter", edit_event, "event"),
    Attack("delete event", "rewriter", delete_event, "event"),
    Attack("reorder two events", "rewriter", reorder_events, "event"),
    Attack("delete whole epoch", "naive", delete_epoch_naive, "epoch"),
    Attack("delete whole epoch", "rewriter", delete_epoch, "epoch"),
    Attack("truncate tail (from epoch)", "rewriter", truncate_tail, "epoch"),
    Attack("fork epoch (same prev, other root)", "rewriter", fork_epoch, "epoch"),
]


def run_matrix(m: Material, attacked_epoch: int) -> list[dict[str, Any]]:
    """Attack epoch `attacked_epoch` (>= 1) and verify under the three trust settings."""
    if not 1 <= attacked_epoch < len(m.epochs):
        raise ValueError("need an attacked epoch with one epoch before it")
    latest = m.epochs[-1]
    trust = {
        "none": (None, None),
        "before": (bytes.fromhex(m.epochs[attacked_epoch - 1]["epoch_root"]), attacked_epoch - 1),
        "after": (bytes.fromhex(latest["epoch_root"]), latest["epoch_no"]),
    }
    rows = []
    for atk in ATTACKS:
        arg = m.epochs[attacked_epoch]["first_seq"] + 1 if atk.target == "event" else attacked_epoch
        tampered = atk.fn(m, arg)
        ev, ep = tampered.lines()
        row: dict[str, Any] = {"attack": atk.name, "adversary": atk.adversary}
        for label, (root, epoch) in trust.items():
            res = verify_epochs(ep, trusted_root=root, trusted_epoch=epoch, event_lines=ev)
            row[label] = res.result
            row[f"{label}_reason"] = res.reason
        rows.append(row)
    return rows


def detected(result: str) -> bool:
    return result not in ("VERIFIED", "UNANCHORED")


def markdown(rows: list[dict[str, Any]]) -> str:
    out = [
        "| Attack | Adversary | No trust root | Trusted root before attacked epoch | Trusted root at/after attacked epoch |",
        "|---|---|---|---|---|",
    ]
    for r in rows:
        cells = [
            f"{'**detected**' if detected(r[k]) else 'not detected'} ({r[k]}{', ' + r[k + '_reason'] if r[k + '_reason'] else ''})"
            for k in ("none", "before", "after")
        ]
        out.append(f"| {r['attack']} | {r['adversary']} | " + " | ".join(cells) + " |")
    return "\n".join(out)
