"""Epoch-record and evidence-bundle verification (docs/gateway/06 §6-8, 10 §3 V1-V4, V8).

Results (worst first): TAMPERED, INVALID_PROOF, INCOMPLETE, UNANCHORED, VERIFIED.

* UNANCHORED: every check passed, but no external trust root was supplied, so the result only
  says the material is internally consistent ("locally sealed only"). A trusted root must come
  from outside the system being audited (from Phase 6: an on-chain anchor).
* A trusted root for epoch N vouches for every epoch <= N (each R_t commits to R_{t-1}). It
  says nothing about epochs > N.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from agw_verifier import STATEMENT
from agw_verifier.cbor import NonCanonical, loads
from agw_verifier.chain import Report, event_hash, payload_digest, verify_lines
from agw_verifier.merkle import ZERO32, epoch_root, inclusion_ok, root_of

EPOCHS_FORMAT = "agw-epochs/v1"
BUNDLE_FORMAT = "agw-bundle/v1"
LOCAL_ONLY = "locally sealed only: no external trust root was given"
_ORDER = ["TAMPERED", "INVALID_PROOF", "INCOMPLETE", "UNANCHORED", "VERIFIED"]


@dataclass
class Result:
    result: str = "VERIFIED"
    tenant: str | None = None
    reason: str | None = None
    first_bad_epoch: int | None = None
    first_bad_seq: int | None = None
    epochs_checked: int = 0
    last_epoch_no: int | None = None
    last_epoch_root: str | None = None
    trusted_epoch: int | None = None
    unsealed_events: int | None = None
    notes: list[str] = field(default_factory=list)
    statement: str = STATEMENT

    def fail(
        self, result: str, reason: str, *, epoch: int | None = None, seq: int | None = None
    ) -> Result:
        if _ORDER.index(result) < _ORDER.index(self.result) or self.reason is None:
            self.result, self.reason = result, reason
            self.first_bad_epoch, self.first_bad_seq = epoch, seq
        return self

    @property
    def ok(self) -> bool:
        return self.result in ("VERIFIED", "UNANCHORED")

    def as_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items()}


# --------------------------------------------------------------------------- epoch records
def _hex32(v: Any) -> bytes | None:
    try:
        b = bytes.fromhex(v)
    except (TypeError, ValueError):
        return None
    return b if len(b) == 32 else None


def _record_problem(rec: Any, tenant: str) -> str | None:
    if not isinstance(rec, dict):
        return "EPOCH_NOT_AN_OBJECT"
    for k in ("epoch_no", "tree_size", "first_seq", "last_seq"):
        if not isinstance(rec.get(k), int) or isinstance(rec.get(k), bool) or rec[k] < 0:
            return f"EPOCH_FIELD_{k.upper()}"
    for k in ("merkle_root", "prev_root", "epoch_root"):
        if _hex32(rec.get(k)) is None:
            return f"EPOCH_FIELD_{k.upper()}"
    if rec.get("tenant") != tenant:
        return "EPOCH_TENANT_MISMATCH"
    if rec["tree_size"] < 1 or rec["tree_size"] != rec["last_seq"] - rec["first_seq"] + 1:
        return "EPOCH_SIZE_INCONSISTENT"
    return None


def recompute_root(rec: dict[str, Any]) -> bytes:
    return epoch_root(
        rec["tenant"],
        rec["epoch_no"],
        rec["tree_size"],
        rec["first_seq"],
        rec["last_seq"],
        bytes.fromhex(rec["merkle_root"]),
        bytes.fromhex(rec["prev_root"]),
    )


def walk_epochs(res: Result, records: Sequence[dict[str, Any]], tenant: str) -> dict[int, bytes]:
    """V4 + continuity: contiguous numbering, tiling, prev links, recomputed roots."""
    roots: dict[int, bytes] = {}
    prev: dict[str, Any] | None = None
    for rec in records:
        problem = _record_problem(rec, tenant)
        if problem:
            res.fail(
                "TAMPERED", problem, epoch=rec.get("epoch_no") if isinstance(rec, dict) else None
            )
            return roots
        no = rec["epoch_no"]
        if prev is None:
            if no == 0 and (rec["first_seq"] != 0 or bytes.fromhex(rec["prev_root"]) != ZERO32):
                res.fail("TAMPERED", "GENESIS_EPOCH_INVALID", epoch=no)
                return roots
            if no != 0:
                res.notes.append(f"material starts at epoch {no}; epochs 0..{no - 1} not checked")
        else:
            if no != prev["epoch_no"] + 1:
                res.fail("TAMPERED", "EPOCH_NUMBER_GAP", epoch=prev["epoch_no"] + 1)
                return roots
            if rec["first_seq"] != prev["last_seq"] + 1:
                res.fail("TAMPERED", "EPOCH_SEQ_NOT_TILED", epoch=no)
                return roots
            if rec["prev_root"] != prev["epoch_root"]:
                res.fail("TAMPERED", "EPOCH_PREV_ROOT_MISMATCH", epoch=no)
                return roots
        if recompute_root(rec).hex() != rec["epoch_root"]:
            res.fail("TAMPERED", "EPOCH_ROOT_MISMATCH", epoch=no)
            return roots
        roots[no] = bytes.fromhex(rec["epoch_root"])
        res.epochs_checked += 1
        res.last_epoch_no, res.last_epoch_root = no, rec["epoch_root"]
        prev = rec
    return roots


def apply_trust(
    res: Result,
    roots: dict[int, bytes],
    trusted_root: bytes | None,
    trusted_epoch: int | None,
    *,
    min_epoch: int | None = None,
) -> Result:
    if not res.ok:
        return res
    if trusted_root is None:
        res.result = "UNANCHORED" if res.result == "VERIFIED" else res.result
        res.notes.append(LOCAL_ONLY)
        return res
    n = trusted_epoch if trusted_epoch is not None else res.last_epoch_no
    res.trusted_epoch = n
    if n is None:
        return res.fail("INCOMPLETE", "NO_EPOCHS_IN_MATERIAL")
    if min_epoch is not None and n < min_epoch:
        return res.fail("INCOMPLETE", "TRUSTED_EPOCH_PRECEDES_EVENT", epoch=n)
    if n in roots:
        if roots[n] != trusted_root:
            return res.fail("TAMPERED", "TRUSTED_ROOT_MISMATCH", epoch=n)
        if res.last_epoch_no is not None and n < res.last_epoch_no:
            res.notes.append(
                f"epochs {n + 1}..{res.last_epoch_no} are not covered by the trusted root"
            )
            if min_epoch is None:  # whole-export mode: part of the material is unanchored
                res.result = "UNANCHORED"
        return res
    if res.last_epoch_no is None or n > res.last_epoch_no:
        first_missing = 0 if res.last_epoch_no is None else res.last_epoch_no + 1
        return res.fail("TAMPERED", "TRUNCATED_BEFORE_TRUSTED_ROOT", epoch=first_missing)
    return res.fail("INCOMPLETE", "TRUSTED_EPOCH_NOT_IN_MATERIAL", epoch=n)


def verify_epochs(
    epoch_lines: Iterable[str],
    *,
    trusted_root: bytes | None = None,
    trusted_epoch: int | None = None,
    event_lines: Iterable[str] | None = None,
) -> Result:
    res = Result()
    it = iter(epoch_lines)
    try:
        meta = json.loads(next(it))
        assert isinstance(meta, dict) and meta.get("format") == EPOCHS_FORMAT  # noqa: S101
        tenant = str(meta["tenant"])
        records = [json.loads(line) for line in it if line.strip()]
    except (StopIteration, ValueError, KeyError, AssertionError, TypeError):
        return res.fail("TAMPERED", "BAD_EPOCHS_EXPORT")
    res.tenant = tenant
    roots = walk_epochs(res, records, tenant)
    if res.ok and event_lines is not None:
        _check_events_against_epochs(res, records, event_lines)
    return apply_trust(res, roots, trusted_root, trusted_epoch)


def _check_events_against_epochs(
    res: Result, records: Sequence[dict[str, Any]], event_lines: Iterable[str]
) -> None:
    """Full audit: chain-verify the event export, then recompute every epoch's M_t."""
    chain: Report = verify_lines(event_lines)
    if chain.result == "TAMPERED":
        res.fail("TAMPERED", f"EVENTS_{chain.reason}", seq=chain.first_bad_seq)
        return
    if chain.tenant != res.tenant:
        res.fail("TAMPERED", "EVENTS_TENANT_MISMATCH")
        return
    hashes = chain.hashes
    for rec in records:
        leaves = [hashes.get(s) for s in range(rec["first_seq"], rec["last_seq"] + 1)]
        if any(x is None for x in leaves):
            res.fail("INCOMPLETE", "EVENTS_MISSING_FOR_EPOCH", epoch=rec["epoch_no"])
            return
        if root_of([x for x in leaves if x is not None]).hex() != rec["merkle_root"]:
            res.fail("TAMPERED", "EPOCH_MERKLE_ROOT_MISMATCH", epoch=rec["epoch_no"])
            return
    if chain.result == "INCOMPLETE":
        res.fail("INCOMPLETE", "EVENTS_INCOMPLETE")
    last_sealed = records[-1]["last_seq"] if records else -1
    res.unsealed_events = sum(1 for s in hashes if s > last_sealed)
    if res.unsealed_events:
        res.notes.append(
            f"{res.unsealed_events} events after the last sealed epoch are not covered"
        )


# --------------------------------------------------------------------------- bundles
def verify_bundle(
    bundle: Any, *, trusted_root: bytes | None = None, trusted_epoch: int | None = None
) -> Result:
    res = Result()
    try:
        assert isinstance(bundle, dict) and bundle.get("format") == BUNDLE_FORMAT  # noqa: S101
        assert bundle.get("bundle_version") == 1  # noqa: S101
        tenant = str(bundle["tenant"])
        ev, proof, epoch = bundle["event"], bundle["proof"], bundle["epoch"]
        chain = list(bundle.get("epoch_chain", []))
        header = bytes.fromhex(ev["header"])
        path = [bytes.fromhex(p) for p in proof["audit_path"]]
        leaf_index, proof_size = int(proof["leaf_index"]), int(proof["tree_size"])
    except (AssertionError, KeyError, TypeError, ValueError):
        return res.fail("INCOMPLETE", "BAD_OR_INCOMPLETE_BUNDLE")
    res.tenant = tenant
    try:
        rec = loads(header)
    except NonCanonical as exc:
        return res.fail("TAMPERED", f"HEADER_NONCANONICAL:{exc.code}", seq=ev.get("seq"))
    if (
        not isinstance(rec, dict)
        or rec.get("tenant") != tenant
        or not isinstance(rec.get("seq"), int)
    ):
        return res.fail("TAMPERED", "HEADER_TENANT_OR_SEQ", seq=ev.get("seq"))
    seq = rec["seq"]
    problem = _record_problem(epoch, tenant)
    if problem:
        return res.fail(
            "TAMPERED", problem, epoch=epoch.get("epoch_no") if isinstance(epoch, dict) else None
        )
    # The tree size and index come from the epoch header, never from the proof alone (06 §6.3).
    if not epoch["first_seq"] <= seq <= epoch["last_seq"]:
        return res.fail(
            "INVALID_PROOF", "EVENT_NOT_IN_EPOCH_RANGE", epoch=epoch["epoch_no"], seq=seq
        )
    if leaf_index != seq - epoch["first_seq"] or proof_size != epoch["tree_size"]:
        return res.fail(
            "INVALID_PROOF", "PROOF_POSITION_MISMATCH", epoch=epoch["epoch_no"], seq=seq
        )
    if proof.get("epoch_no") != epoch["epoch_no"]:
        return res.fail("INVALID_PROOF", "PROOF_EPOCH_MISMATCH", epoch=epoch["epoch_no"], seq=seq)
    if not inclusion_ok(
        event_hash(header),
        leaf_index,
        epoch["tree_size"],
        path,
        bytes.fromhex(epoch["merkle_root"]),
    ):
        return res.fail("INVALID_PROOF", "INCLUSION_PROOF_FAILED", epoch=epoch["epoch_no"], seq=seq)
    if "payload" in ev:
        pref = rec.get("payload")
        try:
            raw = bytes.fromhex(ev["payload"])
            payload = loads(raw)
        except (ValueError, NonCanonical):
            return res.fail("TAMPERED", "PAYLOAD_NONCANONICAL", seq=seq)
        if not isinstance(pref, dict) or payload_digest(raw) != pref.get("digest"):
            return res.fail("TAMPERED", "PAYLOAD_DIGEST_MISMATCH", seq=seq)
        if not isinstance(payload, dict) or payload.get("event") != rec.get("id"):
            return res.fail("TAMPERED", "PAYLOAD_EVENT_MISMATCH", seq=seq)
    roots = walk_epochs(res, [epoch, *chain], tenant)
    if not res.ok:
        return res
    return apply_trust(res, roots, trusted_root, trusted_epoch, min_epoch=epoch["epoch_no"])


def sha256_file(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
