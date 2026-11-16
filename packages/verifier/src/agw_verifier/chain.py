"""Hash-chain verification of an ``agw-export/v1`` file (docs/gateway/06 §4-5, 10 §3 V1/V2/V8).

Checks, per event in file order:
  V1  header is strict AGW-CBOR-v1 (decode + re-encode identical)
  V2  record shape; tenant; seq matches its line and increases; prev link = recomputed
      hash of the previous event; genesis prev = ZERO32; stored event_hash = recomputed
  V8  payload (if exported): strict CBOR, digest = header.payload.digest, length, and
      payload.event = header.id
plus: duplicate event ids, and an optional TRUSTED HEAD (seq, hash) obtained out of band.

Results (worst wins): TAMPERED (first bad seq + reason) > INCOMPLETE (missing seq ranges or
payloads) > VERIFIED.

Known limit (asserted by tests, fixed by later phases): without a trusted head, deleting the
newest events (a suffix) is NOT detectable - the remaining prefix is a valid chain. Merkle
epochs + on-chain anchors provide that trusted head later.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from agw_verifier import STATEMENT
from agw_verifier.cbor import NonCanonical, loads

ZERO32 = bytes(32)
FORMAT = "agw-export/v1"


def _tag(t: str) -> bytes:
    raw = t.encode()
    return bytes([len(raw)]) + raw


EVENT_PREFIX = _tag("AGW/event/v1")
PAYLOAD_PREFIX = _tag("AGW/payload/v1")

HEADER_KEYS = frozenset(
    {
        "v",
        "tenant",
        "seq",
        "prev",
        "id",
        "type",
        "ts",
        "class",
        "actor",
        "action",
        "run",
        "tool",
        "env",
        "risk",
        "policy",
        "approval",
        "args",
        "dispatch",
        "outcome",
        "payload",
        "refs",
        "code",
        "violation",
        "obs",
        "epoch",
        "disclosure",  # Phase 7
        "erasure",  # Phase 7
        "delegation",  # Phase 8 (ADR-0030); "refs" (05 §4) is written from Phase 8 on
    }
)
# Phase 7: an export reports a payload it could not produce. Ciphertext that fails its AEAD
# tag / stored SHA-256 was altered at rest -> TAMPERED; deleted (retention) or missing ->
# INCOMPLETE (the header and proofs still verify).
TAMPER_PAYLOAD_STATUS = frozenset({"DECRYPT_FAILED", "BLOB_CORRUPT"})
REQUIRED_KEYS = ("v", "tenant", "seq", "prev", "id", "type", "ts", "class", "actor")
PAYLOAD_KEYS = frozenset(
    {
        "v",
        "salt",
        "event",
        "intent",
        "execution",
        "effects",
        "context",
        "delegation",
        "approval",
        "disclosure",
    }
)


def event_hash(header: bytes) -> bytes:
    return hashlib.sha256(EVENT_PREFIX + header).digest()


def payload_digest(payload: bytes) -> bytes:
    return hashlib.sha256(PAYLOAD_PREFIX + payload).digest()


@dataclass
class Report:
    result: str = "VERIFIED"
    tenant: str | None = None
    events_checked: int = 0
    first_bad_seq: int | None = None
    reason: str | None = None
    missing_ranges: list[tuple[int, int]] = field(default_factory=list)
    missing_payloads: list[int] = field(default_factory=list)
    last_seq: int | None = None
    last_hash: str | None = None
    statement: str = STATEMENT
    hashes: dict[int, bytes] = field(default_factory=dict)  # recomputed event hashes by seq

    def tamper(self, seq: int | None, reason: str) -> Report:
        self.result, self.first_bad_seq, self.reason = "TAMPERED", seq, reason
        return self

    def as_dict(self) -> dict[str, Any]:
        return {
            "result": self.result,
            "tenant": self.tenant,
            "events_checked": self.events_checked,
            "first_bad_seq": self.first_bad_seq,
            "reason": self.reason,
            "missing_ranges": [list(r) for r in self.missing_ranges],
            "missing_payloads": self.missing_payloads,
            "last_seq": self.last_seq,
            "last_hash": self.last_hash,
            "statement": self.statement,
        }


def _check_shape(rec: Any, tenant: str) -> str | None:
    if not isinstance(rec, dict):
        return "HEADER_NOT_A_MAP"
    if set(rec) - HEADER_KEYS:
        return "UNKNOWN_HEADER_KEY"
    if any(k not in rec for k in REQUIRED_KEYS):
        return "MISSING_HEADER_KEY"
    if rec["v"] != 1:
        return "UNSUPPORTED_VERSION"
    if rec["tenant"] != tenant:
        return "TENANT_MISMATCH"
    if not isinstance(rec["seq"], int) or isinstance(rec["seq"], bool) or rec["seq"] < 0:
        return "BAD_SEQ"
    if not (isinstance(rec["prev"], bytes) and len(rec["prev"]) == 32):
        return "BAD_PREV"
    if not (isinstance(rec["id"], bytes) and len(rec["id"]) == 16):
        return "BAD_ID"
    pref = rec.get("payload")
    if pref is not None and not (
        isinstance(pref, dict)
        and isinstance(pref.get("digest"), bytes)
        and len(pref["digest"]) == 32
        and isinstance(pref.get("len"), int)
    ):
        return "BAD_PAYLOAD_REF"
    return None


def _check_payload(rec: dict[str, Any], hex_payload: str) -> str | None:
    try:
        raw = bytes.fromhex(hex_payload)
    except ValueError:
        return "PAYLOAD_NOT_HEX"
    try:
        payload = loads(raw)
    except NonCanonical as exc:
        return f"PAYLOAD_NONCANONICAL:{exc.code}"
    if not isinstance(payload, dict) or set(payload) - PAYLOAD_KEYS:
        return "PAYLOAD_SHAPE"
    if payload_digest(raw) != rec["payload"]["digest"]:
        return "PAYLOAD_DIGEST_MISMATCH"
    if len(raw) != rec["payload"]["len"]:
        return "PAYLOAD_LENGTH_MISMATCH"
    if payload.get("event") != rec["id"]:
        return "PAYLOAD_EVENT_MISMATCH"
    if not (isinstance(payload.get("salt"), bytes) and len(payload["salt"]) == 32):
        return "PAYLOAD_SALT"
    return None


def verify_lines(
    lines: Iterable[str],
    *,
    trusted_head: bytes | None = None,
    trusted_seq: int | None = None,
) -> Report:
    report = Report()
    it = iter(lines)
    try:
        meta = json.loads(next(it))
    except (StopIteration, json.JSONDecodeError):
        return report.tamper(None, "BAD_EXPORT_METADATA")
    if (
        not isinstance(meta, dict)
        or meta.get("format") != FORMAT
        or not isinstance(meta.get("tenant"), str)
    ):
        return report.tamper(None, "BAD_EXPORT_METADATA")
    tenant = meta["tenant"]
    report.tenant = tenant
    expect_payloads = bool(meta.get("payloads"))

    expected_seq = 0
    prev_hash: bytes | None = None  # None: predecessor not available (start or after a gap)
    seen_ids: set[bytes] = set()
    hashes: dict[int, bytes] = {}

    for raw_line in it:
        if not raw_line.strip():
            continue
        try:
            line = json.loads(raw_line)
            header = bytes.fromhex(line["header"])
            line_seq = int(line["seq"])
        except (ValueError, KeyError, TypeError):
            return report.tamper(None, "BAD_EXPORT_LINE")
        try:
            rec = loads(header)
        except NonCanonical as exc:
            return report.tamper(line_seq, f"HEADER_NONCANONICAL:{exc.code}")
        problem = _check_shape(rec, tenant)
        if problem:
            return report.tamper(line_seq, problem)
        seq = rec["seq"]
        if seq != line_seq:
            return report.tamper(line_seq, "SEQ_LABEL_MISMATCH")
        if seq < expected_seq:
            return report.tamper(seq, "SEQ_ORDER")
        if seq > expected_seq:
            report.missing_ranges.append((expected_seq, seq - 1))
            prev_hash = None  # cannot check the link across a gap
        if seq == 0 and rec["prev"] != ZERO32:
            return report.tamper(seq, "GENESIS_PREV_NOT_ZERO")
        if prev_hash is not None and rec["prev"] != prev_hash:
            return report.tamper(seq, "PREV_HASH_MISMATCH")
        if rec["id"] in seen_ids:
            return report.tamper(seq, "DUPLICATE_EVENT_ID")
        seen_ids.add(rec["id"])
        h = event_hash(header)
        stored = line.get("event_hash")
        if stored is not None and stored != h.hex():
            return report.tamper(seq, "STORED_EVENT_HASH_MISMATCH")
        if "payload" in rec:
            if "payload" in line:
                p_problem = _check_payload(rec, line["payload"])
                if p_problem:
                    return report.tamper(seq, p_problem)
            elif line.get("payload_status") in TAMPER_PAYLOAD_STATUS:
                return report.tamper(seq, f"PAYLOAD_{line['payload_status']}")
            elif expect_payloads:
                report.missing_payloads.append(seq)
        elif "payload" in line:
            return report.tamper(seq, "UNEXPECTED_PAYLOAD")
        hashes[seq] = h
        report.hashes[seq] = h
        prev_hash, expected_seq = h, seq + 1
        report.events_checked += 1
        report.last_seq, report.last_hash = seq, h.hex()

    if trusted_seq is not None and trusted_head is not None:
        if trusted_seq in hashes:
            if hashes[trusted_seq] != trusted_head:
                return report.tamper(trusted_seq, "TRUSTED_HEAD_MISMATCH")
        elif report.last_seq is None or report.last_seq < trusted_seq:
            first_missing = 0 if report.last_seq is None else report.last_seq + 1
            return report.tamper(first_missing, "TRUNCATED_BEFORE_TRUSTED_HEAD")
        else:
            report.missing_ranges.append((trusted_seq, trusted_seq))

    if report.missing_ranges or report.missing_payloads:
        report.result = "INCOMPLETE"
    return report
